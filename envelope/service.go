package envelope

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

// Config 构造 Service 的配置。
type Config struct {
	// Dir 本地存储目录。
	Dir string
	// RootSecret 主根密钥材料（>=16 字节）。仅存在于内存，用于派生各版本 KEK，
	// 绝不写入磁盘或日志。
	RootSecret []byte
	// Logger 可选日志器；为空时使用 slog.Default()。日志只记录版本号/租户/判定
	// 依据，绝不记录明文、DEK、KEK 或根密钥。
	Logger *slog.Logger
}

// Service 是信封加密组件的对外入口。
//
// 一把读写锁保护跨文件的一致性：
//   - Encrypt（写数据文件，并依赖当前密钥版本）走写锁；
//   - Decrypt 只读，走读锁，内部密码学运算使用 keyring 的原子快照，
//     因此可与 Rotate 并发且始终拿到一致版本；
//   - RotateKey 走写锁，与任何写入串行，保证“用哪个版本加密”和
//     “该版本元数据已落盘”这两件事对外部观察者原子可见。
type Service struct {
	mu     sync.RWMutex
	store  Store
	kr     *keyring
	eng    *cryptoEngine
	logger *slog.Logger
}

// New 创建并初始化 Service：加载（或首次创建）密钥环元数据。
// 首次启动会生成第 1 个主密钥版本；之后启动从 keys.json 恢复全部历史版本，
// 历史密文因此始终可解。
func New(ctx context.Context, cfg Config) (*Service, error) {
	if len(cfg.RootSecret) < minRootSecretLen {
		return nil, &InvalidArgumentError{
			Argument: "RootSecret",
			Reason:   fmt.Sprintf("must be at least %d bytes", minRootSecretLen),
		}
	}
	store, err := NewFileStore(cfg.Dir)
	if err != nil {
		return nil, err
	}
	eng, err := newCryptoEngine(cfg.RootSecret)
	if err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	svc := &Service{store: store, eng: eng, logger: logger}
	svc.kr = newKeyring(eng)

	kf, err := store.LoadKeyring()
	switch {
	case err == nil:
		if err := svc.kr.Restore(kf); err != nil {
			return nil, err
		}
		svc.logger.LogAttrs(ctx, slog.LevelInfo,
			"envelope: restored keyring from disk",
			slog.Int("current_version", kf.CurrentVersion),
			slog.Int("version_count", len(kf.Versions)),
			slog.Int("tenant_count", len(kf.Tenants)),
		)
	case errors.Is(err, io.EOF):
		// 首次启动：生成初始主密钥版本并立即持久化（仅盐，非秘密）。
		kv, berr := svc.kr.Bootstrap()
		if berr != nil {
			return nil, berr
		}
		if perr := store.SaveKeyring(svc.kr.snapshotMeta()); perr != nil {
			return nil, perr
		}
		svc.logger.LogAttrs(ctx, slog.LevelInfo,
			"envelope: bootstrapped new keyring",
			slog.Int("key_version", kv.version),
			slog.String("basis", "no keys.json found, generated version 1 and persisted salt only"),
		)
	default:
		return nil, err
	}
	return svc, nil
}

// RegisterTenant 注册一个租户，使其可以加解密数据。幂等。
func (s *Service) RegisterTenant(ctx context.Context, tenant string) error {
	if err := validateName(tenant); err != nil {
		return &InvalidArgumentError{Argument: "tenant", Reason: err.Error()}
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	prev := s.kr.load() // 快照不可变，落盘失败时可直接回滚
	added, err := s.kr.RegisterTenant(tenant)
	if err != nil {
		return err
	}
	if !added {
		return nil
	}
	if err := s.store.SaveKeyring(s.kr.snapshotMeta()); err != nil {
		s.kr.snap.Store(prev) // 内存不领先于磁盘，保持内存/磁盘一致
		return err
	}
	s.logger.LogAttrs(ctx, slog.LevelInfo,
		"envelope: tenant registered",
		slog.String("tenant", tenant),
		slog.String("basis", "tenant added to registry and keys.json persisted"),
	)
	return nil
}

// requireTenant 校验租户身份：空租户/非法名 -> InvalidArgument；
// 未注册 -> ErrTenantUnknown。返回哨兵错误的具体包装。
func (s *Service) requireTenant(tenant string) error {
	if err := validateName(tenant); err != nil {
		return &InvalidArgumentError{Argument: "tenant", Reason: err.Error()}
	}
	if !s.kr.TenantRegistered(tenant) {
		return &TenantUnknownError{Tenant: tenant}
	}
	return nil
}

// Encrypt 以 tenant 身份把 plaintext 信封加密后，以 id 原子写入本地存储。
// 始终使用当前主密钥版本。写入采用临时文件 + fsync + rename，
// 任何中途失败都不会留下半成品密文，也不会影响后续解密。
func (s *Service) Encrypt(ctx context.Context, tenant, id string, plaintext []byte) (*EnvelopeCiphertext, error) {
	if err := validateName(id); err != nil {
		return nil, &InvalidArgumentError{Argument: "id", Reason: err.Error()}
	}

	// 身份判定在读锁阶段即可完成，但为了让“判定 -> 用当前版本加密 -> 落盘”
	// 与轮换严格串行，写操作整体持写锁。
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.requireTenant(tenant); err != nil {
		s.denied(ctx, "encrypt", tenant, "", 0, err)
		return nil, err
	}
	if exists, err := s.store.RecordExists(tenant, id); err != nil {
		return nil, err
	} else if exists {
		return nil, &RecordExistsError{Tenant: tenant, ID: id}
	}

	kv, kek, err := s.kr.CurrentKEK()
	if err != nil {
		return nil, err
	}
	ct, err := s.eng.seal(kv, kek, plaintext)
	if err != nil {
		return nil, err
	}

	rec := &recordFile{
		Header: recordHeader{
			ID:          id,
			Tenant:      tenant,
			KeyVersion:  ct.Version,
			WrappedKey:  ct.WrappedDEK,
			WrapNonce:   ct.Nonce,
			DataNonce:   ct.DataNonce,
			CreatedUnix: time.Now().Unix(),
		},
		Ciphertext: ct.Ciphertext,
	}
	// CreateRecord 内部原子落盘；失败点之后磁盘上不存在任何该 ID 的文件，
	// 因此后面的 Decrypt 不会读到半成品。
	if err := s.store.CreateRecord(tenant, id, rec); err != nil {
		return nil, err
	}

	s.logger.LogAttrs(ctx, slog.LevelInfo,
		"envelope: encrypted record",
		slog.String("tenant", tenant),
		slog.String("id", id),
		slog.Int("key_version", ct.Version),
		slog.String("basis",
			fmt.Sprintf("sealed with current key version %d; KEK derived in-memory from root secret + version salt", ct.Version)),
	)
	return ct, nil
}

// Decrypt 以 tenant 身份读取 id 的密文并解密。
// 可区分错误：ErrTenantUnknown（未注册）、ErrTenantDenied（跨租户）、
// ErrRecordNotFound（无此数据）、ErrKeyVersionNotFound（引用缺失版本）、
// ErrCiphertextCorrupt（损坏/篡改）。
func (s *Service) Decrypt(ctx context.Context, tenant, id string) ([]byte, *EnvelopeCiphertext, error) {
	if err := validateName(id); err != nil {
		return nil, nil, &InvalidArgumentError{Argument: "id", Reason: err.Error()}
	}

	// 读锁：与轮换/其它写入可以并发；keyring 快照本身是原子不可变的。
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.requireTenant(tenant); err != nil {
		s.denied(ctx, "decrypt", tenant, id, 0, err)
		return nil, nil, err
	}

	rec, err := s.store.LoadRecord(tenant, id)
	if err != nil {
		return nil, nil, err
	}
	// 二次归属判定：即使存储层按路径隔离，也以文件内声明的 owner 为准，
	// owner 不匹配 => 明确的跨租户拒绝原因。
	if rec.Header.Tenant != tenant {
		err := &TenantDeniedError{CallerTenant: tenant, OwnerTenant: rec.Header.Tenant}
		s.denied(ctx, "decrypt", tenant, id, rec.Header.KeyVersion, err)
		return nil, nil, err
	}

	ct := &EnvelopeCiphertext{
		Version:    rec.Header.KeyVersion,
		WrappedDEK: rec.Header.WrappedKey,
		Nonce:      rec.Header.WrapNonce,
		Ciphertext: rec.Ciphertext,
		DataNonce:  rec.Header.DataNonce,
	}
	if err := ct.validate(); err != nil {
		if ce, ok := err.(*CorruptCiphertextError); ok {
			ce.Tenant, ce.ID = tenant, id
		}
		return nil, nil, err
	}

	// 按密文记录的历史版本取 KEK；版本缺失必须显式报错，不能降级。
	_, kek, err := s.kr.KEKForVersion(ct.Version)
	if err != nil {
		var kve *KeyVersionError
		if errors.As(err, &kve) {
			s.logger.LogAttrs(ctx, slog.LevelWarn,
				"envelope: decrypt rejected",
				slog.String("tenant", tenant),
				slog.String("id", id),
				slog.Int("referenced_key_version", ct.Version),
				slog.String("basis", "record references a key version absent from keyring; no fallback"),
			)
		}
		return nil, nil, err
	}

	pt, err := s.eng.open(kek, ct)
	if err != nil {
		if ce, ok := err.(*CorruptCiphertextError); ok {
			ce.Tenant, ce.ID = tenant, id
		}
		s.logger.LogAttrs(ctx, slog.LevelWarn,
			"envelope: decrypt failed",
			slog.String("tenant", tenant),
			slog.String("id", id),
			slog.Int("key_version", ct.Version),
			slog.String("basis", "AEAD authentication failed; ciphertext corrupt or tampered"),
		)
		return nil, nil, err
	}

	s.logger.LogAttrs(ctx, slog.LevelInfo,
		"envelope: decrypted record",
		slog.String("tenant", tenant),
		slog.String("id", id),
		slog.Int("key_version", ct.Version),
		slog.Int("current_version", s.kr.CurrentVersion()),
		slog.String("basis",
			fmt.Sprintf("historical KEK for version %d derived from retained version salt; rotation does not remove old versions", ct.Version)),
	)
	return pt, ct, nil
}

// RotateKey 轮换主密钥：生成新版本并设为当前版本，旧版本全部保留，
// 因而历史密文仍可按其记录的版本解密。
func (s *Service) RotateKey(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	prev := s.kr.load() // 快照不可变，落盘失败时可直接回滚
	kv, err := s.kr.Rotate()
	if err != nil {
		return 0, err
	}
	if err := s.store.SaveKeyring(s.kr.snapshotMeta()); err != nil {
		s.kr.snap.Store(prev) // 回滚为上一个快照，避免“新版本加密了数据但重启后版本消失”
		return 0, err
	}
	s.logger.LogAttrs(ctx, slog.LevelInfo,
		"envelope: key rotated",
		slog.Int("new_key_version", kv.version),
		slog.Int("retained_versions", s.kr.VersionCount()),
		slog.String("basis", "new current version persisted with salt only; all previous versions retained for decryption"),
	)
	return kv.version, nil
}

// CurrentKeyVersion 返回当前主密钥版本号。
func (s *Service) CurrentKeyVersion() int { return s.kr.CurrentVersion() }

// VersionCount 返回密钥环保留的版本数量（测试/诊断用）。
func (s *Service) VersionCount() int { return s.kr.VersionCount() }

func (s *Service) denied(ctx context.Context, op, tenant, id string, version int, err error) {
	attrs := []slog.Attr{
		slog.String("op", op),
		slog.String("tenant", tenant),
		slog.String("reason", err.Error()),
		slog.String("basis", "tenant registry / ownership check failed"),
	}
	if id != "" {
		attrs = append(attrs, slog.String("id", id))
	}
	if version > 0 {
		attrs = append(attrs, slog.Int("key_version", version))
	}
	s.logger.LogAttrs(ctx, slog.LevelWarn, "envelope: access denied", attrs...)
}
