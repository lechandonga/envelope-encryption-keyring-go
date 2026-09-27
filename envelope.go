package envelope

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
)

// recordFormatVersion 是密文记录封装格式的版本号（与主密钥版本相互独立）。
const recordFormatVersion = 1

// CiphertextRecord 是一条密文在磁盘上的完整 JSON 形态。
// 其中不含任何明文密钥材料：数据密钥 DEK 以 wrappedDEK 形式存在，
// 且由记录指定版本的主密钥包装。
type CiphertextRecord struct {
	FormatVersion uint32 `json:"format_version"`
	TenantID      string `json:"tenant_id"`   // 属主租户，用于访问控制判定
	RecordID      string `json:"record_id"`   // 记录 ID，参与 AAD 绑定
	KeyVersion    uint32 `json:"key_version"` // 包装 DEK 所用主密钥版本
	WrappedDEK    []byte `json:"wrapped_dek"` // 主密钥包装后的数据密钥
	Ciphertext    []byte `json:"ciphertext"`  // DEK/AES-GCM 加密后的载荷（含 nonce）
	CreatedAt     string `json:"created_at"`  // 首次创建时间
	UpdatedAt     string `json:"updated_at"`  // 最近一次写入时间
}

// WritePolicy 决定 Encrypt 在目标记录已存在时的行为。
type WritePolicy int

const (
	// WritePolicyMustCreate 仅允许新建；记录已存在返回 ErrRecordAlreadyExists。
	WritePolicyMustCreate WritePolicy = iota
	// WritePolicyOverwrite 允许同属主租户覆盖已有记录。
	WritePolicyOverwrite
)

// Service 组合密钥环与本地存储，对外提供按租户隔离的信封加解密能力。
//
// 并发模型：
//   - 密钥环内部 RWMutex：加解密持读锁、轮换持写锁。轮换期间不会有任何
//     加解密看到“半个新版本”，读侧要么全部用旧版本、要么全部用新版本；
//   - 存储内部 per-record 锁 + 原子 rename：同一记录并发写串行落盘，
//     每次落盘都是完整记录，失败不留半成品。
type Service struct {
	keyring *Keyring
	storage *Storage
	log     *slog.Logger
}

// NewService 创建信封加解密服务。
func NewService(kr *Keyring, st *Storage, log *slog.Logger) (*Service, error) {
	if kr == nil {
		return nil, fmt.Errorf("%w: keyring is nil", ErrInvalidArgument)
	}
	if st == nil {
		return nil, fmt.Errorf("%w: storage is nil", ErrInvalidArgument)
	}
	if log == nil {
		log = slog.Default()
	}
	return &Service{keyring: kr, storage: st, log: log}, nil
}

// encryptMaxAttempts 限制并发冲突时的重读重试次数，避免极端竞争下活锁。
const encryptMaxAttempts = 8

// Encrypt 以 tenantID 身份加密 plaintext 并写入 recordID。
//
//   - 新建策略下，若记录已存在：先读取属主租户——属主不是自己则返回
//     ErrTenantMismatch（写别人数据被拒绝）；属主是自己则返回 ErrRecordAlreadyExists；
//   - 覆盖策略下，仅属主租户本人可覆盖，否则返回 ErrTenantMismatch；
//   - 加密使用密钥环“当前版本”主密钥包装随机 DEK，记录与版本号一起落盘；
//   - 落盘是原子操作，中途失败不会产生半成品密文，原有记录保持可解密；
//   - “检查—加密—写入”与其它写者并发时，以存储层的原子创建结果为准，
//     发现冲突会重新读取记录、重新做属主判定并重试，绝不会把属主的合法
//     覆盖误判成“已存在”，也不会借重试窗口写入别的租户的数据。
func (s *Service) Encrypt(tenantID, recordID string, plaintext []byte, policy WritePolicy) (*CiphertextRecord, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenantID is empty", ErrInvalidArgument)
	}
	if err := validateRecordID(recordID); err != nil {
		return nil, err
	}
	if plaintext == nil {
		return nil, fmt.Errorf("%w: plaintext is nil", ErrInvalidArgument)
	}

	// attempt 执行一次“读取现状 → 属主判定 → 信封加密 → 原子落盘”。
	// conflict=true 表示落盘时输给并发创建者，需要调用方重读后重试。
	attempt := func() (recOut *CiphertextRecord, conflict bool, errOut error) {
		// 1) 读取现状并做访问控制：记录若已存在，只有属主租户本人可以写。
		existing, err := s.loadRecord(recordID)
		if err != nil && !errors.Is(err, ErrRecordNotFound) {
			return nil, false, err
		}
		if existing != nil {
			if existing.TenantID != tenantID {
				s.log.Warn("encrypt denied",
					"tenant_id", tenantID,
					"owner_tenant_id", existing.TenantID,
					"record_id", recordID,
					"operation", "encrypt",
					"basis", "stored tenant_id does not match caller tenant_id")
				return nil, false, &TenantAccessError{
					TenantID: tenantID, OwnerTenantID: existing.TenantID,
					RecordID: recordID, Operation: "encrypt",
				}
			}
			if policy == WritePolicyMustCreate {
				return nil, false, fmt.Errorf("%w: record %q", ErrRecordAlreadyExists, recordID)
			}
		}

		// 2) 信封加密：随机 DEK；版本号与 DEK 包装 AAD 在 Keyring 同一把读锁内
		//    确定，与并发轮换线性一致：要么整段使用旧版本、要么整段使用新版本。
		dek, err := randomKey()
		if err != nil {
			return nil, false, err
		}
		defer wipeBytes(dek)

		wrappedDEK, version, err := s.keyring.WrapCurrentWithAAD(dek, func(v uint32) []byte {
			return dekWrapAAD(tenantID, recordID, v)
		})
		if err != nil {
			return nil, false, err
		}
		// version 是本次封包的线性化版本，数据 GCM 的 AAD 使用同一个版本号。
		ciphertext, err := gcmSeal(dek, plaintext, dataAAD(tenantID, recordID, version))
		if err != nil {
			return nil, false, err
		}

		now := nowRFC3339()
		rec := &CiphertextRecord{
			FormatVersion: recordFormatVersion,
			TenantID:      tenantID,
			RecordID:      recordID,
			KeyVersion:    version,
			WrappedDEK:    wrappedDEK,
			Ciphertext:    ciphertext,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		if existing != nil {
			rec.CreatedAt = existing.CreatedAt // 覆盖保留原始创建时间
		}

		// 3) 原子落盘：此前不存在则用原子 Create，已存在且属主校验通过则原子替换。
		data, err := json.MarshalIndent(rec, "", "  ")
		if err != nil {
			return nil, false, err
		}
		if existing == nil {
			err = s.storage.SaveIfAbsent(recordID, data)
			if errors.Is(err, ErrRecordAlreadyExists) {
				return nil, true, nil // 并发创建者抢先：重读并重新做属主判定
			}
			if err != nil {
				return nil, false, err
			}
		} else {
			if err := s.storage.Save(recordID, data); err != nil {
				return nil, false, err
			}
		}
		return rec, false, nil
	}

	var conflict bool
	for i := 0; i < encryptMaxAttempts; i++ {
		rec, c, err := attempt()
		if err != nil {
			return nil, err
		}
		if !c {
			s.log.Info("encrypted record",
				"tenant_id", tenantID,
				"record_id", recordID,
				"key_version", rec.KeyVersion,
				"basis", "sealed with current master key version")
			return rec, nil
		}
		conflict = c
	}
	if conflict {
		// 极端竞争下持续输给并发创建者：直接返回可区分的已存在错误。
		return nil, fmt.Errorf("%w: record %q (concurrent create contention exhausted retries)",
			ErrRecordAlreadyExists, recordID)
	}
	return nil, fmt.Errorf("%w: record %q", ErrInvalidArgument, recordID)
}

// Decrypt 以 tenantID 身份解密 recordID。
//
//	记录不存在 -> ErrRecordNotFound；
//	属主不匹配 -> ErrTenantMismatch（*TenantAccessError，含双方租户）；
//	引用主密钥版本缺失 -> ErrKeyVersionNotFound（*KeyVersionError，含版本号），
//	  不静默降级到其它版本；
//	密文损坏/被篡改/认证失败 -> ErrInvalidCiphertext。
func (s *Service) Decrypt(tenantID, recordID string) ([]byte, *CiphertextRecord, error) {
	if tenantID == "" {
		return nil, nil, fmt.Errorf("%w: tenantID is empty", ErrInvalidArgument)
	}
	if err := validateRecordID(recordID); err != nil {
		return nil, nil, err
	}

	rec, err := s.loadRecord(recordID)
	if err != nil {
		return nil, nil, err
	}

	// 访问控制优先：跨租户读取直接拒绝，并给出可区分原因。
	if rec.TenantID != tenantID {
		s.log.Warn("decrypt denied",
			"tenant_id", tenantID,
			"owner_tenant_id", rec.TenantID,
			"record_id", recordID,
			"key_version", rec.KeyVersion,
			"operation", "decrypt",
			"basis", "stored tenant_id does not match caller tenant_id")
		return nil, nil, &TenantAccessError{
			TenantID: tenantID, OwnerTenantID: rec.TenantID,
			RecordID: recordID, Operation: "decrypt",
		}
	}

	if rec.FormatVersion != recordFormatVersion {
		return nil, nil, fmt.Errorf("%w: unsupported format version %d", ErrInvalidCiphertext, rec.FormatVersion)
	}
	// 记录内字段自洽性：record_id 也必须匹配，防止文件被改名/挪用时误用。
	if rec.RecordID != recordID {
		return nil, nil, fmt.Errorf("%w: embedded record_id %q != requested %q",
			ErrInvalidCiphertext, rec.RecordID, recordID)
	}

	// 用记录声明的版本解包 DEK；版本不存在时错误必须可区分。
	dek, err := s.keyring.UnwrapVersion(rec.KeyVersion, rec.WrappedDEK,
		dekWrapAAD(tenantID, recordID, rec.KeyVersion))
	if err != nil {
		if errors.Is(err, ErrKeyVersionNotFound) {
			s.log.Error("decrypt failed: missing key version",
				"tenant_id", tenantID,
				"record_id", recordID,
				"key_version", rec.KeyVersion,
				"basis", "record references a master key version absent from keyring; no fallback")
			return nil, nil, &KeyVersionError{
				Version: rec.KeyVersion, TenantID: tenantID, RecordID: recordID,
			}
		}
		// DEK 解包认证失败：密文被篡改或 AAD 不一致。
		return nil, nil, fmt.Errorf("%w: unwrap data encryption key: %v", ErrInvalidCiphertext, err)
	}
	defer wipeBytes(dek)

	plaintext, err := gcmOpen(dek, rec.Ciphertext, dataAAD(tenantID, recordID, rec.KeyVersion))
	if err != nil {
		s.log.Error("decrypt failed: authentication error",
			"tenant_id", tenantID,
			"record_id", recordID,
			"key_version", rec.KeyVersion,
			"basis", "AES-GCM authentication failed: tampered ciphertext or AAD mismatch")
		return nil, nil, fmt.Errorf("%w: open ciphertext: %v", ErrInvalidCiphertext, err)
	}

	s.log.Info("decrypted record",
		"tenant_id", tenantID,
		"record_id", recordID,
		"key_version", rec.KeyVersion,
		"basis", "unwrapped DEK with referenced (possibly old) master key version")
	return plaintext, rec, nil
}

// RotateKey 轮换主密钥：生成新版本并原子推进“当前版本”。
// 不触碰任何历史密文——它们继续引用各自写入时的旧版本，解密照常。
func (s *Service) RotateKey() (uint32, error) {
	v, err := s.keyring.Rotate()
	if err != nil {
		return 0, err
	}
	s.log.Info("key rotation complete; existing ciphertexts keep their original key_version",
		"key_version", v,
		"basis", "rotation adds a version and advances pointer; old versions retained")
	return v, nil
}

// CurrentKeyVersion 暴露当前主密钥版本（观测/测试用）。
func (s *Service) CurrentKeyVersion() uint32 { return s.keyring.CurrentVersion() }

func (s *Service) loadRecord(recordID string) (*CiphertextRecord, error) {
	raw, err := s.storage.Load(recordID)
	if err != nil {
		return nil, err
	}
	var rec CiphertextRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		// 原子写保证正常流程不会读到半截文件；出现解析失败说明文件被外部破坏。
		return nil, fmt.Errorf("%w: parse record %q: %v", ErrInvalidCiphertext, recordID, err)
	}
	return &rec, nil
}

// dataAAD 是加密业务数据时的认证附加数据，把租户、记录与主密钥版本绑定进 GCM 标签：
// 密文一旦被挪到别的租户/记录/版本语境，认证即失败。
func dataAAD(tenantID, recordID string, keyVersion uint32) []byte {
	return []byte(fmt.Sprintf(
		"envelope:data:v1:tenant=%s:record=%s:key_version=%d",
		tenantID, recordID, keyVersion))
}

// dekWrapAAD 是主密钥包装 DEK 时的认证附加数据，绑定语义与 dataAAD 相同。
func dekWrapAAD(tenantID, recordID string, keyVersion uint32) []byte {
	return []byte(fmt.Sprintf(
		"envelope:dek:v1:tenant=%s:record=%s:key_version=%d",
		tenantID, recordID, keyVersion))
}

// wipeBytes 尽力清除内存中的明文密钥（不提供绝对保证，但避免引用残留）。
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
