package envelope

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Keyring 管理本地信封加密的主密钥多版本：
//   - 每个版本是一把随机生成的 AES-256 主密钥，只用 KEK 包装后落盘；
//   - CurrentVersion 指向“新写入数据”使用的版本；
//   - Rotate 生成新版本并推进 CurrentVersion，旧版本全部保留以解密历史数据；
//   - 所有版本状态在 RWMutex 保护下访问，轮换时持写锁整体替换并原子落盘，
//     与并发的加解密操作线性一致，不会出现“内存已推进、落盘还是旧版”的中间态。
type Keyring struct {
	mu sync.RWMutex

	versions       map[uint32]*versionEntry // version -> 条目（含明文主密钥，仅存内存）
	currentVersion uint32                   // 新写入使用的版本
	nextVersion    uint32                   // 下一次轮换分配的版本号
	kdf            kdfParams                // KEK 派生参数（盐等，非敏感）

	filePath   string       // 密钥环文件路径
	passphrase string       // 口令仅内存留存，用于重新包装/落盘；不落盘、不记日志
	log        *slog.Logger // 日志只允许出现版本号等元数据
}

// versionEntry 是内存中的主密钥版本条目。plain 只存在于内存，
// 落盘时必须替换为 wrapped（KEK 包装后的密文）。
type versionEntry struct {
	version uint32
	created string // RFC3339 创建时间
	plain   []byte // 32B 明文主密钥，仅内存
	wrapped []byte // KEK/AES-GCM 包装后的主密钥，落盘形态
}

// persistedKeyring 是密钥环文件的 JSON 结构。
// 明文主密钥绝不出现在该结构中：只有 KDF 参数（盐不保密）与密态主密钥。
type persistedKeyring struct {
	KDF            kdfParams          `json:"kdf"`
	CurrentVersion uint32             `json:"current_version"`
	NextVersion    uint32             `json:"next_version"`
	Versions       []persistedVersion `json:"versions"`
}

type persistedVersion struct {
	Version uint32 `json:"version"`
	Created string `json:"created"`
	Wrapped []byte `json:"wrapped_master_key"`
}

// CreateKeyring 在 dir 下创建并初始化密钥环文件（同时生成 v1 主密钥）。
// 文件已存在时返回错误，避免覆盖既有密钥材料。
func CreateKeyring(dir, passphrase string, log *slog.Logger) (*Keyring, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("%w: passphrase must not be empty", ErrInvalidArgument)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create keyring directory: %w", err)
	}
	filePath := filepath.Join(dir, "keyring.json")
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create keyring file: %w", err)
	}
	_ = f.Close()

	if log == nil {
		log = slog.Default()
	}
	kd, err := newKDFParams()
	if err != nil {
		return nil, err
	}
	kr := &Keyring{
		versions:    make(map[uint32]*versionEntry),
		nextVersion: 1,
		kdf:         kd,
		filePath:    filePath,
		passphrase:  passphrase,
		log:         log,
	}
	v, err := kr.addVersionLocked()
	if err != nil {
		return nil, err
	}
	kr.currentVersion = v
	if err := kr.persistLocked(); err != nil {
		return nil, err
	}
	kr.log.Info("keyring initialized", "key_version", v, "basis", "initial master key version")
	return kr, nil
}

// OpenKeyring 打开既有密钥环文件并用口令解包全部主密钥版本。
// 口令错误时返回可识别的 ErrInvalidPassphrase。
func OpenKeyring(dir, passphrase string, log *slog.Logger) (*Keyring, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("%w: passphrase must not be empty", ErrInvalidArgument)
	}
	filePath := filepath.Join(dir, "keyring.json")
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read keyring file: %w", err)
	}
	var pk persistedKeyring
	if err := json.Unmarshal(raw, &pk); err != nil {
		return nil, fmt.Errorf("parse keyring file: %w", err)
	}
	if len(pk.Versions) == 0 {
		return nil, ErrKeyringNotInitialized
	}

	kek := deriveKEK(passphrase, pk.KDF)
	kr := &Keyring{
		versions:       make(map[uint32]*versionEntry, len(pk.Versions)),
		currentVersion: pk.CurrentVersion,
		nextVersion:    pk.NextVersion,
		kdf:            pk.KDF,
		filePath:       filePath,
		passphrase:     passphrase,
		log:            log,
	}
	if log == nil {
		kr.log = slog.Default()
	}
	for _, pv := range pk.Versions {
		// AAD 绑定版本号，防止密态主密钥被跨版本挪动。
		aad := masterKeyAAD(pv.Version)
		plain, err := gcmOpen(kek, pv.Wrapped, aad)
		if err != nil {
			return nil, fmt.Errorf("%w: cannot unwrap master key version %d", ErrInvalidPassphrase, pv.Version)
		}
		if len(plain) != keySize {
			return nil, fmt.Errorf("%w: unwrapped master key has wrong length (version %d)", ErrInvalidPassphrase, pv.Version)
		}
		kr.versions[pv.Version] = &versionEntry{
			version: pv.Version,
			created: pv.Created,
			plain:   plain,
			wrapped: pv.Wrapped,
		}
	}
	if _, ok := kr.versions[kr.currentVersion]; !ok {
		return nil, fmt.Errorf("%w: current version %d missing in keyring", ErrKeyVersionNotFound, kr.currentVersion)
	}
	kr.log.Info("keyring opened",
		"key_version", kr.currentVersion,
		"total_versions", len(kr.versions),
		"basis", "unwrapped all retained versions with passphrase-derived KEK")
	return kr, nil
}

// CurrentVersion 返回当前用于新加密的主密钥版本号。
func (k *Keyring) CurrentVersion() uint32 {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.currentVersion
}

// Versions 返回密钥环当前保留的全部版本号（升序），仅用于观测/测试。
func (k *Keyring) Versions() []uint32 {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([]uint32, 0, len(k.versions))
	for v := range k.versions {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Rotate 生成一把全新随机主密钥作为新版本，原子推进 CurrentVersion 并落盘。
// 返回新版本号。旧版本全部保留：轮换后用旧版本加密的历史密文仍可解密。
// 整个“生成版本 → 推进指针 → 落盘”在同一把写锁内完成。
func (k *Keyring) Rotate() (uint32, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	newVersion, err := k.addVersionLocked()
	if err != nil {
		return 0, err
	}
	k.currentVersion = newVersion
	if err := k.persistLocked(); err != nil {
		// 落盘失败：内存状态整体回滚，不留下“指针已推进但无持久化”的半成品。
		delete(k.versions, newVersion)
		// 恢复指针：addVersionLocked 不会改动 currentVersion，因此无需额外恢复。
		return 0, fmt.Errorf("rotate to version %d: %w", newVersion, err)
	}
	k.log.Info("master key rotated",
		"key_version", newVersion,
		"basis", "new writes sealed with new version; previous versions retained for decrypt")
	return newVersion, nil
}

// WrapCurrentWithAAD 在同一把读锁内完成“读取当前版本号 + 用该版本封包 DEK”，
// aadFunc 以实际版本号构造 AAD，从而保证记录内 key_version 与 GCM 标签的
// AAD 绝对一致，消除任何与并发轮换之间的漂移窗口。
func (k *Keyring) WrapCurrentWithAAD(dek []byte, aadFunc func(version uint32) []byte) (wrapped []byte, version uint32, err error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	version = k.currentVersion
	return k.wrapLocked(version, dek, aadFunc(version))
}

// wrapLocked 使用指定版本封包；调用方持读锁。
func (k *Keyring) wrapLocked(version uint32, dek, aad []byte) ([]byte, uint32, error) {
	entry, ok := k.versions[version]
	if !ok {
		return nil, 0, fmt.Errorf("%w: version %d", ErrKeyVersionNotFound, version)
	}
	w, err := gcmSeal(entry.plain, dek, aad)
	if err != nil {
		return nil, 0, err
	}
	return w, entry.version, nil
}

// UnwrapVersion 用指定版本主密钥解包 DEK。
// 引用不存在的版本时错误可通过 errors.Is(err, ErrKeyVersionNotFound) 区分，
// 绝不静默改用当前版本或其它版本。
func (k *Keyring) UnwrapVersion(version uint32, wrappedDEK, aad []byte) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	entry, ok := k.versions[version]
	if !ok {
		return nil, fmt.Errorf("%w: version %d", ErrKeyVersionNotFound, version)
	}
	dek, err := gcmOpen(entry.plain, wrappedDEK, aad)
	if err != nil {
		return nil, err
	}
	return dek, nil
}

// addVersionLocked 生成下一把主密钥并用当前 KEK 包装，加入 versions。
// 调用方必须持有写锁。
func (k *Keyring) addVersionLocked() (uint32, error) {
	plain, err := randomKey()
	if err != nil {
		return 0, err
	}
	kek := deriveKEK(k.passphrase, k.kdf)
	v := k.nextVersion
	aad := masterKeyAAD(v)
	wrapped, err := gcmSeal(kek, plain, aad)
	if err != nil {
		return 0, err
	}
	k.versions[v] = &versionEntry{
		version: v,
		created: nowRFC3339(),
		plain:   plain,
		wrapped: wrapped,
	}
	k.nextVersion++
	return v, nil
}

// persistLocked 把完整密钥环状态序列化并原子写入文件（同目录临时文件 + rename）。
// 调用方必须持有写锁；文件权限 0600，内容只包含密态主密钥与 KDF 参数。
func (k *Keyring) persistLocked() error {
	pk := persistedKeyring{
		KDF:            k.kdf,
		CurrentVersion: k.currentVersion,
		NextVersion:    k.nextVersion,
	}
	for _, e := range k.versions {
		pk.Versions = append(pk.Versions, persistedVersion{
			Version: e.version,
			Created: e.created,
			Wrapped: e.wrapped,
		})
	}
	sort.Slice(pk.Versions, func(i, j int) bool { return pk.Versions[i].Version < pk.Versions[j].Version })

	data, err := json.MarshalIndent(&pk, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(k.filePath, data, 0o600); err != nil {
		return err
	}
	return nil
}

// masterKeyAAD 构造包装主密钥时的认证附加数据，绑定版本号。
func masterKeyAAD(version uint32) []byte {
	return []byte(fmt.Sprintf("envelope:masterkey:v1:version=%d", version))
}

// nowRFC3339 返回当前 UTC 时间的 RFC3339 字符串。
func nowRFC3339() string {
	return nowUTC().Format("2006-01-02T15:04:05Z07:00")
}
