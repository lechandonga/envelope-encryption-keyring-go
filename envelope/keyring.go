package envelope

import (
	"crypto/rand"
	"io"
	"sort"
	"sync/atomic"
	"time"
)

// saltLen 是每版本 KEK 派生盐的长度（非秘密，但要求每版本独立随机）。
const saltLen = 32

// keyring 管理多版本主密钥以及租户注册表，并提供按版本取 KEK 的能力。
//
// 并发模型：
//   - versions / currentVersion / tenants 的“读”全部走 atomic.Pointer
//     指向不可变快照，读路径（加解密）完全无锁，与轮换并发进行时拿到的
//     永远是某个时间点一致的快照，不会出现版本错乱；
//   - rotate / 注册租户等写操作由外层 Service.mu 写锁串行化，并以
//     copy-on-write 方式整体替换快照。
type keyringSnapshot struct {
	versions       map[int]*keyVersion // 版本号 -> 版本信息（保留全部历史版本）
	currentVersion int                 // 当前加密使用的版本
	tenants        map[string]struct{} // 已注册租户集合
}

type keyring struct {
	eng  *cryptoEngine
	snap atomic.Pointer[keyringSnapshot]
}

func newKeyring(eng *cryptoEngine) *keyring {
	k := &keyring{eng: eng}
	k.snap.Store(&keyringSnapshot{
		versions: map[int]*keyVersion{},
		tenants:  map[string]struct{}{},
	})
	return k
}

// load 取当前不可变快照（构造后永不为 nil）。
func (k *keyring) load() *keyringSnapshot { return k.snap.Load() }

// cloneLocked 复制一份可变快照，供 copy-on-write 写操作使用。
func (s *keyringSnapshot) cloneLocked() *keyringSnapshot {
	versions := make(map[int]*keyVersion, len(s.versions))
	for v, kv := range s.versions {
		cp := *kv
		salt := make([]byte, len(kv.salt))
		copy(salt, kv.salt)
		cp.salt = salt
		versions[v] = &cp
	}
	tenants := make(map[string]struct{}, len(s.tenants))
	for t := range s.tenants {
		tenants[t] = struct{}{}
	}
	return &keyringSnapshot{
		versions:       versions,
		currentVersion: s.currentVersion,
		tenants:        tenants,
	}
}

func newSalt() ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// Bootstrap 空密钥环启动：生成第一个主密钥版本。
// 非空（从磁盘恢复）时必须使用 Restore，而不是重新生成。
func (k *keyring) Bootstrap() (*keyVersion, error) {
	cur := k.load()
	if len(cur.versions) != 0 {
		return cur.versions[cur.currentVersion], nil
	}
	salt, err := newSalt()
	if err != nil {
		return nil, err
	}
	kv := &keyVersion{version: 1, salt: salt, createdUnix: time.Now().Unix()}

	next := cur.cloneLocked()
	next.versions[1] = kv
	next.currentVersion = 1
	k.snap.Store(next)
	return kv, nil
}

// Restore 从磁盘元数据恢复整个密钥环（启动时调用一次）。
func (k *keyring) Restore(f *keyringFile) error {
	if f == nil {
		return &InvalidArgumentError{Argument: "keyringFile", Reason: "nil"}
	}
	snap := &keyringSnapshot{
		versions:       map[int]*keyVersion{},
		currentVersion: f.CurrentVersion,
		tenants:        map[string]struct{}{},
	}
	for _, m := range f.Versions {
		salt := make([]byte, len(m.Salt))
		copy(salt, m.Salt)
		snap.versions[m.Version] = &keyVersion{
			version:     m.Version,
			salt:        salt,
			createdUnix: m.CreatedUnix,
		}
	}
	for _, t := range f.Tenants {
		snap.tenants[t] = struct{}{}
	}
	if snap.currentVersion != 0 {
		if _, ok := snap.versions[snap.currentVersion]; !ok {
			return &CorruptCiphertextError{
				Reason: "keys.json current_version does not match any version entry",
			}
		}
	}
	k.snap.Store(snap)
	return nil
}

// CurrentVersion 返回当前主密钥版本；密钥环为空时返回 0。
func (k *keyring) CurrentVersion() int { return k.load().currentVersion }

// VersionCount 返回已保留的主密钥版本数量。
func (k *keyring) VersionCount() int { return len(k.load().versions) }

// TenantRegistered 判定租户是否已注册。
func (k *keyring) TenantRegistered(tenant string) bool {
	_, ok := k.load().tenants[tenant]
	return ok
}

// CurrentKEK 返回当前版本的版本信息与 KEK，供加密新数据使用。
func (k *keyring) CurrentKEK() (*keyVersion, []byte, error) {
	s := k.load()
	if s.currentVersion == 0 {
		return nil, nil, ErrKeyringEmpty
	}
	kv := s.versions[s.currentVersion]
	kek, err := k.eng.deriveKEK(kv)
	if err != nil {
		return nil, nil, err
	}
	return kv, kek, nil
}

// KEKForVersion 按版本号返回历史版本信息与 KEK，供解密老密文使用。
// 版本不存在时返回包裹了 ErrKeyVersionNotFound 的 *KeyVersionError，
// 绝不静默降级到别的版本。
func (k *keyring) KEKForVersion(version int) (*keyVersion, []byte, error) {
	s := k.load()
	kv, ok := s.versions[version]
	if !ok {
		return nil, nil, &KeyVersionError{Version: version}
	}
	kek, err := k.eng.deriveKEK(kv)
	if err != nil {
		return nil, nil, err
	}
	return kv, kek, nil
}

// Rotate 生成一个新主密钥版本并把它设为当前版本；旧版本全部保留。
// 返回新版本号。写路径：调用方必须持有 Service.mu 写锁。
func (k *keyring) Rotate() (*keyVersion, error) {
	cur := k.load()
	salt, err := newSalt()
	if err != nil {
		return nil, err
	}
	nv := cur.currentVersion + 1
	kv := &keyVersion{version: nv, salt: salt, createdUnix: time.Now().Unix()}

	next := cur.cloneLocked()
	next.versions[nv] = kv
	next.currentVersion = nv
	k.snap.Store(next)
	return kv, nil
}

// RegisterTenant 登记一个租户（幂等）。写路径：调用方必须持有 Service.mu 写锁。
// 返回 true 表示这是新登记的租户（需要持久化）。
func (k *keyring) RegisterTenant(tenant string) (bool, error) {
	if tenant == "" {
		return false, &InvalidArgumentError{Argument: "tenant", Reason: "must not be empty"}
	}
	cur := k.load()
	if _, ok := cur.tenants[tenant]; ok {
		return false, nil
	}
	next := cur.cloneLocked()
	next.tenants[tenant] = struct{}{}
	k.snap.Store(next)
	return true, nil
}

// Tenants 返回已注册租户的有序快照切片。
func (k *keyring) Tenants() []string {
	s := k.load()
	out := make([]string, 0, len(s.tenants))
	for t := range s.tenants {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// snapshotMeta 把当前快照转成可落盘的元数据（仅非秘密材料）。
func (k *keyring) snapshotMeta() *keyringFile {
	s := k.load()
	f := &keyringFile{
		CurrentVersion: s.currentVersion,
		Tenants:        k.Tenants(),
		Versions:       make([]keyMeta, 0, len(s.versions)),
	}
	versions := make([]int, 0, len(s.versions))
	for v := range s.versions {
		versions = append(versions, v)
	}
	sort.Ints(versions)
	for _, v := range versions {
		kv := s.versions[v]
		salt := make([]byte, len(kv.salt))
		copy(salt, kv.salt)
		f.Versions = append(f.Versions, keyMeta{
			Version:     kv.version,
			Salt:        salt,
			CreatedUnix: kv.createdUnix,
		})
	}
	return f
}
