package envelope

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

// Storage 是密文记录的本地文件存储：
//   - 每条密文记录落为 <dir>/records/<recordID> 一个独立文件，0600 权限；
//   - 写入走 writeFileAtomic（临时文件 + fsync + rename），写失败绝不留下
//     半成品密文，更不会让原有完整密文被截断；
//   - 进程内用 per-record（分桶）互斥串行化同一记录的并发写入，不同记录互不阻塞；
//   - 存储层不理解租户语义：租户访问控制由 Service 在密文元数据层面强制执行，
//     这里只负责“按 ID 存/取字节”。
//
// 注意：锁是进程内锁，适用于单进程本地组件；文件本身的原子性保证在崩溃/
// 异常退出时依然成立。
type Storage struct {
	dir string

	writeLocks *stripedMutex
}

// validRecordID 限制记录 ID 字符集，杜绝路径穿越与奇怪文件名。
// 允许字母数字、'-'、'_'、'.'，长度 1~128，且首字符不允许是 '.'。
var validRecordID = regexp.MustCompile(`^[A-Za-z0-9_\-][A-Za-z0-9_\-.]{0,127}$`)

// NewStorage 打开（必要时创建）一个密文存储目录。
func NewStorage(dir string) (*Storage, error) {
	if dir == "" {
		return nil, fmt.Errorf("%w: storage dir is empty", ErrInvalidArgument)
	}
	recordsDir := filepath.Join(dir, "records")
	if err := os.MkdirAll(recordsDir, 0o700); err != nil {
		return nil, fmt.Errorf("create storage dir: %w", err)
	}
	return &Storage{
		dir:        recordsDir,
		writeLocks: newStripedMutex(64),
	}, nil
}

// Save 原子保存一条密文记录（覆盖语义）。同 ID 并发写在进程内串行化，
// 每次落盘都是一个完整、可解析的密文 blob。
func (s *Storage) Save(recordID string, data []byte) error {
	if err := validateRecordID(recordID); err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("%w: empty ciphertext payload", ErrInvalidArgument)
	}
	mu := s.writeLocks.get(recordID)
	mu.Lock()
	defer mu.Unlock()
	return writeFileAtomic(s.path(recordID), data, 0o600)
}

// SaveIfAbsent 仅当记录不存在时写入，用于“新建”语义；已存在时返回
// ErrRecordAlreadyExists，保证不会静默覆盖别人的数据。
func (s *Storage) SaveIfAbsent(recordID string, data []byte) error {
	if err := validateRecordID(recordID); err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("%w: empty ciphertext payload", ErrInvalidArgument)
	}
	mu := s.writeLocks.get(recordID)
	mu.Lock()
	defer mu.Unlock()

	if _, err := os.Stat(s.path(recordID)); err == nil {
		return fmt.Errorf("%w: record %q", ErrRecordAlreadyExists, recordID)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat record %q: %w", recordID, err)
	}
	return writeFileAtomic(s.path(recordID), data, 0o600)
}

// Load 读取一条密文记录；不存在时返回 ErrRecordNotFound。
func (s *Storage) Load(recordID string) ([]byte, error) {
	if err := validateRecordID(recordID); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(s.path(recordID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: record %q", ErrRecordNotFound, recordID)
		}
		return nil, fmt.Errorf("read record %q: %w", recordID, err)
	}
	return data, nil
}

// Exists 返回记录是否存在。
func (s *Storage) Exists(recordID string) (bool, error) {
	if err := validateRecordID(recordID); err != nil {
		return false, err
	}
	_, err := os.Stat(s.path(recordID))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("stat record %q: %w", recordID, err)
}

// Delete 删除一条记录；不存在时返回 ErrRecordNotFound。
func (s *Storage) Delete(recordID string) error {
	if err := validateRecordID(recordID); err != nil {
		return err
	}
	mu := s.writeLocks.get(recordID)
	mu.Lock()
	defer mu.Unlock()

	if err := os.Remove(s.path(recordID)); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: record %q", ErrRecordNotFound, recordID)
		}
		return fmt.Errorf("delete record %q: %w", recordID, err)
	}
	return nil
}

func (s *Storage) path(recordID string) string {
	return filepath.Join(s.dir, recordID)
}

func validateRecordID(recordID string) error {
	if !validRecordID.MatchString(recordID) {
		return fmt.Errorf("%w: record ID %q must match %s and must not start with '.'",
			ErrInvalidArgument, recordID, validRecordID.String())
	}
	return nil
}

// stripedMutex 以 ID 哈希分桶提供 per-key 互斥锁，避免为海量记录各建一把锁。
type stripedMutex struct {
	locks []sync.Mutex
	mask  uint32
}

func newStripedMutex(n int) *stripedMutex {
	// n 向上取到 2 的幂，掩码取桶。
	size := 1
	for size < n {
		size <<= 1
	}
	return &stripedMutex{
		locks: make([]sync.Mutex, size),
		mask:  uint32(size - 1),
	}
}

func (sm *stripedMutex) get(key string) *sync.Mutex {
	return &sm.locks[fnv32(key)&sm.mask]
}

// fnv32 FNV-1a 32 位哈希，仅用于锁分桶，不承担任何安全职责。
func fnv32(s string) uint32 {
	const (
		offset32 = uint32(2166136261)
		prime32  = uint32(16777619)
	)
	h := offset32
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= prime32
	}
	return h
}
