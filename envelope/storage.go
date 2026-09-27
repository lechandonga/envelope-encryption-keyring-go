package envelope

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// keyMeta 是单个主密钥版本在磁盘上的持久形态。
// 只保存非秘密材料：版本号、派生盐、创建时间。rootSecret 不在这里。
type keyMeta struct {
	Version     int    `json:"version"`
	Salt        []byte `json:"salt"`
	CreatedUnix int64  `json:"created_unix"`
}

// keyringFile 是密钥环元数据文件 keys.json 的内容。
type keyringFile struct {
	CurrentVersion int       `json:"current_version"`
	Tenants        []string  `json:"tenants"`
	Versions       []keyMeta `json:"versions"`
}

// recordHeader 是每条密文记录的落盘头部。
// 注意：落盘内容不包含任何明文密钥材料；wrapped_key 是被 KEK 包裹后的 DEK。
type recordHeader struct {
	ID          string `json:"id"`
	Tenant      string `json:"tenant"`
	KeyVersion  int    `json:"key_version"`
	WrappedKey  []byte `json:"wrapped_key"`
	WrapNonce   []byte `json:"wrap_nonce"`
	DataNonce   []byte `json:"data_nonce"`
	CreatedUnix int64  `json:"created_unix"`
}

// recordFile 是单条数据记录 <id>.json 的完整落盘内容。
type recordFile struct {
	Header recordHeader `json:"header"`
	// Ciphertext 用 DEK 加密业务明文得到的密文（含 GCM tag）。
	Ciphertext []byte `json:"ciphertext"`
}

// Store 是本地持久化抽象。
type Store interface {
	// LoadKeyring 读取密钥环元数据；文件不存在时返回 (nil, io.EOF)。
	LoadKeyring() (*keyringFile, error)
	// SaveKeyring 以原子方式（临时文件 + rename）整体写入密钥环元数据。
	SaveKeyring(f *keyringFile) error

	// LoadRecord 读取一条密文记录；不存在时返回包裹 ErrRecordNotFound 的错误。
	LoadRecord(tenant, id string) (*recordFile, error)
	// CreateRecord 原子写入一条新记录。若文件已存在，返回包裹 ErrRecordExists 的错误。
	CreateRecord(tenant, id string, rec *recordFile) error
	// RecordExists 判断某租户下某 ID 是否存在。
	RecordExists(tenant, id string) (bool, error)
}

const (
	keysFileName = "keys.json"
	tenantsDir   = "tenants"
	dataDir      = "data"
	tmpSuffix    = ".tmp"
)

// FileStore 是基于本地目录的 Store 实现。
//
// 目录布局：
//
//	dir/keys.json                 密钥环元数据（只有版本号/盐/租户，无密钥材料）
//	dir/tenants/<tenant>/data/<id>.json   每条业务密文一个文件
//
// 所有写操作都是“写临时文件 -> fsync -> rename”，中途崩溃只会留下一个
// 会被忽略的 .tmp 文件，绝不会出现半截 JSON 被后续读取。
type FileStore struct {
	dir string
}

// NewFileStore 在 dir 下初始化本地存储布局。
func NewFileStore(dir string) (*FileStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, &InvalidArgumentError{Argument: "dir", Reason: "must not be empty"}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("envelope: create store dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, tenantsDir), 0o700); err != nil {
		return nil, fmt.Errorf("envelope: create tenants dir: %w", err)
	}
	// 解析为绝对路径，杜绝后续相对路径带来的歧义。
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	return &FileStore{dir: abs}, nil
}

func (s *FileStore) keysPath() string {
	return filepath.Join(s.dir, keysFileName)
}

// tenantDir / recordPath 对租户与 ID 做严格白名单校验，
// 防止 "../" 之类的输入逃逸到别的目录或别的租户空间。
func (s *FileStore) tenantDir(tenant string) (string, error) {
	if err := validateName(tenant); err != nil {
		return "", &InvalidArgumentError{Argument: "tenant", Reason: err.Error()}
	}
	return filepath.Join(s.dir, tenantsDir, tenant), nil
}

func (s *FileStore) recordPath(tenant, id string) (string, error) {
	td, err := s.tenantDir(tenant)
	if err != nil {
		return "", err
	}
	if err := validateName(id); err != nil {
		return "", &InvalidArgumentError{Argument: "id", Reason: err.Error()}
	}
	return filepath.Join(td, dataDir, id+".json"), nil
}

// validateName 只允许字母、数字、点、下划线、连字符；长度 1~128。
func validateName(name string) error {
	if name == "" || len(name) > 128 {
		return fmt.Errorf("name must be 1~128 chars")
	}
	if name == "." || name == ".." {
		return fmt.Errorf("reserved name not allowed")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return fmt.Errorf("only [A-Za-z0-9._-] allowed, got %q", r)
		}
	}
	return nil
}

// writeFileAtomic 在同目录写临时文件，fsync 后原子 rename 覆盖目标。
func writeFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("envelope: mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*"+tmpSuffix)
	if err != nil {
		return fmt.Errorf("envelope: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			// 失败路径：尽量清理临时文件，绝不让半成品留下被后续读到。
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("envelope: write temp file: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("envelope: fsync temp file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("envelope: close temp file: %w", err)
	}
	if err = os.Chmod(tmpName, perm); err != nil {
		return fmt.Errorf("envelope: chmod temp file: %w", err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("envelope: rename temp file: %w", err)
	}
	return nil
}

func (s *FileStore) LoadKeyring() (*keyringFile, error) {
	raw, err := os.ReadFile(s.keysPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("envelope: read %s: %w", keysFileName, err)
	}
	var f keyringFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, &CorruptCiphertextError{Reason: keysFileName + " is not valid JSON: " + err.Error()}
	}
	return &f, nil
}

func (s *FileStore) SaveKeyring(f *keyringFile) error {
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("envelope: encode keyring metadata: %w", err)
	}
	return writeFileAtomic(s.keysPath(), raw, 0o600)
}

func (s *FileStore) LoadRecord(tenant, id string) (*recordFile, error) {
	path, err := s.recordPath(tenant, id)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, &RecordNotFoundError{Tenant: tenant, ID: id}
		}
		return nil, fmt.Errorf("envelope: read record: %w", err)
	}
	var rec recordFile
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, &CorruptCiphertextError{
			Tenant: tenant,
			ID:     id,
			Reason: "record file is not valid JSON: " + err.Error(),
		}
	}
	// 即便文件读得到，也校验文件内声明的归属，防止被人手工挪动文件后混淆归属。
	if rec.Header.Tenant != "" && rec.Header.Tenant != tenant {
		return nil, &TenantDeniedError{CallerTenant: tenant, OwnerTenant: rec.Header.Tenant}
	}
	return &rec, nil
}

// CreateRecord 原子创建一条记录；已存在则返回 *RecordExistsError，绝不静默覆盖。
//
// 实现采用“同目录临时文件 + 原子硬链接(link)”：
//   - 先完整写出并 fsync 临时文件，保证内容落盘；
//   - link(2) 在目标路径上是原子的排他操作，目标已存在时返回 EEXIST，
//     因而即使绕过 Service 写锁（例如多进程），也绝不会覆盖既有密文；
//   - 成功后删除临时名（同一 inode 仍由目标路径引用）。
func (s *FileStore) CreateRecord(tenant, id string, rec *recordFile) error {
	if rec == nil {
		return &InvalidArgumentError{Argument: "record", Reason: "nil"}
	}
	path, err := s.recordPath(tenant, id)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("envelope: mkdir %s: %w", dir, err)
	}
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("envelope: encode record: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".tmp-*"+tmpSuffix)
	if err != nil {
		return fmt.Errorf("envelope: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	abort := func(cause error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return cause
	}
	if _, err := tmp.Write(raw); err != nil {
		return abort(fmt.Errorf("envelope: write temp file: %w", err))
	}
	if err := tmp.Sync(); err != nil {
		return abort(fmt.Errorf("envelope: fsync temp file: %w", err))
	}
	if err := tmp.Close(); err != nil {
		return abort(fmt.Errorf("envelope: close temp file: %w", err))
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return abort(fmt.Errorf("envelope: chmod temp file: %w", err))
	}

	// 原子排他发布：link 不会覆盖已存在目标。
	if lerr := os.Link(tmpName, path); lerr != nil {
		if errors.Is(lerr, os.ErrExist) {
			return abort(&RecordExistsError{Tenant: tenant, ID: id})
		}
		return abort(fmt.Errorf("envelope: publish record: %w", lerr))
	}
	// 发布成功；临时名只是同 inode 的额外目录项，删除不影响正式文件。
	if err := os.Remove(tmpName); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("envelope: unlink temp name after publish: %w", err)
	}
	return nil
}

func (s *FileStore) RecordExists(tenant, id string) (bool, error) {
	path, err := s.recordPath(tenant, id)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("envelope: stat record: %w", err)
	}
}
