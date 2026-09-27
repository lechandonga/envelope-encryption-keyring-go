package envelope

import (
	"errors"
	"fmt"
)

// 哨兵错误：调用方使用 errors.Is 即可判断失败类别，
// 配合错误上携带的结构化字段（KeyVersionError / TenantAccessError）
// 可以进一步区分“具体是哪个版本缺失”“哪个租户越权访问了谁的数据”。
var (
	// ErrKeyVersionNotFound 密文引用的主密钥版本在本地密钥环中不存在。
	// 典型场景：密文在另一套环境产生、对应版本已被物理删除。
	// 组件不会静默降级到其它版本解密。
	ErrKeyVersionNotFound = errors.New("envelope: master key version not found")

	// ErrTenantMismatch 租户越权访问：请求租户与密文属主租户不一致。
	ErrTenantMismatch = errors.New("envelope: tenant access denied")

	// ErrRecordNotFound 本地存储中找不到指定密文记录。
	ErrRecordNotFound = errors.New("envelope: ciphertext record not found")

	// ErrRecordAlreadyExists 写入策略为“仅允许新建”时记录已存在。
	ErrRecordAlreadyExists = errors.New("envelope: ciphertext record already exists")

	// ErrInvalidCiphertext 密文结构损坏或认证失败（包含 DEK 解包失败、AAD 不匹配等）。
	ErrInvalidCiphertext = errors.New("envelope: ciphertext is invalid or corrupt")

	// ErrInvalidArgument 入参非法。
	ErrInvalidArgument = errors.New("envelope: invalid argument")

	// ErrKeyringNotInitialized 密钥环尚未初始化（从未执行初始化 / 没有任何主密钥版本）。
	ErrKeyringNotInitialized = errors.New("envelope: keyring is not initialized")

	// ErrInvalidPassphrase 打开密钥环时口令错误（KEK 解包认证失败）。
	ErrInvalidPassphrase = errors.New("envelope: incorrect keyring passphrase")
)

// KeyVersionError 表示“密文引用了不存在的主密钥版本”这一具体失败原因。
// errors.Is(err, ErrKeyVersionNotFound) 成立，同时字段给出缺失版本号与上下文。
type KeyVersionError struct {
	// Version 密文引用、但密钥环中不存在的主密钥版本号。
	Version uint32
	// TenantID 发起本次操作的租户（仅用于错误上下文）。
	TenantID string
	// RecordID 触发该错误的密文记录 ID（仅用于错误上下文）。
	RecordID string
}

func (e *KeyVersionError) Error() string {
	if e.RecordID != "" {
		return fmt.Sprintf("%s: version=%d referenced by record %q for tenant %q does not exist",
			ErrKeyVersionNotFound, e.Version, e.RecordID, e.TenantID)
	}
	return fmt.Sprintf("%s: version=%d does not exist", ErrKeyVersionNotFound, e.Version)
}

// Is 支持 errors.Is(err, ErrKeyVersionNotFound)，避免调用方依赖具体类型断言。
func (e *KeyVersionError) Is(target error) bool { return target == ErrKeyVersionNotFound }

func (e *KeyVersionError) Unwrap() error { return ErrKeyVersionNotFound }

// TenantAccessError 表示跨租户越权访问这一具体失败原因。
// errors.Is(err, ErrTenantMismatch) 成立，字段给出请求方/属主/操作类型。
type TenantAccessError struct {
	// TenantID 发起请求的租户。
	TenantID string
	// OwnerTenantID 密文记录的属主租户。
	OwnerTenantID string
	// RecordID 被访问的密文记录 ID。
	RecordID string
	// Operation 触发拒绝的操作，如 "encrypt" / "decrypt"。
	Operation string
}

func (e *TenantAccessError) Error() string {
	return fmt.Sprintf("%s: tenant %q is not allowed to %s record %q owned by tenant %q",
		ErrTenantMismatch, e.TenantID, e.Operation, e.RecordID, e.OwnerTenantID)
}

// Is 支持 errors.Is(err, ErrTenantMismatch)。
func (e *TenantAccessError) Is(target error) bool { return target == ErrTenantMismatch }

func (e *TenantAccessError) Unwrap() error { return ErrTenantMismatch }
