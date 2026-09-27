// Package envelope 提供本地信封加密、主密钥多版本管理/轮换以及按租户隔离的能力。
//
// 本文件集中定义所有可区分的错误类型。调用方应当使用 errors.Is 判定错误类别，
// 用 errors.As 取得携带详细信息的错误结构体，而不是依赖错误字符串匹配。
package envelope

import (
	"errors"
	"fmt"
)

// 哨兵错误：调用方用 errors.Is 判定具体失败原因。
var (
	// ErrKeyVersionNotFound 密文引用的主密钥版本不存在（可能已被删除或从未创建）。
	ErrKeyVersionNotFound = errors.New("envelope: referenced key version not found")
	// ErrTenantDenied 跨租户访问：调用方租户与密文/数据归属租户不一致。
	ErrTenantDenied = errors.New("envelope: cross-tenant access denied")
	// ErrTenantUnknown 调用方使用的租户尚未注册。
	ErrTenantUnknown = errors.New("envelope: tenant is not registered")
	// ErrRecordNotFound 要读取的数据 ID 不存在。
	ErrRecordNotFound = errors.New("envelope: record not found")
	// ErrRecordExists 不允许覆盖的写入目标已存在。
	ErrRecordExists = errors.New("envelope: record already exists")
	// ErrCiphertextCorrupt 密文或信封格式损坏/被篡改。
	ErrCiphertextCorrupt = errors.New("envelope: ciphertext is corrupt or tampered")
	// ErrInvalidArgument 入参不合法。
	ErrInvalidArgument = errors.New("envelope: invalid argument")
	// ErrKeyringEmpty 密钥环里一个主密钥版本都没有（尚未初始化）。
	ErrKeyringEmpty = errors.New("envelope: keyring has no key versions")
)

// KeyVersionError 携带被引用却找不到的主密钥版本号。
type KeyVersionError struct {
	Version int
}

func (e *KeyVersionError) Error() string {
	return fmt.Sprintf("%s: key version %d is not present in the keyring", ErrKeyVersionNotFound, e.Version)
}

func (e *KeyVersionError) Unwrap() error { return ErrKeyVersionNotFound }

// TenantDeniedError 携带一次跨租户访问的判定依据：调用方与数据归属方。
type TenantDeniedError struct {
	CallerTenant string
	OwnerTenant  string
}

func (e *TenantDeniedError) Error() string {
	return fmt.Sprintf("%s: caller tenant %q does not own record of tenant %q",
		ErrTenantDenied, e.CallerTenant, e.OwnerTenant)
}

func (e *TenantDeniedError) Unwrap() error { return ErrTenantDenied }

// TenantUnknownError 表示调用方租户没有在本地密钥环中注册。
type TenantUnknownError struct {
	Tenant string
}

func (e *TenantUnknownError) Error() string {
	return fmt.Sprintf("%s: tenant %q has not been registered", ErrTenantUnknown, e.Tenant)
}

func (e *TenantUnknownError) Unwrap() error { return ErrTenantUnknown }

// RecordNotFoundError 携带缺失的数据 ID 与租户。
type RecordNotFoundError struct {
	Tenant string
	ID     string
}

func (e *RecordNotFoundError) Error() string {
	return fmt.Sprintf("%s: no record with id %q for tenant %q", ErrRecordNotFound, e.ID, e.Tenant)
}

func (e *RecordNotFoundError) Unwrap() error { return ErrRecordNotFound }

// RecordExistsError 携带冲突的数据 ID 与租户。
type RecordExistsError struct {
	Tenant string
	ID     string
}

func (e *RecordExistsError) Error() string {
	return fmt.Sprintf("%s: record %q already exists for tenant %q", ErrRecordExists, e.ID, e.Tenant)
}

func (e *RecordExistsError) Unwrap() error { return ErrRecordExists }

// CorruptCiphertextError 携带解析/校验失败的密文所属租户与数据 ID（可能为空）。
type CorruptCiphertextError struct {
	Tenant string
	ID     string
	Reason string
}

func (e *CorruptCiphertextError) Error() string {
	who := e.Tenant
	if who == "" {
		who = "<unknown>"
	}
	return fmt.Sprintf("%s: record %q of tenant %q: %s",
		ErrCiphertextCorrupt, e.ID, who, e.Reason)
}

func (e *CorruptCiphertextError) Unwrap() error { return ErrCiphertextCorrupt }

// InvalidArgumentError 携带具体的参数名与原因。
type InvalidArgumentError struct {
	Argument string
	Reason   string
}

func (e *InvalidArgumentError) Error() string {
	return fmt.Sprintf("%s: argument %s: %s", ErrInvalidArgument, e.Argument, e.Reason)
}

func (e *InvalidArgumentError) Unwrap() error { return ErrInvalidArgument }
