package envelope_test

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	envelope "github.com/lechandonga/envelope-encryption-keyring-go"
)

// ExampleService 演示：初始化 → 按租户加密 → 轮换主密钥 → 旧密文照常解密、
// 新密文用新版本 → 跨租户读取被拒绝且原因可区分。
func ExampleService() {
	dir, err := os.MkdirTemp("", "envelope-example-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	log := slog.New(slog.NewTextHandler(io.Discard, nil)) // 示例静默日志；实战可接任意 slog handler

	kr, err := envelope.CreateKeyring(dir, "a-local-passphrase", log)
	if err != nil {
		panic(err)
	}
	st, err := envelope.NewStorage(dir)
	if err != nil {
		panic(err)
	}
	svc, err := envelope.NewService(kr, st, log)
	if err != nil {
		panic(err)
	}

	// tenant-a 在轮换前写入数据（v1）。
	if _, err := svc.Encrypt("tenant-a", "invoice-1", []byte("amount=100"), envelope.WritePolicyMustCreate); err != nil {
		panic(err)
	}

	// 轮换主密钥：新数据从此用新版本，旧版本保留。
	newVersion, err := svc.RotateKey()
	if err != nil {
		panic(err)
	}
	fmt.Println("rotated to version:", newVersion)

	// 历史密文仍按其记录的旧版本解开。
	oldPT, oldRec, err := svc.Decrypt("tenant-a", "invoice-1")
	if err != nil {
		panic(err)
	}
	fmt.Printf("old record v%d decrypts: %s\n", oldRec.KeyVersion, oldPT)

	// 新密文使用当前版本。
	newRec, err := svc.Encrypt("tenant-a", "invoice-2", []byte("amount=200"), envelope.WritePolicyMustCreate)
	if err != nil {
		panic(err)
	}
	fmt.Println("new record version:", newRec.KeyVersion)

	// 跨租户读取：明确可区分的拒绝原因。
	_, _, err = svc.Decrypt("tenant-b", "invoice-1")
	switch {
	case errors.Is(err, envelope.ErrTenantMismatch):
		fmt.Println("tenant-b denied: tenant mismatch")
	case errors.Is(err, envelope.ErrKeyVersionNotFound):
		fmt.Println("key version missing")
	default:
		panic(err)
	}

	// 重启后：用同口令打开密钥环，历史密文继续可解。
	kr2, err := envelope.OpenKeyring(dir, "a-local-passphrase", log)
	if err != nil {
		panic(err)
	}
	svc2, err := envelope.NewService(kr2, st, log)
	if err != nil {
		panic(err)
	}
	pt, _, err := svc2.Decrypt("tenant-a", "invoice-1")
	if err != nil {
		panic(err)
	}
	fmt.Printf("after restart old record still decrypts: %s\n", pt)

	// Output:
	// rotated to version: 2
	// old record v1 decrypts: amount=100
	// new record version: 2
	// tenant-b denied: tenant mismatch
	// after restart old record still decrypts: amount=100
}
