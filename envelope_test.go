package envelope

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	_, svc, _ := setupService(t, "passphrase")

	plaintext := []byte("hello multi-tenant envelope encryption")
	rec, err := svc.Encrypt("tenant-a", "doc-1", plaintext, WritePolicyMustCreate)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if rec.KeyVersion != 1 {
		t.Fatalf("new record key version = %d, want 1", rec.KeyVersion)
	}

	got, loaded, err := svc.Decrypt("tenant-a", "doc-1")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %q", got)
	}
	if loaded.KeyVersion != 1 {
		t.Fatalf("loaded key version = %d, want 1", loaded.KeyVersion)
	}
}

func TestRotateThenOldCiphertextStillDecryptsAndNewWritesUseNewVersion(t *testing.T) {
	_, svc, kr := setupService(t, "passphrase")

	// 轮换前：v1 写入老数据。
	oldPlaintext := []byte("written-before-rotation")
	oldRec, err := svc.Encrypt("tenant-a", "old-doc", oldPlaintext, WritePolicyMustCreate)
	if err != nil {
		t.Fatalf("Encrypt old: %v", err)
	}
	if oldRec.KeyVersion != 1 {
		t.Fatalf("old record key version = %d, want 1", oldRec.KeyVersion)
	}

	// 轮换到 v2、再 v3。
	if v, err := svc.RotateKey(); err != nil || v != 2 {
		t.Fatalf("RotateKey = %d, %v", v, err)
	}
	if v, err := svc.RotateKey(); err != nil || v != 3 {
		t.Fatalf("RotateKey = %d, %v", v, err)
	}
	if kr.CurrentVersion() != 3 {
		t.Fatalf("current version = %d, want 3", kr.CurrentVersion())
	}

	// 历史密文引用的还是 v1，必须能用保留下来的旧版本解开。
	got, recAfter, err := svc.Decrypt("tenant-a", "old-doc")
	if err != nil {
		t.Fatalf("Decrypt old after rotation: %v", err)
	}
	if !bytes.Equal(got, oldPlaintext) {
		t.Fatalf("old plaintext mismatch: got %q", got)
	}
	if recAfter.KeyVersion != 1 {
		t.Fatalf("old record must keep key_version=1, got %d", recAfter.KeyVersion)
	}
	t.Logf("basis=retained old master key version allows decrypt; record key_version=%d, service current=%d",
		recAfter.KeyVersion, svc.CurrentKeyVersion())

	// 轮换后新写入必须走当前版本 v3。
	newPlaintext := []byte("written-after-rotation")
	newRec, err := svc.Encrypt("tenant-a", "new-doc", newPlaintext, WritePolicyMustCreate)
	if err != nil {
		t.Fatalf("Encrypt new: %v", err)
	}
	if newRec.KeyVersion != 3 {
		t.Fatalf("new record key version = %d, want 3", newRec.KeyVersion)
	}
	got, _, err = svc.Decrypt("tenant-a", "new-doc")
	if err != nil || !bytes.Equal(got, newPlaintext) {
		t.Fatalf("Decrypt new after rotation: %q, %v", got, err)
	}
}

func TestCrossTenantDecryptDeniedWithDistinguishableReason(t *testing.T) {
	_, svc, _ := setupService(t, "passphrase")
	if _, err := svc.Encrypt("tenant-a", "secret", []byte("a's data"), WritePolicyMustCreate); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, _, err := svc.Decrypt("tenant-b", "secret")
	if !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("err = %v, want ErrTenantMismatch", err)
	}
	var tae *TenantAccessError
	if !errors.As(err, &tae) {
		t.Fatalf("err type = %T, want *TenantAccessError", err)
	}
	if tae.TenantID != "tenant-b" || tae.OwnerTenantID != "tenant-a" || tae.Operation != "decrypt" {
		t.Fatalf("tenant error context = %+v", tae)
	}
	// 不能和“版本缺失”混为一谈。
	if errors.Is(err, ErrKeyVersionNotFound) {
		t.Fatal("cross-tenant error must not also match ErrKeyVersionNotFound")
	}
	t.Logf("basis=stored owner tenant_id (%s) != caller tenant_id (%s); record key_version=%d",
		tae.OwnerTenantID, tae.TenantID, 1)
}

func TestCrossTenantWriteOverwriteDenied(t *testing.T) {
	_, svc, _ := setupService(t, "passphrase")
	if _, err := svc.Encrypt("tenant-a", "doc", []byte("a"), WritePolicyMustCreate); err != nil {
		t.Fatalf("Encrypt a: %v", err)
	}

	// tenant-b 试图覆盖 tenant-a 的记录：拒绝，且原数据不被改动。
	_, err := svc.Encrypt("tenant-b", "doc", []byte("b was here"), WritePolicyOverwrite)
	if !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("err = %v, want ErrTenantMismatch", err)
	}
	var tae *TenantAccessError
	if !errors.As(err, &tae) || tae.Operation != "encrypt" || tae.OwnerTenantID != "tenant-a" {
		t.Fatalf("tenant error context = %+v", tae)
	}

	got, _, err := svc.Decrypt("tenant-a", "doc")
	if err != nil || !bytes.Equal(got, []byte("a")) {
		t.Fatalf("owner data altered after denied cross-tenant write: %q, %v", got, err)
	}
}

func TestDecryptReferencingMissingKeyVersionIsDistinguishable(t *testing.T) {
	dir, svc, _ := setupService(t, "passphrase")

	// 手工构造一条引用密钥环里不存在版本 42 的密文记录，直接落盘。
	// 组件绝不能静默用当前版本去尝试解密。
	rec := CiphertextRecord{
		FormatVersion: recordFormatVersion,
		TenantID:      "tenant-a",
		RecordID:      "ghost-version",
		KeyVersion:    42,
		WrappedDEK:    bytes.Repeat([]byte{1}, 32+12+16),
		Ciphertext:    bytes.Repeat([]byte{2}, 12+16),
		CreatedAt:     nowRFC3339(),
		UpdatedAt:     nowRFC3339(),
	}
	st, err := NewStorage(dir)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	raw, _ := json.MarshalIndent(&rec, "", "  ")
	if err := st.Save("ghost-version", raw); err != nil {
		t.Fatalf("seed ghost record: %v", err)
	}

	_, _, err = svc.Decrypt("tenant-a", "ghost-version")
	if !errors.Is(err, ErrKeyVersionNotFound) {
		t.Fatalf("err = %v, want ErrKeyVersionNotFound", err)
	}
	var kve *KeyVersionError
	if !errors.As(err, &kve) {
		t.Fatalf("err type = %T, want *KeyVersionError", err)
	}
	if kve.Version != 42 || kve.RecordID != "ghost-version" || kve.TenantID != "tenant-a" {
		t.Fatalf("key version error context = %+v", kve)
	}
	t.Logf("basis=record key_version=%d absent from keyring (current=%d); no fallback attempted",
		kve.Version, svc.CurrentKeyVersion())
}

func TestTamperedCiphertextRejected(t *testing.T) {
	dir, svc, _ := setupService(t, "passphrase")
	if _, err := svc.Encrypt("tenant-a", "doc", []byte("integrity matters"), WritePolicyMustCreate); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	raw := readRecordFile(t, dir, "doc")
	var rec CiphertextRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// 翻转密文一个字节，GCM 认证必须失败。
	rec.Ciphertext[len(rec.Ciphertext)-1] ^= 0xFF
	tampered, _ := json.Marshal(&rec)
	st, _ := NewStorage(dir)
	if err := st.Save("doc", tampered); err != nil {
		t.Fatalf("save tampered: %v", err)
	}

	if _, _, err := svc.Decrypt("tenant-a", "doc"); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("err = %v, want ErrInvalidCiphertext", err)
	}
}

func TestCiphertextFileContainsNoPlaintextOrDEK(t *testing.T) {
	dir, svc, _ := setupService(t, "passphrase")
	secret := []byte("TOP-SECRET-PAYLOAD-1234567890")
	if _, err := svc.Encrypt("tenant-a", "secret-doc", secret, WritePolicyMustCreate); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	raw := readRecordFile(t, dir, "secret-doc")
	if bytes.Contains(raw, secret) {
		t.Fatal("plaintext payload leaked into record file")
	}
	if bytes.Contains(raw, []byte("TOP-SECRET")) {
		t.Fatal("plaintext fragment leaked into record file")
	}
}

func TestWritePolicies(t *testing.T) {
	_, svc, _ := setupService(t, "passphrase")

	if _, err := svc.Encrypt("tenant-a", "doc", []byte("v1"), WritePolicyMustCreate); err != nil {
		t.Fatalf("first create: %v", err)
	}
	// MustCreate 再次写入：已存在。
	if _, err := svc.Encrypt("tenant-a", "doc", []byte("v2"), WritePolicyMustCreate); !errors.Is(err, ErrRecordAlreadyExists) {
		t.Fatalf("err = %v, want ErrRecordAlreadyExists", err)
	}
	// 属主 Overwrite：允许，且能解出新内容。
	if _, err := svc.Encrypt("tenant-a", "doc", []byte("v2"), WritePolicyOverwrite); err != nil {
		t.Fatalf("owner overwrite: %v", err)
	}
	got, _, err := svc.Decrypt("tenant-a", "doc")
	if err != nil || !bytes.Equal(got, []byte("v2")) {
		t.Fatalf("after overwrite: %q, %v", got, err)
	}
}

func TestRecordNotFound(t *testing.T) {
	_, svc, _ := setupService(t, "passphrase")
	if _, _, err := svc.Decrypt("tenant-a", "missing"); !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("err = %v, want ErrRecordNotFound", err)
	}
}

func TestInvalidRecordIDRejectsPathTraversal(t *testing.T) {
	_, svc, _ := setupService(t, "passphrase")
	for _, bad := range []string{"../escape", "a/b", ".hidden", "", strings.Repeat("a", 129)} {
		if _, err := svc.Encrypt("t", bad, []byte("x"), WritePolicyMustCreate); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("recordID %q: err = %v, want ErrInvalidArgument", bad, err)
		}
	}
}

func TestEmptyTenantRejected(t *testing.T) {
	_, svc, _ := setupService(t, "passphrase")
	if _, err := svc.Encrypt("", "doc", []byte("x"), WritePolicyMustCreate); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("encrypt empty tenant: err = %v, want ErrInvalidArgument", err)
	}
	if _, _, err := svc.Decrypt("", "doc"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("decrypt empty tenant: err = %v, want ErrInvalidArgument", err)
	}
}

func TestConcurrentCreateSameIDDifferentTenantsOnlyOwnerWins(t *testing.T) {
	_, svc, _ := setupService(t, "passphrase")

	// tenant-a 与 tenant-b 同时抢建同一记录 ID。
	// 只有一个能成功落盘，另一个必须收到明确拒绝（越权或已存在），
	// 绝不允许两个租户的密文互相覆盖，也不允许一个租户读到另一个租户的数据。
	var wg sync.WaitGroup
	errs := make([]error, 2)
	recs := make([]*CiphertextRecord, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		recs[0], errs[0] = svc.Encrypt("tenant-a", "race-id", []byte("a payload"), WritePolicyMustCreate)
	}()
	go func() {
		defer wg.Done()
		recs[1], errs[1] = svc.Encrypt("tenant-b", "race-id", []byte("b payload"), WritePolicyMustCreate)
	}()
	wg.Wait()

	var owner string
	var ownerPayload []byte
	switch {
	case errs[0] == nil && errs[1] != nil:
		owner = "tenant-a"
		ownerPayload = []byte("a payload")
	case errs[1] == nil && errs[0] != nil:
		owner = "tenant-b"
		ownerPayload = []byte("b payload")
	default:
		t.Fatalf("expected exactly one winner, got errs: a=%v b=%v", errs[0], errs[1])
	}

	// 输家的错误必须是可区分的越权或已存在，不能是笼统错误。
	loserErr := errs[0]
	if owner == "tenant-a" {
		loserErr = errs[1]
	}
	if !errors.Is(loserErr, ErrTenantMismatch) && !errors.Is(loserErr, ErrRecordAlreadyExists) {
		t.Fatalf("loser err = %v, want ErrTenantMismatch or ErrRecordAlreadyExists", loserErr)
	}

	// 落盘记录只能被属主解开，且明文是属主的明文。
	got, stored, err := svc.Decrypt(owner, "race-id")
	if err != nil {
		t.Fatalf("owner decrypt: %v", err)
	}
	if !bytes.Equal(got, ownerPayload) {
		t.Fatalf("owner payload mismatch: %q", got)
	}
	loser := "tenant-a"
	if owner == "tenant-a" {
		loser = "tenant-b"
	}
	if _, _, err := svc.Decrypt(loser, "race-id"); !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("loser decrypt err = %v, want ErrTenantMismatch", err)
	}
	t.Logf("basis=atomic create linearizes ownership; owner=%s, loser=%s denied, record key_version=%d",
		owner, loser, stored.KeyVersion)
}
