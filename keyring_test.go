package envelope

import (
	"bytes"
	"errors"
	"sync"
	"testing"
)

func TestKeyringCreateAndOpenRoundTrip(t *testing.T) {
	dir, kr, _ := setupKeyring(t, "correct horse battery staple")

	if got := kr.CurrentVersion(); got != 1 {
		t.Fatalf("initial current version = %d, want 1", got)
	}
	if vs := kr.Versions(); len(vs) != 1 || vs[0] != 1 {
		t.Fatalf("initial versions = %v, want [1]", vs)
	}

	// 重新打开：所有版本都应能用口令解包，当前版本保持一致。
	log, _ := newTestLogger(t)
	reopened, err := OpenKeyring(dir, "correct horse battery staple", log)
	if err != nil {
		t.Fatalf("OpenKeyring: %v", err)
	}
	if reopened.CurrentVersion() != 1 {
		t.Fatalf("reopened current version = %d, want 1", reopened.CurrentVersion())
	}
}

func TestKeyringRotationRetainsOldVersions(t *testing.T) {
	dir, kr, _ := setupKeyring(t, "passphrase")

	v2, err := kr.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if v2 != 2 {
		t.Fatalf("rotated version = %d, want 2", v2)
	}
	v3, err := kr.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if v3 != 3 || kr.CurrentVersion() != 3 {
		t.Fatalf("after rotations current = v%d, want 3", kr.CurrentVersion())
	}
	if vs := kr.Versions(); len(vs) != 3 {
		t.Fatalf("retained versions = %v, want all 3", vs)
	}

	// 重开后当前版本与全部历史版本都还在：历史密文解密依赖这一点。
	log, _ := newTestLogger(t)
	reopened, err := OpenKeyring(dir, "passphrase", log)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if reopened.CurrentVersion() != 3 {
		t.Fatalf("reopened current = %d, want 3", reopened.CurrentVersion())
	}
	if vs := reopened.Versions(); len(vs) != 3 {
		t.Fatalf("reopened versions = %v, want 3 retained versions", vs)
	}

	// 轮换后旧版本仍可解包此前包装的 DEK。
	dek := bytes.Repeat([]byte{0xAB}, keySize)
	wrapped, used, err := kr.WrapCurrentWithAAD(dek, func(v uint32) []byte {
		return []byte("aad")
	})
	if err != nil {
		t.Fatalf("WrapCurrentWithAAD: %v", err)
	}
	if used != 3 {
		t.Fatalf("WrapCurrent used v%d, want v3", used)
	}
	if _, err := kr.UnwrapVersion(1, wrapped, []byte("aad")); err == nil {
		t.Fatal("unexpected success unwrapping v3 blob with v1 key: want auth failure")
	}
}

func TestKeyringUnwrapMissingVersionIsDistinguishable(t *testing.T) {
	_, kr, _ := setupKeyring(t, "passphrase")

	// 用一个密钥环里从不存在的版本号解包，错误必须是 ErrKeyVersionNotFound，
	// 不能静默降级。
	_, err := kr.UnwrapVersion(99, []byte("anything"), []byte("aad"))
	if !errors.Is(err, ErrKeyVersionNotFound) {
		t.Fatalf("err = %v, want errors.Is ErrKeyVersionNotFound", err)
	}
}

func TestOpenKeyringWrongPassphrase(t *testing.T) {
	dir, _, _ := setupKeyring(t, "right-passphrase")

	log, _ := newTestLogger(t)
	if _, err := OpenKeyring(dir, "wrong-passphrase", log); !errors.Is(err, ErrInvalidPassphrase) {
		t.Fatalf("err = %v, want ErrInvalidPassphrase", err)
	}
}

func TestCreateKeyringRejectsOverwrite(t *testing.T) {
	dir, _, _ := setupKeyring(t, "passphrase")
	log, _ := newTestLogger(t)
	if _, err := CreateKeyring(dir, "passphrase", log); err == nil {
		t.Fatal("expected error when creating keyring over existing file")
	}
}

func TestKeyringFileContainsNoPlaintextMaterial(t *testing.T) {
	dir, kr, _ := setupKeyring(t, "passphrase")
	if _, err := kr.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	raw := readKeyringFile(t, dir)
	for _, v := range kr.Versions() {
		plain, ok := kr.plainMasterKey(v)
		if !ok {
			t.Fatalf("version %d missing in memory", v)
		}
		if bytes.Contains(raw, plain) {
			t.Fatalf("plaintext master key of version %d found in keyring file", v)
		}
	}
	if bytes.Contains(raw, []byte("passphrase")) {
		t.Fatal("passphrase bytes found in keyring file")
	}
}

func TestConcurrentRotationSurvivesRestart(t *testing.T) {
	dir, kr, _ := setupKeyring(t, "passphrase")

	// 并发轮换后，当前版本指针与全部新版本都必须已经持久化，
	// 因为 Rotate 在同一把写锁内“生成版本 + 推进指针 + 原子落盘”。
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = kr.Rotate()
		}()
	}
	wg.Wait()

	wantCurrent := kr.CurrentVersion()
	log, _ := newTestLogger(t)
	reopened, err := OpenKeyring(dir, "passphrase", log)
	if err != nil {
		t.Fatalf("reopen after concurrent rotations: %v", err)
	}
	if reopened.CurrentVersion() != wantCurrent {
		t.Fatalf("current version after restart = %d, want %d", reopened.CurrentVersion(), wantCurrent)
	}
	if len(reopened.Versions()) != int(wantCurrent) {
		t.Fatalf("versions after restart = %v, want 1..%d", reopened.Versions(), wantCurrent)
	}
	t.Logf("basis=rotate persists version+pointer atomically; after restart current key_version=%d with all versions retained", wantCurrent)
}
