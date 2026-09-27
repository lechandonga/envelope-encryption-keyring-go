package envelope

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ---- 测试用日志：把密钥版本与判定依据输出到 t.Log（go test -v 可见） ----

type testLogHandler struct{ t *testing.T }

func (h testLogHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h testLogHandler) Handle(_ context.Context, r slog.Record) error {
	parts := []string{"[log]", r.Level.String(), r.Message}
	r.Attrs(func(a slog.Attr) bool {
		parts = append(parts, fmt.Sprintf("%s=%v", a.Key, a.Value.Any()))
		return true
	})
	h.t.Log(strings.Join(parts, " "))
	return nil
}

func (h testLogHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h testLogHandler) WithGroup(_ string) slog.Handler      { return h }

var testRootSecret = []byte("local-test-root-secret-32-bytes!") // 仅测试使用

func newTestService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	svc, err := New(context.Background(), Config{
		Dir:        dir,
		RootSecret: testRootSecret,
		Logger:     slog.New(testLogHandler{t: t}),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if svc.CurrentKeyVersion() != 1 {
		t.Fatalf("initial version = %d, want 1", svc.CurrentKeyVersion())
	}
	return svc
}

func mustRegister(t *testing.T, svc *Service, tenant string) {
	t.Helper()
	if err := svc.RegisterTenant(context.Background(), tenant); err != nil {
		t.Fatalf("RegisterTenant(%q): %v", tenant, err)
	}
}

// 1. 基本往返：加密后能解回原文，且密文携带正确的密钥版本。
func TestEncryptDecryptRoundTrip(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	mustRegister(t, svc, "acme")

	pt := []byte("hello envelope encryption")
	ct, err := svc.Encrypt(ctx, "acme", "doc-1", pt)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if ct.Version != 1 {
		t.Fatalf("ciphertext version = %d, want 1", ct.Version)
	}
	got, ct2, err := svc.Decrypt(ctx, "acme", "doc-1")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(pt) {
		t.Fatalf("plaintext mismatch: got %q", got)
	}
	if ct2.Version != 1 {
		t.Fatalf("decrypt reported version = %d, want 1", ct2.Version)
	}
}

//  2. 轮换后历史数据仍可解密：v1 老密文用保留的 v1 KEK 解开；
//     新密文用 v2；二者互不串用版本。
func TestRotateThenReadOldData(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	mustRegister(t, svc, "acme")

	oldPT := []byte("written before rotation")
	oldCT, err := svc.Encrypt(ctx, "acme", "old-doc", oldPT)
	if err != nil {
		t.Fatalf("Encrypt old: %v", err)
	}
	if oldCT.Version != 1 {
		t.Fatalf("old ciphertext version = %d, want 1", oldCT.Version)
	}

	nv, err := svc.RotateKey(ctx)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if nv != 2 {
		t.Fatalf("new version = %d, want 2", nv)
	}
	if svc.VersionCount() != 2 {
		t.Fatalf("retained version count = %d, want 2 (old versions must be kept)", svc.VersionCount())
	}

	newPT := []byte("written after rotation")
	newCT, err := svc.Encrypt(ctx, "acme", "new-doc", newPT)
	if err != nil {
		t.Fatalf("Encrypt new: %v", err)
	}
	if newCT.Version != 2 {
		t.Fatalf("new ciphertext version = %d, want 2 (new writes use current version)", newCT.Version)
	}

	// 老密文必须仍按 v1 解开，不能被静默重封或拒绝。
	gotOld, oldMeta, err := svc.Decrypt(ctx, "acme", "old-doc")
	if err != nil {
		t.Fatalf("Decrypt old after rotation: %v", err)
	}
	if string(gotOld) != string(oldPT) {
		t.Fatalf("old plaintext mismatch: %q", gotOld)
	}
	if oldMeta.Version != 1 {
		t.Fatalf("old doc should still reference version 1, got %d", oldMeta.Version)
	}
	t.Logf("ASSERT old-doc decrypted with retained key_version=1 while current_version=%d", svc.CurrentKeyVersion())

	gotNew, newMeta, err := svc.Decrypt(ctx, "acme", "new-doc")
	if err != nil {
		t.Fatalf("Decrypt new: %v", err)
	}
	if string(gotNew) != string(newPT) || newMeta.Version != 2 {
		t.Fatalf("new doc mismatch: pt=%q version=%d", gotNew, newMeta.Version)
	}

	// 多次轮换后再轮换一次，确认 v1/v2 都保留。
	if _, err := svc.RotateKey(ctx); err != nil {
		t.Fatalf("RotateKey #2: %v", err)
	}
	if svc.VersionCount() != 3 {
		t.Fatalf("version count = %d, want 3", svc.VersionCount())
	}
	gotOld2, meta2, err := svc.Decrypt(ctx, "acme", "old-doc")
	if err != nil {
		t.Fatalf("Decrypt old after 2 rotations: %v", err)
	}
	if string(gotOld2) != string(oldPT) || meta2.Version != 1 {
		t.Fatalf("old doc after 2 rotations mismatch: pt=%q version=%d", gotOld2, meta2.Version)
	}
}

// 3. 跨租户越权必须被拒绝，且原因可区分为：
//   - ErrRecordNotFound：记录按租户路径物理隔离，B 在自己的命名空间里看不到 A 的数据，
//     连“是否存在”都无法探知；
//   - ErrTenantDenied：即使数据文件被人为挪到 B 的目录下，文件内 owner 仍是 A，
//     解密时按 owner 字段明确拒绝（错误结构体携带调用方与属主）；
//   - ErrTenantUnknown：调用方租户根本未注册。
func TestCrossTenantDenied(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	fs := svc.store.(*FileStore)
	mustRegister(t, svc, "tenant-a")
	mustRegister(t, svc, "tenant-b")

	if _, err := svc.Encrypt(ctx, "tenant-a", "secret", []byte("A's secret")); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// 3.1 B 在自己租户空间读同名 ID：路径隔离下文件不在 B 的目录，
	//     返回 ErrRecordNotFound，B 无法据此判断 A 是否有该数据。
	_, _, err := svc.Decrypt(ctx, "tenant-b", "secret")
	if !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("want ErrRecordNotFound (per-tenant path isolation), got %v", err)
	}
	t.Log("ASSERT tenant-b cannot see tenant-a record in its own namespace: basis=per-tenant path isolation")

	// 3.2 模拟文件被误挪/误投放进 B 的目录：文件内 owner 仍是 tenant-a，
	//     此时必须给出明确的 ErrTenantDenied 而不是把 A 的数据解给 B。
	srcPath := svc.mustRecordPath(t, "tenant-a", "secret")
	dstPath := svc.mustRecordPath(t, "tenant-b", "secret")
	raw, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dstPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// 存储层自身就会对 owner 不匹配的文件返回 ErrTenantDenied（第一道防线）。
	if _, lerr := fs.LoadRecord("tenant-b", "secret"); !errors.Is(lerr, ErrTenantDenied) {
		t.Fatalf("Store.LoadRecord misplaced file: want ErrTenantDenied, got %v", lerr)
	}
	// 直接读原始字节确认被挪文件的 owner 头确实仍是 tenant-a（判定依据真实存在）。
	var misplaced recordFile
	if err := json.Unmarshal(raw, &misplaced); err != nil {
		t.Fatal(err)
	}
	if misplaced.Header.Tenant != "tenant-a" {
		t.Fatalf("misplaced record owner = %q, want tenant-a", misplaced.Header.Tenant)
	}
	// Service.Decrypt 同样必须拒绝（第二道防线，错误携带调用方与属主）。
	_, _, err = svc.Decrypt(ctx, "tenant-b", "secret")
	if !errors.Is(err, ErrTenantDenied) {
		t.Fatalf("want ErrTenantDenied for misplaced record, got %v", err)
	}
	var de *TenantDeniedError
	if !errors.As(err, &de) {
		t.Fatalf("want *TenantDeniedError, got %T", err)
	}
	if de.CallerTenant != "tenant-b" || de.OwnerTenant != "tenant-a" {
		t.Fatalf("denial detail wrong: %+v", de)
	}
	t.Logf("ASSERT misplaced record denied: caller=%s owner=%s basis=in-file owner header mismatch",
		de.CallerTenant, de.OwnerTenant)

	// 3.3 未注册租户 -> ErrTenantUnknown，必须能和上面两类原因区分开。
	_, _, err = svc.Decrypt(ctx, "tenant-c", "secret")
	if !errors.Is(err, ErrTenantUnknown) {
		t.Fatalf("want ErrTenantUnknown, got %v", err)
	}
	var ue *TenantUnknownError
	if !errors.As(err, &ue) || ue.Tenant != "tenant-c" {
		t.Fatalf("want *TenantUnknownError{tenant-c}, got %v", err)
	}
	t.Logf("ASSERT unregistered caller denied: tenant=%s basis=not in tenant registry", ue.Tenant)

	// 未注册租户写入同样被拒。
	if _, err := svc.Encrypt(ctx, "tenant-c", "x", []byte("y")); !errors.Is(err, ErrTenantUnknown) {
		t.Fatalf("encrypt by unknown tenant: want ErrTenantUnknown, got %v", err)
	}
}

// 4. 密文引用了不存在的密钥版本：必须显式报错，不能静默降级。
func TestMissingKeyVersionNotSilentlyFallback(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	dir := svc.store.(*FileStore).dir
	mustRegister(t, svc, "acme")

	if _, err := svc.Encrypt(ctx, "acme", "old", []byte("sealed at v1")); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := svc.RotateKey(ctx); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	// 人为从 keys.json 删掉 v1（把 v1 条目的版本号改成不存在的 99），
	// 再用相同 rootSecret 重启，模拟“引用了缺失的密钥版本”。
	keysPath := filepath.Join(dir, keysFileName)
	raw, err := os.ReadFile(keysPath)
	if err != nil {
		t.Fatalf("read keys.json: %v", err)
	}
	var kf keyringFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		t.Fatalf("parse keys.json: %v", err)
	}
	found := false
	for i := range kf.Versions {
		if kf.Versions[i].Version == 1 {
			kf.Versions[i].Version = 99
			found = true
		}
	}
	if !found {
		t.Fatalf("test setup: version 1 entry not found in keys.json")
	}
	out, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysPath, out, 0o600); err != nil {
		t.Fatalf("rewrite keys.json: %v", err)
	}

	svc2, err := New(ctx, Config{Dir: dir, RootSecret: testRootSecret,
		Logger: slog.New(testLogHandler{t: t})})
	if err != nil {
		t.Fatalf("reopen service: %v", err)
	}
	_, _, err = svc2.Decrypt(ctx, "acme", "old")
	if !errors.Is(err, ErrKeyVersionNotFound) {
		t.Fatalf("want ErrKeyVersionNotFound, got %v", err)
	}
	var kve *KeyVersionError
	if !errors.As(err, &kve) || kve.Version != 1 {
		t.Fatalf("want *KeyVersionError{Version:1}, got %v", err)
	}
	t.Logf("ASSERT missing key version rejected: referenced_version=%d basis=not present in keyring, no fallback", kve.Version)
}

// 5. 密文被篡改 -> ErrCiphertextCorrupt，后续解密不受影响。
func TestTamperedCiphertextRejected(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	mustRegister(t, svc, "acme")
	if _, err := svc.Encrypt(ctx, "acme", "doc", []byte("integrity protected")); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	path := svc.mustRecordPath(t, "acme", "doc")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rec recordFile
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	// 翻转密文正文中段一个字节：base64 编码后仍是合法 JSON 内容，
	// 但必然导致 AES-GCM 认证失败。
	mid := len(rec.Ciphertext) / 2
	rec.Ciphertext[mid] ^= 0xFF
	bad, err := json.MarshalIndent(&rec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Decrypt(ctx, "acme", "doc"); !errors.Is(err, ErrCiphertextCorrupt) {
		t.Fatalf("want ErrCiphertextCorrupt, got %v", err)
	} else {
		t.Logf("ASSERT tamper detected: key_version=1 basis=AEAD authentication failed")
	}
	// 其它记录不受影响，服务仍一致。
	if _, err := svc.Encrypt(ctx, "acme", "doc-2", []byte("still works")); err != nil {
		t.Fatalf("service inconsistent after tamper: %v", err)
	}
}

//  6. 并发加解密与轮换同时进行：所有成功写入的密文随时可解且原文一致，
//     密文版本始终是密钥环中真实存在的版本，不允许版本错乱。
func TestConcurrentEncryptDecryptAndRotate(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	mustRegister(t, svc, "acme")

	const (
		encrypters = 8
		perWorker  = 25
		rotations  = 5
	)

	var (
		wg       sync.WaitGroup // 加密 + 轮换协程
		readerWG sync.WaitGroup // 持续解密校验协程（单独计数，避免与 wg.Wait 死锁）
		created  sync.Map       // id -> plaintext
		existsN  int64
		existsMu sync.Mutex
	)

	// 轮换协程：与读写并发执行。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rotations; i++ {
			nv, err := svc.RotateKey(ctx)
			if err != nil {
				t.Errorf("RotateKey: %v", err)
				return
			}
			t.Logf("rotated to key_version=%d basis=all old versions retained", nv)
		}
	}()

	// 加密协程：ID 有重叠，用来并发验证“同一 ID 只有一个成功，其余得到 ErrRecordExists”。
	for w := 0; w < encrypters; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				id := fmt.Sprintf("doc-%d", (w*perWorker+i)%90)
				pt := []byte(fmt.Sprintf("payload for %s", id))
				ct, err := svc.Encrypt(ctx, "acme", id, pt)
				switch {
				case err == nil:
					if _, loaded := created.LoadOrStore(id, pt); loaded {
						t.Errorf("id %s encrypted twice without ErrRecordExists", id)
					}
					if ct.Version < 1 || ct.Version > svc.VersionCount() {
						t.Errorf("id %s got impossible version %d (count=%d)", id, ct.Version, svc.VersionCount())
					}
				case errors.Is(err, ErrRecordExists):
					existsMu.Lock()
					existsN++
					existsMu.Unlock()
				default:
					t.Errorf("Encrypt %s: unexpected error %v", id, err)
				}
			}
		}(w)
	}

	// 解密校验协程：不断读取已创建的记录，要求任何时刻都能解出正确原文。
	// 用独立 WaitGroup，否则它等 stop、主线程等它，会形成死锁。
	stop := make(chan struct{})
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			created.Range(func(k, v any) bool {
				id, want := k.(string), v.([]byte)
				got, ct, err := svc.Decrypt(ctx, "acme", id)
				if err != nil {
					t.Errorf("concurrent Decrypt %s: %v", id, err)
					return true
				}
				if string(got) != string(want) {
					t.Errorf("concurrent plaintext mismatch for %s", id)
				}
				if _, _, err := svc.kr.KEKForVersion(ct.Version); err != nil {
					t.Errorf("ciphertext for %s references nonexistent version %d", id, ct.Version)
				}
				return true
			})
		}
	}()

	wg.Wait() // 等加密和轮换结束
	close(stop)
	readerWG.Wait()

	if existsN == 0 {
		t.Fatalf("expected some concurrent duplicate writes to get ErrRecordExists")
	}
	if svc.VersionCount() != 1+rotations {
		t.Fatalf("version count = %d, want %d", svc.VersionCount(), 1+rotations)
	}

	// 最终一致性：每条已创建记录都能解回原文，且引用版本都在环内。
	n := 0
	created.Range(func(k, v any) bool {
		id, want := k.(string), v.([]byte)
		got, ct, err := svc.Decrypt(ctx, "acme", id)
		if err != nil {
			t.Fatalf("final Decrypt %s: %v", id, err)
		}
		if string(got) != string(want) {
			t.Fatalf("final plaintext mismatch for %s", id)
		}
		if ct.Version < 1 || ct.Version > svc.VersionCount() {
			t.Fatalf("final impossible version %d for %s", ct.Version, id)
		}
		t.Logf("ASSERT %s stable: key_version=%d current_version=%d basis=historical KEK retained",
			id, ct.Version, svc.CurrentKeyVersion())
		n++
		return true
	})
	t.Logf("concurrent test done: %d distinct records, %d duplicate-write rejections, %d total versions",
		n, existsN, svc.VersionCount())
}

// 7. 落盘内容不得包含明文业务数据、根密钥或任何明文密钥材料。
func TestNoPlaintextKeyMaterialOnDisk(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	mustRegister(t, svc, "acme")
	secretPT := []byte("TOP_SECRET_PAYLOAD_MARKER_9f3e")
	if _, err := svc.Encrypt(ctx, "acme", "s1", secretPT); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RotateKey(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Encrypt(ctx, "acme", "s2", secretPT); err != nil {
		t.Fatal(err)
	}
	dir := svc.store.(*FileStore).dir
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if strings.Contains(string(raw), string(secretPT)) {
			t.Errorf("plaintext payload found on disk in %s", path)
		}
		if strings.Contains(string(raw), string(testRootSecret)) {
			t.Errorf("root secret found on disk in %s", path)
		}
		t.Logf("scanned %s (%d bytes): no plaintext payload / root secret", filepath.Base(path), len(raw))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// 8. 重启后状态一致：keys.json 恢复全部版本，老数据可解。
func TestRestartPersistence(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Dir: dir, RootSecret: testRootSecret, Logger: slog.New(testLogHandler{t: t})}
	svc, err := New(ctxBG(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	mustRegister(t, svc, "acme")
	if _, err := svc.Encrypt(ctxBG(), "acme", "k1", []byte("persist me")); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RotateKey(ctxBG()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Encrypt(ctxBG(), "acme", "k2", []byte("new version")); err != nil {
		t.Fatal(err)
	}

	svc2, err := New(ctxBG(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if svc2.VersionCount() != 2 || svc2.CurrentKeyVersion() != 2 {
		t.Fatalf("restored state wrong: count=%d current=%d", svc2.VersionCount(), svc2.CurrentKeyVersion())
	}
	got, ct, err := svc2.Decrypt(ctxBG(), "acme", "k1")
	if err != nil || string(got) != "persist me" || ct.Version != 1 {
		t.Fatalf("old record after restart: pt=%q version=%d err=%v", got, ctVersion(ct), err)
	}
}

// ---- 小工具 ----

func (s *Service) mustRecordPath(t *testing.T, tenant, id string) string {
	t.Helper()
	fs := s.store.(*FileStore)
	p, err := fs.recordPath(tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func ctxBG() context.Context { return context.Background() }

func ctVersion(ct *EnvelopeCiphertext) int {
	if ct == nil {
		return -1
	}
	return ct.Version
}
