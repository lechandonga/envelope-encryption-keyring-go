package envelope

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestConcurrentEncryptDecryptAndRotate 是核心并发场景：
// 多个 goroutine 持续加密新记录、解密既有记录，同时另一些 goroutine 持续轮换主密钥。
// 不变量：
//  1. 每一次成功解密的结果必须等于该记录写入时的明文（无损坏、无版本错乱）；
//  2. 每条密文记录的 key_version 必须指向当时密钥环真实存在的版本；
//  3. 所有错误只能是预期类型，不允许 panic。
func TestConcurrentEncryptDecryptAndRotate(t *testing.T) {
	// 大流量并发测试使用静默 logger 避免刷屏；版本与判定依据在结尾 t.Logf 输出。
	dir := t.TempDir()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	kr, err := CreateKeyring(dir, "passphrase", quiet)
	if err != nil {
		t.Fatalf("CreateKeyring: %v", err)
	}
	st, err := NewStorage(dir)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	svc, err := NewService(kr, st, quiet)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	const (
		encrypters = 8
		decrypters = 8
		rotators   = 2
		iterations = 40
	)

	// recordsMu 保护 records 追加；元素内容一旦写入不再修改。
	var recordsMu sync.Mutex
	type stored struct {
		id        string
		tenant    string
		plaintext []byte
		version   uint32
	}
	var records []stored

	var wg sync.WaitGroup
	errCh := make(chan error, encrypters*iterations+decrypters*iterations)

	// 轮换者：不断生成新版本。
	maxVersionSeen := uint32(1)
	for r := 0; r < rotators; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations/2; i++ {
				v, err := svc.RotateKey()
				if err != nil {
					errCh <- fmt.Errorf("rotate: %w", err)
					return
				}
				recordsMu.Lock()
				if v > maxVersionSeen {
					maxVersionSeen = v
				}
				recordsMu.Unlock()
			}
		}()
	}

	// 加密者：每个 goroutine 用自己的租户写自己的一组记录。
	for e := 0; e < encrypters; e++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			tenant := fmt.Sprintf("tenant-%d", g)
			for i := 0; i < iterations; i++ {
				id := fmt.Sprintf("g%d-doc-%d", g, i)
				pt := []byte(fmt.Sprintf("payload from goroutine %d iteration %d", g, i))
				rec, err := svc.Encrypt(tenant, id, pt, WritePolicyMustCreate)
				if err != nil {
					errCh <- fmt.Errorf("encrypt %s: %w", id, err)
					return
				}
				recordsMu.Lock()
				records = append(records, stored{id: id, tenant: tenant, plaintext: pt, version: rec.KeyVersion})
				recordsMu.Unlock()
			}
		}(e)
	}

	// 解密者：反复随机挑“截至目前已写完”的记录解密，校验明文与版本一致。
	for d := 0; d < decrypters; d++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				recordsMu.Lock()
				n := len(records)
				recordsMu.Unlock()
				if n == 0 {
					continue
				}
				idx := (g*7 + i*13) % n
				recordsMu.Lock()
				target := records[idx]
				recordsMu.Unlock()

				pt, rec, err := svc.Decrypt(target.tenant, target.id)
				if err != nil {
					// 记录可能正被原子替换窗口读取（本测试记录只写一次，不会）；
					// 任何错误都视为异常。
					errCh <- fmt.Errorf("decrypt %s: %w", target.id, err)
					return
				}
				if !bytes.Equal(pt, target.plaintext) {
					errCh <- fmt.Errorf("plaintext corruption on %s", target.id)
					return
				}
				if rec.KeyVersion != target.version {
					errCh <- fmt.Errorf("version drift on %s: file=%d expected=%d",
						target.id, rec.KeyVersion, target.version)
					return
				}
			}
		}(d)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	// 轮换完成后：所有历史记录（覆盖多个旧版本）都必须仍然可解。
	seenVersions := map[uint32]bool{}
	for _, rec := range records {
		got, loaded, err := svc.Decrypt(rec.tenant, rec.id)
		if err != nil {
			t.Fatalf("post-rotation decrypt %s failed: %v", rec.id, err)
		}
		if !bytes.Equal(got, rec.plaintext) {
			t.Fatalf("post-rotation plaintext mismatch on %s", rec.id)
		}
		seenVersions[loaded.KeyVersion] = true
	}
	if len(seenVersions) < 2 {
		t.Fatalf("expected ciphertexts spread across >=2 key versions under rotation, got %v", seenVersions)
	}
	t.Logf("basis=after concurrent rotation, %d records across key versions %v all decrypt; current=%d",
		len(records), mapKeys(seenVersions), kr.CurrentVersion())
}

// TestConcurrentWritesSameRecordNeverCorrupt 同一记录被属主并发覆盖写：
// 任何时刻读到的都必须是“某一次完整写入”，绝不能解析失败或解出半截明文。
func TestConcurrentWritesSameRecordNeverCorrupt(t *testing.T) {
	dir, kr, _ := setupKeyring(t, "passphrase")
	st, err := NewStorage(dir)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	// 热循环会产生数十万次读写，这里使用静默 logger 防止刷屏；
	// 测试结束后的 t.Logf 仍会打印所用密钥版本与判定依据。
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, err := NewService(kr, st, quiet)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	const writers = 16
	const iterations = 50

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				// 每个 (g,i) 的明文唯一，解密成功时必须精确等于它之一。
				pt := []byte(fmt.Sprintf("writer-%d-iteration-%06d-padding-padding-padding", g, i))
				_, err := svc.Encrypt("tenant-a", "hot-doc", pt, WritePolicyOverwrite)
				if err != nil {
					t.Errorf("concurrent overwrite: %v", err)
					return
				}
			}
		}(w)
	}

	// 并发读者：只要解密成功，明文就必须能匹配到某个已知写入值。
	valid := make(map[string]bool, writers*iterations)
	for w := 0; w < writers; w++ {
		for i := 0; i < iterations; i++ {
			valid[fmt.Sprintf("writer-%d-iteration-%06d-padding-padding-padding", w, i)] = true
		}
	}
	stop := make(chan struct{})
	var readerWG sync.WaitGroup
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			pt, _, err := svc.Decrypt("tenant-a", "hot-doc")
			if err != nil {
				if errors.Is(err, ErrRecordNotFound) {
					continue
				}
				// 原子写 + 记录结构自洽：除 NotFound 外不应出现损坏类错误。
				t.Errorf("reader saw corrupt record: %v", err)
				return
			}
			if !valid[string(pt)] {
				t.Errorf("reader saw torn/unknown plaintext: %q", pt)
				return
			}
		}
	}()

	wg.Wait()
	close(stop)
	readerWG.Wait()

	// 终态校验并输出判定依据。
	pt, rec, err := svc.Decrypt("tenant-a", "hot-doc")
	if err != nil {
		t.Fatalf("final decrypt: %v", err)
	}
	if !valid[string(pt)] {
		t.Fatalf("final plaintext is not any complete write: %q", pt)
	}
	t.Logf("basis=every concurrent read returned one complete write (atomic temp+rename, per-record lock); final record key_version=%d current=%d",
		rec.KeyVersion, kr.CurrentVersion())
}

// TestAtomicWriteLeavesNoHalfWrittenFile 模拟写入中途失败：
// 残留的 .tmp 文件不影响正式记录，正式记录要么不存在、要么完整可解。
func TestAtomicWriteLeavesNoHalfWrittenFile(t *testing.T) {
	dir, svc, _ := setupService(t, "passphrase")

	// 先写入一条完整记录。
	if _, err := svc.Encrypt("tenant-a", "doc", []byte("good-content"), WritePolicyMustCreate); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// 在 records 目录伪造一个“写到一半”的临时文件，模拟崩溃残留。
	tmp := filepath.Join(dir, "records", "doc.tmp-crash123")
	if err := os.WriteFile(tmp, []byte("{\"format_version\":"), 0o600); err != nil {
		t.Fatalf("seed tmp: %v", err)
	}

	// 正式记录仍然完整可解。
	got, _, err := svc.Decrypt("tenant-a", "doc")
	if err != nil || !bytes.Equal(got, []byte("good-content")) {
		t.Fatalf("decrypt after simulated crash residue: %q, %v", got, err)
	}
	// 覆盖写也必须成功（rename 替换的是正式文件，与残留 tmp 无关）。
	if _, err := svc.Encrypt("tenant-a", "doc", []byte("better-content"), WritePolicyOverwrite); err != nil {
		t.Fatalf("overwrite after crash residue: %v", err)
	}
	got, _, err = svc.Decrypt("tenant-a", "doc")
	if err != nil || !bytes.Equal(got, []byte("better-content")) {
		t.Fatalf("decrypt after overwrite: %q, %v", got, err)
	}
}

func mapKeys(m map[uint32]bool) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
