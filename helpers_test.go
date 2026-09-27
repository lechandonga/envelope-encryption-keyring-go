package envelope

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// newTestLogger 返回一个 slog.Logger：
//   - JSON 句柄保证字段化输出（key_version / basis 等判定依据）；
//   - 输出同时转发到 testing 日志（go test -v 可见）和内存缓冲（必要时断言）。
//
// 测试要求“单测日志里打印用到的密钥版本和判定依据”，所有业务日志点本身
// 都携带 key_version/key_version 与 basis 字段，这里只负责把它们展示出来。
func newTestLogger(t *testing.T) (*slog.Logger, *threadSafeBuffer) {
	t.Helper()
	buf := &threadSafeBuffer{}
	w := io.MultiWriter(&testWriter{t: t}, buf)
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(h), buf
}

type testWriter struct{ t *testing.T }

func (w *testWriter) Write(p []byte) (int, error) {
	// 逐行输出，避免 testing 自动加时间戳前缀打乱 JSON。
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		w.t.Logf("slog: %s", line)
	}
	return len(p), nil
}

type threadSafeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *threadSafeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *threadSafeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// setupKeyring 在临时目录中创建一套全新密钥环（含 v1）并返回目录。
func setupKeyring(t *testing.T, passphrase string) (string, *Keyring, *slog.Logger) {
	t.Helper()
	dir := t.TempDir()
	log, _ := newTestLogger(t)
	kr, err := CreateKeyring(dir, passphrase, log)
	if err != nil {
		t.Fatalf("CreateKeyring: %v", err)
	}
	return dir, kr, log
}

func setupService(t *testing.T, passphrase string) (string, *Service, *Keyring) {
	t.Helper()
	dir, kr, log := setupKeyring(t, passphrase)
	st, err := NewStorage(dir)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	svc, err := NewService(kr, st, log)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return dir, svc, kr
}

// readKeyringFile 读取磁盘上的密钥环文件原文（用于断言不含明文密钥材料）。
func readKeyringFile(t *testing.T, dir string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "keyring.json"))
	if err != nil {
		t.Fatalf("read keyring file: %v", err)
	}
	return raw
}

// readRecordFile 读取磁盘上某条密文记录原文（用于断言不含明文）。
func readRecordFile(t *testing.T, dir, recordID string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "records", recordID))
	if err != nil {
		t.Fatalf("read record file: %v", err)
	}
	return raw
}
