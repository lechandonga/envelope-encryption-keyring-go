package envelope

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// writeFileAtomic 以“临时文件 + fsync + rename”方式原子写入 path：
//   - 先写入同目录下的随机临时文件并 Sync，保证字节真正落盘；
//   - 再通过 rename 原子替换目标文件，任何时刻目标文件要么是完整旧内容、
//     要么是完整新内容，不会出现写入中途的半成品；
//   - 文件权限由 perm 指定（密钥/密文均使用 0600）。
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	// 无论成功与否都尝试清理临时文件（成功路径下 rename 后文件已不存在，Remove 失败可忽略）。
	defer os.Remove(tmpName)

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

// nowUTC 返回当前 UTC 时间，集中一处便于测试替换。
var nowUTC = func() time.Time { return time.Now().UTC() }
