package envelope

// 以下符号仅在测试构建中可见，用于白盒断言（例如验证落盘内容不含明文密钥）。

// plainMasterKey 返回指定版本主密钥的明文材料副本（仅测试用）。
func (k *Keyring) plainMasterKey(version uint32) ([]byte, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	e, ok := k.versions[version]
	if !ok {
		return nil, false
	}
	out := make([]byte, len(e.plain))
	copy(out, e.plain)
	return out, true
}

// keyringFilePath 返回密钥环文件路径（仅测试用）。
func (k *Keyring) keyringFilePath() string { return k.filePath }
