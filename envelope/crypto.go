package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// kekLen 是 KEK / DEK 的长度：32 字节 => AES-256。
const kekLen = 32

// minRootSecretLen 限制根密钥材料的最小长度，避免弱密钥。
const minRootSecretLen = 16

// keyVersion 是一个主密钥版本。
//
// 主密钥本身（rootSecret）只存在于进程内存中，绝不写入落盘内容；
// 磁盘上只保存派生 KEK 所需的非秘密盐值 salt。KEK 由
// HKDF(rootSecret, salt, info="envelope-kek-v"+version) 派生。
type keyVersion struct {
	version     int    // 版本号，从 1 开始单调递增
	salt        []byte // 每版本独立、随机、非秘密的派生盐
	createdUnix int64  // 创建时间（秒）
}

// EnvelopeCiphertext 是信封加密后的密文结构。
// JSON 落盘/读取；里面绝不包含任何明文密钥材料，只有被 KEK 包裹后的 DEK。
type EnvelopeCiphertext struct {
	// Version 加密时使用的主密钥版本；解密时按它定位历史 KEK。
	Version int `json:"v"`
	// WrappedDEK 被该版本 KEK（AES-GCM）加密后的数据密钥。
	WrappedDEK []byte `json:"wk"`
	// Nonce 包裹 DEK 所用 GCM 的 nonce。
	Nonce []byte `json:"wn"`
	// Ciphertext 用 DEK（AES-GCM）加密业务明文得到的密文（含 GCM tag）。
	Ciphertext []byte `json:"ct"`
	// DataNonce 加密业务明文所用 GCM 的 nonce。
	DataNonce []byte `json:"dn"`
}

// cryptoEngine 封装无状态的密码学原语：KEK 派生、DEK 包裹/解包、数据加解密。
// 它不持有可变状态，因此可以在不持锁的情况下被并发调用。
type cryptoEngine struct {
	rootSecret []byte
}

func newCryptoEngine(rootSecret []byte) (*cryptoEngine, error) {
	if len(rootSecret) < minRootSecretLen {
		return nil, &InvalidArgumentError{
			Argument: "rootSecret",
			Reason:   fmt.Sprintf("must be at least %d bytes, got %d", minRootSecretLen, len(rootSecret)),
		}
	}
	// 拷贝一份，避免调用方之后修改底层数组影响密钥。
	sec := make([]byte, len(rootSecret))
	copy(sec, rootSecret)
	return &cryptoEngine{rootSecret: sec}, nil
}

// versionAAD 把版本号编码为包裹 DEK 时的附加认证数据，
// 确保“被包裹的 DEK 只能在它被加密时的那个主密钥版本下解包”，
// 防止把密文记录里的版本号篡改成别的版本来诱导解密。
func versionAAD(version int) []byte {
	return binary.BigEndian.AppendUint64(nil, uint64(version))
}

// newGCM 以 key 构造 AES-GCM。
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// deriveKEK 为指定版本派生 32 字节 AES-256 密钥。
func (c *cryptoEngine) deriveKEK(kv *keyVersion) ([]byte, error) {
	info := fmt.Appendf(nil, "envelope-kek-v%d", kv.version)
	r := hkdf.New(sha256.New, c.rootSecret, kv.salt, info)
	kek := make([]byte, kekLen)
	if _, err := io.ReadFull(r, kek); err != nil {
		return nil, fmt.Errorf("envelope: derive KEK for version %d: %w", kv.version, err)
	}
	return kek, nil
}

// randomNonce 生成指定 AEAD 的随机 nonce。
func randomNonce(aead cipher.AEAD) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// seal 用 envelope 的方式加密 plaintext，返回完整信封密文。
// kek 必须是由 kv 派生的该版本密钥（由 keyring 统一提供，便于复用与审计）。
func (c *cryptoEngine) seal(kv *keyVersion, kek, plaintext []byte) (*EnvelopeCiphertext, error) {
	// 1) 为这条消息随机生成一把一次性 DEK。
	dek := make([]byte, kekLen)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, err
	}

	dataAEAD, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	dataNonce, err := randomNonce(dataAEAD)
	if err != nil {
		return nil, err
	}
	ct := dataAEAD.Seal(nil, dataNonce, plaintext, nil)

	// 2) 用该版本 KEK 包裹 DEK；AAD 绑定版本号。
	kekAEAD, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	wrapNonce, err := randomNonce(kekAEAD)
	if err != nil {
		return nil, err
	}
	wrapped := kekAEAD.Seal(nil, wrapNonce, dek, versionAAD(kv.version))

	// 用完立刻清掉内存里的明文 DEK（best-effort）。
	for i := range dek {
		dek[i] = 0
	}

	return &EnvelopeCiphertext{
		Version:    kv.version,
		WrappedDEK: wrapped,
		Nonce:      wrapNonce,
		Ciphertext: ct,
		DataNonce:  dataNonce,
	}, nil
}

// validate 做结构性校验；任何字段缺失都按密文损坏处理，绝不静默降级。
func (ct *EnvelopeCiphertext) validate() error {
	switch {
	case ct == nil:
		return &CorruptCiphertextError{Reason: "ciphertext payload is empty"}
	case ct.Version <= 0:
		return &CorruptCiphertextError{Reason: "key version in ciphertext is not positive"}
	case len(ct.WrappedDEK) == 0:
		return &CorruptCiphertextError{Reason: "wrapped data key is empty"}
	case len(ct.Nonce) == 0:
		return &CorruptCiphertextError{Reason: "wrap nonce is empty"}
	case len(ct.Ciphertext) == 0:
		return &CorruptCiphertextError{Reason: "ciphertext body is empty"}
	case len(ct.DataNonce) == 0:
		return &CorruptCiphertextError{Reason: "data nonce is empty"}
	}
	return nil
}

// open 用信封记录的版本对应的 KEK 解包 DEK，再解密业务数据。
// kek 由调用方（keyring）依据 ciphertext.Version 提供，保证按历史版本解密。
// 任何认证失败/篡改都映射为 ErrCiphertextCorrupt，不泄露内部细节。
func (c *cryptoEngine) open(kek []byte, ct *EnvelopeCiphertext) (plaintext []byte, err error) {
	if err := ct.validate(); err != nil {
		return nil, err
	}
	defer func() {
		if r := recover(); r != nil {
			err = &CorruptCiphertextError{Reason: fmt.Sprintf("panic during decrypt: %v", r)}
			plaintext = nil
		}
	}()

	kekAEAD, err := newGCM(kek)
	if err != nil {
		return nil, &CorruptCiphertextError{Reason: "reconstructed key is invalid"}
	}
	dek, err := kekAEAD.Open(nil, ct.Nonce, ct.WrappedDEK, versionAAD(ct.Version))
	if err != nil {
		return nil, &CorruptCiphertextError{Reason: "data key unwrap failed (wrong key version or tampered payload)"}
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()

	dataAEAD, err := newGCM(dek)
	if err != nil {
		return nil, &CorruptCiphertextError{Reason: "reconstructed data key is invalid"}
	}
	pt, err := dataAEAD.Open(nil, ct.DataNonce, ct.Ciphertext, nil)
	if err != nil {
		return nil, &CorruptCiphertextError{Reason: "payload authentication failed (tampered ciphertext)"}
	}
	return pt, nil
}
