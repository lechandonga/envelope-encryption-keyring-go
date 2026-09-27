package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

// 密钥体系（信封加密）：
//
//	passphrase --(PBKDF2-HMAC-SHA256 + salt)--> KEK(主密钥加密密钥，不落盘)
//	master key material(32B, AES-256) --KEK/AES-GCM 包装--> 落盘的密态主密钥版本
//	每条消息随机 DEK(32B) --当前版本主密钥/AES-GCM 包装--> wrappedDEK（随密文记录存放）
//	plaintext --DEK/AES-GCM(AAD 绑定租户/记录/版本)--> ciphertext
//
// 磁盘上永远不出现任何明文密钥材料；日志中也只允许出现版本号与 ID。

const (
	// keySize 是主密钥与数据密钥（DEK）的长度，均为 AES-256。
	keySize = 32
	// defaultKDFIterations 是 KEK 派生使用的 PBKDF2 迭代次数。
	defaultKDFIterations = 200_000
	// kdfSaltSize KEK 派生盐长度。
	kdfSaltSize = 16
)

// kdfParams 描述如何从口令派生出本地 KEK。
type kdfParams struct {
	Algorithm  string `json:"algorithm"` // 固定 "PBKDF2-HMAC-SHA256"
	Iterations int    `json:"iterations"`
	Salt       []byte `json:"salt"` // 随机盐，随密钥环文件落盘（盐不需要保密）
}

// deriveKEK 依据 kdfParams 从口令派生 32 字节 KEK。
func deriveKEK(passphrase string, p kdfParams) []byte {
	return pbkdf2HMACSHA256([]byte(passphrase), p.Salt, p.Iterations, keySize)
}

// newKDFParams 生成带随机盐的 KEK 派生参数。
func newKDFParams() (kdfParams, error) {
	salt := make([]byte, kdfSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return kdfParams{}, err
	}
	return kdfParams{
		Algorithm:  "PBKDF2-HMAC-SHA256",
		Iterations: defaultKDFIterations,
		Salt:       salt,
	}, nil
}

// randomKey 用密码学随机源生成一把 32 字节密钥。
func randomKey() ([]byte, error) {
	k := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, err
	}
	return k, nil
}

// gcmSeal 用 key 对 plaintext 做 AES-256-GCM 封包，输出 nonce||ciphertext。
// 每次调用生成随机 nonce；aad 参与认证但不加密。
func gcmSeal(key, plaintext, aad []byte) ([]byte, error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := g.Seal(nil, nonce, plaintext, aad)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// gcmOpen 是 gcmSeal 的逆操作，输入必须为 nonce||ciphertext。
// 认证失败返回错误（调用方统一映射为 ErrInvalidCiphertext）。
func gcmOpen(key, blob, aad []byte) ([]byte, error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ns := g.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := blob[:ns], blob[ns:]
	return g.Open(nil, nonce, ct, aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != keySize {
		return nil, errors.New("invalid key length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// pbkdf2HMACSHA256 是 RFC 2898 PBKDF2 的标准库实现（HMAC-SHA256），
// 避免为单一原语引入外部依赖。
func pbkdf2HMACSHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		mac := prf
		mac.Reset()
		mac.Write(salt)
		binary.BigEndian.PutUint32(buf[:], uint32(block))
		mac.Write(buf[:])
		T := mac.Sum(nil)
		copy(U, T)
		for n := 2; n <= iter; n++ {
			mac2 := prf
			mac2.Reset()
			mac2.Write(U)
			U = mac2.Sum(U[:0])
			for x := range T {
				T[x] ^= U[x]
			}
		}
		dk = append(dk, T...)
	}
	return dk[:keyLen]
}
