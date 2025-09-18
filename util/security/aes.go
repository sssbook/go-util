package security

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// #####加密全部用AES，不允许用DES，传输用CTR模式 存储用ECB模式(因mysql默认是ECB)
// CFB模式的AES加密字符串（统一函数）
func AESCFBEncryptString(plaintext, key string) (string, error) {
	normalizedKey := normalizeKey([]byte(key))

	block, err := aes.NewCipher(normalizedKey)
	if err != nil {
		return "", fmt.Errorf("创建AES cipher失败: %v", err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("生成随机IV失败: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

	return hex.EncodeToString(ciphertext), nil
}

// CFB模式的AES解密字符串（统一函数）
func AESCFBDecryptString(ciphertext, key string) (string, error) {
	normalizedKey := normalizeKey([]byte(key))

	block, err := aes.NewCipher(normalizedKey)
	if err != nil {
		return "", fmt.Errorf("创建AES cipher失败: %v", err)
	}

	encryptedData, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("解码十六进制字符串失败: %v", err)
	}

	if len(encryptedData) < aes.BlockSize {
		return "", fmt.Errorf("密文长度太短")
	}

	iv := encryptedData[:aes.BlockSize]
	encryptedData = encryptedData[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(encryptedData, encryptedData)

	return string(encryptedData), nil
}

func normalizeKey(key []byte) []byte {
	if len(key) < 16 {
		paddedKey := make([]byte, 16)
		copy(paddedKey, key)
		return paddedKey
	}
	if len(key) > 16 {
		return key[:16]
	}
	return key
}

// ECB模式的AES加密
func AesEcbEncryptString(src, encryptKey string) string {
	key := normalizeKey([]byte(encryptKey))

	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}

	plaintext := []byte(src)

	// ECB模式需要将明文填充到块大小的倍数
	blockSize := block.BlockSize()
	plaintext = pkcs7Padding(plaintext, blockSize)

	ciphertext := make([]byte, len(plaintext))

	// ECB模式：每个块独立加密
	for i := 0; i < len(plaintext); i += blockSize {
		block.Encrypt(ciphertext[i:i+blockSize], plaintext[i:i+blockSize])
	}

	return hex.EncodeToString(ciphertext)
}

// ECB模式的AES解密
func AesEcbDecryptString(src, encryptKey string) string {
	key := normalizeKey([]byte(encryptKey))

	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}

	ciphertext, err := hex.DecodeString(src)
	if err != nil {
		return ""
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return ""
	}

	plaintext := make([]byte, len(ciphertext))

	// ECB模式：每个块独立解密
	for i := 0; i < len(ciphertext); i += aes.BlockSize {
		block.Decrypt(plaintext[i:i+aes.BlockSize], ciphertext[i:i+aes.BlockSize])
	}

	// 去除PKCS7填充
	plaintext = pkcs7UnPadding(plaintext)

	return string(plaintext)
}

// PKCS7填充
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

// PKCS7去填充
func pkcs7UnPadding(data []byte) []byte {
	length := len(data)
	if length == 0 {
		return data
	}
	unpadding := int(data[length-1])
	if unpadding > length {
		return data
	}
	return data[:(length - unpadding)]
}

// encrypts plaintext using AES-CTR mode with PKCS7 padding.
// The key must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively.
// Returns base64-encoded encrypted data.
func AesCTREncrypt(key, plaintext []byte) (string, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", errors.New("invalid key length: must be 16, 24, or 32 bytes")
	}
	if len(plaintext) == 0 {
		return "", errors.New("plaintext cannot be empty")
	}

	dataBlock, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Use AES dataBlock size (16 bytes) for padding instead of hardcoded 32
	paddedPlaintext := padPKCS7(plaintext, aes.BlockSize)

	p := make([]byte, aes.BlockSize+len(paddedPlaintext))
	iv := p[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCTR(dataBlock, iv)
	stream.XORKeyStream(p[aes.BlockSize:], paddedPlaintext)

	return base64.StdEncoding.EncodeToString(p), nil
}

// decrypts base64-encoded data using AES-CTR mode.
// The key must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively.
// Returns the decrypted plaintext with PKCS7 padding removed.
func AesCTRDecrypt(key []byte, encodedData string) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("invalid key length: must be 16, 24, or 32 bytes")
	}
	if encodedData == "" {
		return nil, errors.New("encoded data cannot be empty")
	}

	data, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return nil, err
	}

	if len(data) <= aes.BlockSize {
		return nil, errors.New("encrypted data too short")
	}

	iv := data[:aes.BlockSize]
	text := data[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(text))
	stream.XORKeyStream(plaintext, text)

	return unpadPKCS7(plaintext)
}

// adds PKCS#7 padding to the source data.
// blockSize should be the AES block size (16 bytes).
func padPKCS7(src []byte, blockSize int) []byte {
	if blockSize <= 0 || blockSize > 255 {
		panic("invalid block size for PKCS7 padding")
	}
	padding := blockSize - len(src)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

// removes PKCS#7 padding from the source data.
// Returns an error if the padding is invalid.
func unpadPKCS7(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, errors.New("cannot unpad empty data")
	}

	length := len(src)
	padding := int(src[length-1])

	// Validate padding
	if padding == 0 || padding > length || padding > 16 {
		return nil, errors.New("invalid PKCS7 padding")
	}

	// Verify all padding bytes are the same
	for i := length - padding; i < length; i++ {
		if src[i] != byte(padding) {
			return nil, errors.New("invalid PKCS7 padding")
		}
	}

	return src[:length-padding], nil
}

// Returns the compressed data or an error if compression fails.
func Deflate(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("cannot compress empty data")
	}

	var buf bytes.Buffer
	writer := zlib.NewWriter(&buf)
	_, err := writer.Write(data)
	if err != nil {
		writer.Close()
		return nil, err
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Returns the decompressed data or an error if decompression fails.
func Inflate(compressedData []byte) ([]byte, error) {
	if len(compressedData) == 0 {
		return nil, errors.New("cannot decompress empty data")
	}

	reader := bytes.NewReader(compressedData)
	zlibReader, err := zlib.NewReader(reader)
	if err != nil {
		return nil, err
	}
	defer zlibReader.Close()

	return io.ReadAll(zlibReader)
}
