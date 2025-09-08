package security

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
)

func DESEncryptString(src, encryptKey string) string {
	encrypted, err := DESEncrypt([]byte(src), encryptKey)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(encrypted)
}
func DESDecryptString(src, encryptKey string) string {
	encrypted, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		return ""
	}
	decrypted, err := DESDecrypt(encrypted, encryptKey)
	if err != nil {
		return ""
	}
	//return base64.StdEncoding.EncodeToString(decrypted)
	return string(decrypted)
}

// DESEncrypt DES 加密  DES CBC模式中的iv 即为密码key key必须是8位
func DESEncrypt(origData []byte, key string) ([]byte, error) {
	block, err := des.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	origData = PKCS5Padding(origData, block.BlockSize())
	// origData = ZeroPadding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, []byte(key))
	crypted := make([]byte, len(origData))
	// 根据CryptBlocks方法的说明，如下方式初始化crypted也可以
	// crypted := origData
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

// DESDecrypt DES 解密
func DESDecrypt(crypted []byte, key string) ([]byte, error) {
	block, err := des.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, []byte(key))
	origData := make([]byte, len(crypted))
	// origData := crypted
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	// origData = ZeroUnPadding(origData)
	return origData, nil
}

// ZeroPadding ZeroPadding
func ZeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padtext...)
}

// ZeroUnPadding ZeroUnPadding
func ZeroUnPadding(origData []byte) []byte {
	return bytes.TrimRightFunc(origData, func(r rune) bool {
		return r == rune(0)
	})
}

// PKCS5Padding PKCS5Padding
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// PKCS5UnPadding PKCS5UnPadding
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
