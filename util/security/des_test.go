package security

import (
	"log"
	"testing"
)

func TestAESEncrypt(t *testing.T) {
	p := DESEncryptString("keleqing", "keleqing")

	log.Println("+++++" + p)
}
func TestAESDecrypt(t *testing.T) {
	p := DESDecryptString("j5xfsjHSPou2yRcCR58XAg==", "keleqing")

	log.Println("+++++" + p)
}
