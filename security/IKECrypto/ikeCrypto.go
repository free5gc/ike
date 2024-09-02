package crypto

import "github.com/sirupsen/logrus"

// Interfaces
type IKECrypto interface {
	Encrypt(plainText []byte) ([]byte, error)
	Decrypt(l *logrus.Entry, cipherText []byte) ([]byte, error)
}
