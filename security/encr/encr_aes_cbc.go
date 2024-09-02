package encr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/ike/message"
	"github.com/free5gc/ike/security/lib"
)

const (
	string_ENCR_AES_CBC_128 string = "ENCR_AES_CBC_128"
	string_ENCR_AES_CBC_192 string = "ENCR_AES_CBC_192"
	string_ENCR_AES_CBC_256 string = "ENCR_AES_CBC_256"
)

func toString_ENCR_AES_CBC(attrType uint16, intValue uint16, bytesValue []byte) string {
	if attrType == message.AttributeTypeKeyLength {
		switch intValue {
		case 128:
			return string_ENCR_AES_CBC_128
		case 192:
			return string_ENCR_AES_CBC_192
		case 256:
			return string_ENCR_AES_CBC_256
		default:
			return ""
		}
	} else {
		return ""
	}
}

var (
	_ ENCRType  = &ENCR_AES_CBC{}
	_ ENCRKType = &ENCR_AES_CBC{}
)

type ENCR_AES_CBC struct {
	keyLength int
}

func (t *ENCR_AES_CBC) TransformID() uint16 {
	return message.ENCR_AES_CBC
}

func (t *ENCR_AES_CBC) getAttribute() (bool, uint16, uint16, []byte) {
	return true, message.AttributeTypeKeyLength, uint16(t.keyLength * 8), nil
}

func (t *ENCR_AES_CBC) GetKeyLength() int {
	return t.keyLength
}

func (t *ENCR_AES_CBC) NewCrypto(key []byte) (IKECrypto, error) {
	var err error
	encr := new(ENCR_AES_CBC_Crypto)
	if len(key) != t.keyLength {
		return nil, errors.Errorf("ENCR_AES_CBC init error: Get unexpected key length")
	}
	if encr.block, err = aes.NewCipher(key); err != nil {
		return nil, errors.Wrapf(err, "ENCR_AES_CBC init: Error occur when create new cipher: ")
	} else {
		return encr, nil
	}
}

var _ IKECrypto = &ENCR_AES_CBC_Crypto{}

type ENCR_AES_CBC_Crypto struct {
	block cipher.Block
}

func (encr *ENCR_AES_CBC_Crypto) Encrypt(plainText []byte) ([]byte, error) {
	// Padding message
	plainText = lib.PKCS7Padding(plainText, aes.BlockSize)
	plainText[len(plainText)-1]--

	// Slice
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	initializationVector := cipherText[:aes.BlockSize]

	// IV
	_, err := io.ReadFull(rand.Reader, initializationVector)
	if err != nil {
		return nil, errors.New("Read random initialization vector failed")
	}

	// Encryption
	cbcBlockMode := cipher.NewCBCEncrypter(encr.block, initializationVector)
	cbcBlockMode.CryptBlocks(cipherText[aes.BlockSize:], plainText)

	return cipherText, nil
}

func (encr *ENCR_AES_CBC_Crypto) Decrypt(l *logrus.Entry, cipherText []byte) ([]byte, error) {
	// Check
	if len(cipherText) < aes.BlockSize {
		return nil, errors.New("ENCR_AES_CBC_Crypto: Length of cipher text is too short to decrypt")
	}

	initializationVector := cipherText[:aes.BlockSize]
	encryptedMessage := cipherText[aes.BlockSize:]

	if len(encryptedMessage)%aes.BlockSize != 0 {
		return nil, errors.New("ENCR_AES_CBC_Crypto: Cipher text is not a multiple of block size")
	}

	// Slice
	plainText := make([]byte, len(encryptedMessage))

	// Decryption
	cbcBlockMode := cipher.NewCBCDecrypter(encr.block, initializationVector)
	cbcBlockMode.CryptBlocks(plainText, encryptedMessage)

	l.Tracef("Decrypted content:\n%s", hex.Dump(plainText))

	// Remove padding
	padding := int(plainText[len(plainText)-1]) + 1
	plainText = plainText[:len(plainText)-padding]

	l.Tracef("Decrypted content with out padding:\n%s", hex.Dump(plainText))

	return plainText, nil
}
