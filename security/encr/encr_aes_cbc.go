package encr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/pkg/errors"

	"github.com/free5gc/ike/message"
	ikeCrypto "github.com/free5gc/ike/security/IKECrypto"
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

func (t *ENCR_AES_CBC) getAttribute() (bool, uint16, uint16, []byte, error) {
	keyLengthBits := t.keyLength * 8
	if keyLengthBits < 0 || keyLengthBits > 0xFFFF {
		return false, 0, 0, nil, errors.Errorf("key length exceeds uint16 maximum value: %v", keyLengthBits)
	}
	return true, message.AttributeTypeKeyLength, uint16(keyLengthBits), nil, nil
}

func (t *ENCR_AES_CBC) GetKeyLength() int {
	return t.keyLength
}

func (t *ENCR_AES_CBC) NewCrypto(key []byte, iv []byte, padding []byte) (ikeCrypto.IKECrypto, error) {
	var err error
	encr := new(ENCR_AES_CBC_Crypto)
	if len(key) != t.keyLength {
		return nil, errors.Errorf("ENCR_AES_CBC init error: Get unexpected key length")
	}
	encr.iv = iv
	encr.padding = padding

	if encr.block, err = aes.NewCipher(key); err != nil {
		return nil, errors.Wrapf(err, "ENCR_AES_CBC init: Error occur when create new cipher: ")
	} else {
		return encr, nil
	}
}

var _ ikeCrypto.IKECrypto = &ENCR_AES_CBC_Crypto{}

type ENCR_AES_CBC_Crypto struct {
	block   cipher.Block
	iv      []byte // initializationVector
	padding []byte
}

func (encr *ENCR_AES_CBC_Crypto) Encrypt(plainText []byte) ([]byte, error) {
	var err error

	// Padding message
	if encr.padding == nil {
		plainText, err = lib.PKCS7Padding(plainText, aes.BlockSize)
		if err != nil {
			return nil, errors.Wrapf(err, "Encr Encrypt()")
		}
	} else {
		plainText = append(plainText, encr.padding...)
	}

	// Slice
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	var initializationVector []byte
	if encr.iv == nil {
		initializationVector = cipherText[:aes.BlockSize]
		// IV
		_, err = io.ReadFull(rand.Reader, initializationVector)
		if err != nil {
			return nil, errors.Errorf("Read random initialization vector failed")
		}
	} else {
		copy(cipherText[:aes.BlockSize], encr.iv)
		initializationVector = encr.iv
	}

	// Encryption
	cbcBlockMode := cipher.NewCBCEncrypter(encr.block, initializationVector) // #nosec G407
	cbcBlockMode.CryptBlocks(cipherText[aes.BlockSize:], plainText)

	return cipherText, nil
}

func (encr *ENCR_AES_CBC_Crypto) Decrypt(cipherText []byte) ([]byte, error) {
	// Check
	if len(cipherText) < aes.BlockSize {
		return nil, errors.Errorf("ENCR_AES_CBC_Crypto: Length of cipher text is too short to decrypt")
	}

	var initializationVector []byte
	if encr.iv == nil {
		initializationVector = cipherText[:aes.BlockSize]
	} else {
		initializationVector = encr.iv
	}

	encryptedMessage := cipherText[aes.BlockSize:]

	if len(encryptedMessage)%aes.BlockSize != 0 {
		return nil, errors.Errorf("ENCR_AES_CBC_Crypto: Cipher text is not a multiple of block size")
	}

	// Slice
	plainText := make([]byte, len(encryptedMessage))

	// Decryption
	cbcBlockMode := cipher.NewCBCDecrypter(encr.block, initializationVector) // #nosec G407
	cbcBlockMode.CryptBlocks(plainText, encryptedMessage)

	// fmt.Printf("Decrypted content:\n%s", hex.Dump(plainText))
	// Remove padding
	padding := int(plainText[len(plainText)-1]) + 1
	plainText = plainText[:len(plainText)-padding]

	// fmt.Printf("Decrypted content with out padding:\n%s", hex.Dump(plainText))

	return plainText, nil
}
