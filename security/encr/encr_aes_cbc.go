package encr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/pkg/errors"

	ikeCrypto "github.com/free5gc/ike/security/IKECrypto"
	"github.com/free5gc/ike/security/lib"
	ike_types "github.com/free5gc/ike/types"
)

const (
	ENCR_AES_CBC_128 string = "ENCR_AES_CBC_128"
	ENCR_AES_CBC_192 string = "ENCR_AES_CBC_192"
	ENCR_AES_CBC_256 string = "ENCR_AES_CBC_256"
)

func toString_ENCR_AES_CBC(attrType uint16, intValue uint16, bytesValue []byte) string {
	if attrType == ike_types.AttributeTypeKeyLength {
		switch intValue {
		case 128:
			return ENCR_AES_CBC_128
		case 192:
			return ENCR_AES_CBC_192
		case 256:
			return ENCR_AES_CBC_256
		default:
			return ""
		}
	} else {
		return ""
	}
}

var (
	_ ENCRType  = &EncrAesCbc{}
	_ ENCRKType = &EncrAesCbc{}
)

type EncrAesCbc struct {
	keyLength int
}

func (t *EncrAesCbc) TransformID() uint16 {
	return ike_types.ENCR_AES_CBC
}

func (t *EncrAesCbc) getAttribute() (bool, uint16, uint16, []byte, error) {
	keyLengthBits := t.keyLength * 8
	if keyLengthBits < 0 || keyLengthBits > 0xFFFF {
		return false, 0, 0, nil, errors.Errorf("key length exceeds uint16 maximum value: %v", keyLengthBits)
	}
	return true, ike_types.AttributeTypeKeyLength, uint16(keyLengthBits), nil, nil
}

func (t *EncrAesCbc) GetKeyLength() int {
	return t.keyLength
}

func (t *EncrAesCbc) NewCrypto(key []byte) (ikeCrypto.IKECrypto, error) {
	var err error
	encr := new(EncrAesCbcCrypto)
	if len(key) != t.keyLength {
		return nil, errors.Errorf("EncrAesCbc init error: Get unexpected key length")
	}

	if encr.Block, err = aes.NewCipher(key); err != nil {
		return nil, errors.Wrapf(err, "EncrAesCbc init: Error occur when create new cipher: ")
	} else {
		return encr, nil
	}
}

var _ ikeCrypto.IKECrypto = &EncrAesCbcCrypto{}

type EncrAesCbcCrypto struct {
	Block   cipher.Block
	Iv      []byte // initializationVector
	Padding []byte
}

func (encr *EncrAesCbcCrypto) Encrypt(plainText []byte) ([]byte, error) {
	var err error

	// Padding message
	if encr.Padding == nil {
		plainText, err = lib.PKCS7Padding(plainText, aes.BlockSize)
		if err != nil {
			return nil, errors.Wrapf(err, "Encr Encrypt()")
		}
	} else {
		plainText = append(plainText, encr.Padding...)
	}

	// Slice
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	var initializationVector []byte
	if encr.Iv == nil {
		initializationVector = cipherText[:aes.BlockSize]
		// IV
		_, err = io.ReadFull(rand.Reader, initializationVector)
		if err != nil {
			return nil, errors.Errorf("Read random initialization vector failed")
		}
	} else {
		copy(cipherText[:aes.BlockSize], encr.Iv)
		initializationVector = encr.Iv
	}

	// Encryption
	cbcBlockMode := cipher.NewCBCEncrypter(encr.Block, initializationVector) // #nosec G407
	cbcBlockMode.CryptBlocks(cipherText[aes.BlockSize:], plainText)

	return cipherText, nil
}

func (encr *EncrAesCbcCrypto) Decrypt(cipherText []byte) ([]byte, error) {
	// Check
	if len(cipherText) < aes.BlockSize {
		return nil, errors.Errorf("EncrAesCbcCrypto: Length of cipher text is too short to decrypt")
	}

	var initializationVector []byte
	if encr.Iv == nil {
		initializationVector = cipherText[:aes.BlockSize]
	} else {
		initializationVector = encr.Iv
	}

	encryptedMessage := cipherText[aes.BlockSize:]

	if len(encryptedMessage)%aes.BlockSize != 0 {
		return nil, errors.Errorf("EncrAesCbcCrypto: Cipher text is not a multiple of block size")
	}

	// Slice
	plainText := make([]byte, len(encryptedMessage))

	// Decryption
	cbcBlockMode := cipher.NewCBCDecrypter(encr.Block, initializationVector) // #nosec G407
	cbcBlockMode.CryptBlocks(plainText, encryptedMessage)

	// fmt.Printf("Decrypted content:\n%s", hex.Dump(plainText))
	// Remove padding
	padding := int(plainText[len(plainText)-1]) + 1
	plainText = plainText[:len(plainText)-padding]

	// fmt.Printf("Decrypted content with out padding:\n%s", hex.Dump(plainText))

	return plainText, nil
}
