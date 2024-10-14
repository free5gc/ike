package encr

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	sk_ei_256 = []byte{
		0x3d, 0x3c, 0x6a, 0x1f, 0x1c, 0x69, 0x3a, 0xcf,
		0x22, 0x3a, 0xed, 0xf3, 0x0a, 0xc8, 0x1a, 0xe4,
		0xfc, 0xd2, 0x1c, 0x7e, 0x6f, 0xce, 0xfd, 0xd7,
		0x42, 0x80, 0x84, 0x2d, 0x7f, 0xee, 0xfd, 0x10,
	}
	iv_nil_256 = []byte{
		0x95, 0xb0, 0xf4, 0x84, 0x49, 0x80, 0xf4, 0xaa,
		0x28, 0x86, 0x1a, 0x0f, 0x11, 0x25, 0x30, 0x61,
	}
	padding_nil_256 = []byte{
		0xb7, 0x8d, 0xb0, 0x3d, 0x23, 0x1f, 0x01, 0x4d,
		0xb0, 0x91, 0xcb, 0x52, 0x14, 0xed, 0x7b, 0x0f,
	}
	cipherText_nil_256 = []byte{
		0x95, 0xb0, 0xf4, 0x84, 0x49, 0x80, 0xf4, 0xaa,
		0x28, 0x86, 0x1a, 0x0f, 0x11, 0x25, 0x30, 0x61,
		0xf2, 0x6c, 0x08, 0x2f, 0x44, 0x36, 0x8b, 0x76,
		0x94, 0x3f, 0xd6, 0xee, 0x38, 0xe5, 0x48, 0xe8,
	}
	iv_256 = []byte{
		0xf1, 0x42, 0xeb, 0x54, 0x99, 0x07, 0x27, 0xc1,
		0xb8, 0x02, 0x30, 0x2e, 0xea, 0xb6, 0xfe, 0x1e,
	}
	padding_256 = []byte{
		0xd3, 0xae, 0xca, 0x6b, 0x2f, 0x91, 0x5f, 0x07,
	}
	plainText_256 = []byte{
		0x29, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x00,
		0x0a, 0x0a, 0x00, 0xca, 0x24, 0x00, 0x00, 0x08,
		0x00, 0x00, 0x40, 0x00, 0x27, 0x00, 0x00, 0x0c,
		0x01, 0x00, 0x00, 0x00, 0x0a, 0x0a, 0x00, 0x5e,
		0x21, 0x00, 0x00, 0x1c, 0x02, 0x00, 0x00, 0x00,
		0xc5, 0x25, 0x2b, 0x3b, 0x2f, 0x8d, 0xb9, 0x67,
		0xb8, 0xe0, 0x88, 0x05, 0x5c, 0x02, 0xd2, 0xe3,
		0xa3, 0xe2, 0x11, 0xb5, 0x2c, 0x00, 0x00, 0x2c,
		0x00, 0x00, 0x00, 0x28, 0x01, 0x03, 0x04, 0x03,
		0xc6, 0xe6, 0x62, 0x17, 0x03, 0x00, 0x00, 0x0c,
		0x01, 0x00, 0x00, 0x0c, 0x80, 0x0e, 0x01, 0x00,
		0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0c,
		0x00, 0x00, 0x00, 0x08, 0x05, 0x00, 0x00, 0x00,
		0x2d, 0x00, 0x00, 0x18, 0x01, 0x00, 0x00, 0x00,
		0x07, 0x00, 0x00, 0x10, 0x00, 0x00, 0xff, 0xff,
		0x0a, 0x0a, 0x00, 0x00, 0x0a, 0x0a, 0x00, 0xff,
		0x29, 0x00, 0x00, 0x18, 0x01, 0x00, 0x00, 0x00,
		0x07, 0x00, 0x00, 0x10, 0x00, 0x00, 0xff, 0xff,
		0x0a, 0x0a, 0x00, 0x00, 0x0a, 0x0a, 0x00, 0xff,
		0x29, 0x00, 0x00, 0x08, 0x00, 0x00, 0x40, 0x0c,
		0x29, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x40, 0x0d,
		0x0a, 0x64, 0x64, 0x7c, 0x29, 0x00, 0x00, 0x0c,
		0x00, 0x00, 0x40, 0x0d, 0xac, 0x10, 0x16, 0xfd,
		0x29, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x40, 0x0d,
		0xac, 0x10, 0x06, 0xfd, 0x29, 0x00, 0x00, 0x0c,
		0x00, 0x00, 0x40, 0x0d, 0xac, 0x1f, 0xff, 0xff,
		0x29, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x40, 0x0d,
		0xac, 0x11, 0x00, 0x01, 0x29, 0x00, 0x00, 0x0c,
		0x00, 0x00, 0x40, 0x0d, 0x0a, 0x64, 0x64, 0x0c,
		0x29, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x40, 0x0d,
		0xac, 0x10, 0x3d, 0x01, 0x29, 0x00, 0x00, 0x0c,
		0x00, 0x00, 0x40, 0x0d, 0xac, 0x10, 0x3e, 0x01,
		0x29, 0x00, 0x00, 0x08, 0x00, 0x00, 0x40, 0x14,
		0x29, 0x00, 0x00, 0x08, 0x00, 0x00, 0x40, 0x21,
		0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x40, 0x24,
	}
	cipherText_256 = []byte{
		0xf1, 0x42, 0xeb, 0x54, 0x99, 0x07, 0x27, 0xc1,
		0xb8, 0x02, 0x30, 0x2e, 0xea, 0xb6, 0xfe, 0x1e,
		0x40, 0xf2, 0x5d, 0x95, 0x0e, 0x12, 0xba, 0xe0,
		0xc2, 0x42, 0x96, 0x7d, 0xa6, 0xa4, 0x05, 0xe3,
		0xaa, 0xcb, 0xd8, 0x16, 0x39, 0x6a, 0x89, 0x42,
		0xd6, 0xe7, 0x43, 0x3d, 0x54, 0x87, 0x6a, 0x8a,
		0x50, 0x8c, 0x7f, 0x8b, 0xfb, 0x2c, 0xf4, 0x18,
		0xf4, 0x77, 0x50, 0xb1, 0x85, 0x50, 0x2c, 0xab,
		0xa8, 0xfe, 0x46, 0x62, 0xd1, 0xdd, 0x6f, 0xd7,
		0xfa, 0xd7, 0xb0, 0x7e, 0xb6, 0x02, 0x05, 0x51,
		0xe7, 0xf7, 0xd7, 0xcd, 0xde, 0x4d, 0x8e, 0xbe,
		0xe0, 0xb8, 0xdc, 0x9e, 0xd9, 0xd6, 0x00, 0xc7,
		0x3d, 0xd2, 0xf4, 0xab, 0xa6, 0xc9, 0xe8, 0x04,
		0xf0, 0xff, 0x86, 0xa5, 0x6a, 0x71, 0x59, 0xe9,
		0xf3, 0x3f, 0xc3, 0x61, 0x0d, 0x61, 0x31, 0x24,
		0xfd, 0xf1, 0x96, 0x6d, 0xcc, 0x8e, 0xa5, 0x13,
		0x43, 0xa4, 0x5b, 0xbc, 0x60, 0x03, 0x6e, 0x2f,
		0x7e, 0xef, 0xea, 0x8b, 0x61, 0x84, 0x05, 0xeb,
		0xd3, 0xdf, 0xba, 0xbc, 0x56, 0xef, 0xa0, 0x0c,
		0x9e, 0x53, 0xfd, 0xd3, 0xa9, 0x3d, 0x4f, 0xb4,
		0xb9, 0xd5, 0x2a, 0xd6, 0xb2, 0xb2, 0x87, 0xdc,
		0x03, 0xd8, 0xb3, 0x59, 0xde, 0x12, 0x4e, 0x6b,
		0x0a, 0xdc, 0x5e, 0x34, 0xa1, 0xf9, 0xd7, 0xe0,
		0xc7, 0xca, 0xd9, 0xa1, 0x3c, 0x27, 0x1a, 0xc1,
		0xaa, 0x75, 0xc8, 0xa0, 0xd6, 0xfe, 0x89, 0x7b,
		0x74, 0xaf, 0xfd, 0xa5, 0x4b, 0xfd, 0x05, 0xd9,
		0x25, 0x3e, 0x18, 0xa4, 0xb7, 0xa9, 0xe7, 0x22,
		0x76, 0x57, 0x58, 0x64, 0x16, 0x9e, 0x8a, 0x38,
		0xdc, 0x87, 0x7f, 0x4f, 0x68, 0xab, 0x61, 0xd6,
		0x56, 0xe5, 0xa6, 0x94, 0x63, 0xb0, 0x67, 0xd9,
		0xbc, 0x74, 0x60, 0x53, 0x13, 0x1f, 0xe5, 0x8a,
		0x70, 0xaa, 0x7a, 0x8f, 0xf6, 0x0c, 0x86, 0xa6,
		0x56, 0xcf, 0x30, 0x97, 0x92, 0x48, 0x51, 0x01,
		0x40, 0xc9, 0x44, 0x3f, 0x80, 0x07, 0x62, 0x5e,
		0x20, 0x1e, 0x96, 0xd8, 0x9d, 0x60, 0x8f, 0xf5,
		0xab, 0xd3, 0xeb, 0x3e, 0x0f, 0x3b, 0xf5, 0x04,
		0x8d, 0xce, 0x8e, 0x63, 0x0a, 0x66, 0xb8, 0x9a,
		0xa7, 0x8e, 0x45, 0x27, 0x3b, 0xd2, 0xd3, 0xda,
	}
)

func TestEncrypt_256(t *testing.T) {
	var sk EncrAesCbcCrypto
	var block cipher.Block
	var err error
	var cipher []byte

	block, err = aes.NewCipher(sk_ei_256)
	require.NoError(t, err)

	sk = EncrAesCbcCrypto{
		Block:   block,
		Iv:      iv_nil_256,
		Padding: padding_nil_256,
	}
	cipher, err = sk.Encrypt(nil)
	require.NoError(t, err)
	require.Equal(t, cipherText_nil_256, cipher)

	sk = EncrAesCbcCrypto{
		Block:   block,
		Iv:      iv_256,
		Padding: padding_256,
	}
	cipher, err = sk.Encrypt(plainText_256)
	require.NoError(t, err)
	require.Equal(t, cipherText_256, cipher)
}

func TestDecrypt_256(t *testing.T) {
	var sk EncrAesCbcCrypto
	var err error
	var block cipher.Block
	var plain []byte

	block, err = aes.NewCipher(sk_ei_256)
	require.NoError(t, err)

	sk = EncrAesCbcCrypto{
		Block:   block,
		Iv:      iv_nil_256,
		Padding: padding_nil_256,
	}
	plain, err = sk.Decrypt(cipherText_nil_256)
	require.NoError(t, err)
	testnil := make([]byte, 0)
	require.Equal(t, testnil, plain)

	sk = EncrAesCbcCrypto{
		Block:   block,
		Iv:      iv_256,
		Padding: padding_256,
	}
	plain, err = sk.Decrypt(cipherText_256)
	require.NoError(t, err)
	require.Equal(t, plainText_256, plain)
}