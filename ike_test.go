package ike

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/ike/message"
	"github.com/free5gc/ike/security"
	"github.com/free5gc/ike/security/encr"
	"github.com/free5gc/ike/security/integ"
)

var (
	eapIkeMsg = message.IKEMessage{
		IKEHeader: &message.IKEHeader{
			InitiatorSPI: 0x000000000006f708,
			ResponderSPI: 0xc9e2e31f8b64053d,
			MajorVersion: 2,
			MinorVersion: 0,
			ExchangeType: message.IKE_AUTH,
			Flags:        message.InitiatorBitCheck,
			MessageID:    0x03,
			NextPayload:  uint8(message.TypeSK),
			PayloadBytes: []byte{
				0x30, 0x00, 0x00, 0x50, 0xec, 0x50, 0x31, 0x16,
				0x2c, 0x69, 0x2f, 0xbb, 0xfc, 0x4d, 0x20, 0x64,
				0x0c, 0x91, 0x21, 0xeb, 0xe9, 0x47, 0x5e, 0xf9,
				0x4f, 0x9b, 0x02, 0x95, 0x9d, 0x31, 0x24, 0x2e,
				0x53, 0x5e, 0x9c, 0x3c, 0x4d, 0xca, 0xec, 0xd1,
				0xbf, 0xd6, 0xdd, 0x80, 0xaa, 0x81, 0x2b, 0x07,
				0xde, 0x36, 0xde, 0xe9, 0xb7, 0x50, 0x94, 0x35,
				0xf6, 0x35, 0xe1, 0xaa, 0xae, 0x1c, 0x38, 0x25,
				0xf4, 0xea, 0xe3, 0x38, 0x49, 0x03, 0xf7, 0x24,
				0xf4, 0x44, 0x17, 0x0c, 0x68, 0x45, 0xca, 0x80,
			},
		},
		Payloads: message.IKEPayloadContainer{
			&message.EAP{
				Code:       0x02,
				Identifier: 0x3b,
				EAPTypeData: []message.EAPTypeFormat{
					&message.EAPExpanded{
						VendorID:   0x28af,
						VendorType: 0x03,
						VendorData: []byte{
							0x02, 0x00, 0x00, 0x00, 0x00, 0x15, 0x7e, 0x00,
							0x57, 0x2d, 0x10, 0xf5, 0x07, 0x36, 0x2e, 0x32,
							0x2d, 0xe3, 0x68, 0x57, 0x93, 0x65, 0xd2, 0x86,
							0x2b, 0x50, 0xed,
						},
					},
				},
			},
		},
	}
	eapRawMsg = []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0xf7, 0x08,
		0xc9, 0xe2, 0xe3, 0x1f, 0x8b, 0x64, 0x05, 0x3d,
		0x2e, 0x20, 0x23, 0x08, 0x00, 0x00, 0x00, 0x03,
		0x00, 0x00, 0x00, 0x6c, 0x30, 0x00, 0x00, 0x50,
		0xec, 0x50, 0x31, 0x16, 0x2c, 0x69, 0x2f, 0xbb,
		0xfc, 0x4d, 0x20, 0x64, 0x0c, 0x91, 0x21, 0xeb,
		0xe9, 0x47, 0x5e, 0xf9, 0x4f, 0x9b, 0x02, 0x95,
		0x9d, 0x31, 0x24, 0x2e, 0x53, 0x5e, 0x9c, 0x3c,
		0x4d, 0xca, 0xec, 0xd1, 0xbf, 0xd6, 0xdd, 0x80,
		0xaa, 0x81, 0x2b, 0x07, 0xde, 0x36, 0xde, 0xe9,
		0xb7, 0x50, 0x94, 0x35, 0xf6, 0x35, 0xe1, 0xaa,
		0xae, 0x1c, 0x38, 0x25, 0xf4, 0xea, 0xe3, 0x38,
		0x49, 0x03, 0xf7, 0x24, 0xf4, 0x44, 0x17, 0x0c,
		0x68, 0x45, 0xca, 0x80,
	}
)

func TestEncodeDecode(t *testing.T) {
	encryptionAlgorithm := encr.StrToType("ENCR_AES_CBC_256")

	integrityAlgorithm := integ.StrToType("AUTH_HMAC_SHA1_96")

	ikeSAKey := &security.IKESAKey{
		EncrInfo:  encryptionAlgorithm,
		IntegInfo: integrityAlgorithm,
	}

	var err error
	ikeSAKey.SK_ei, err = hex.DecodeString(
		"3d7a26417122cee9" +
			"c77c59f375b024cd" +
			"b9f0b5777ea18b50" +
			"f8a671fd3b2daa99")
	require.NoError(t, err)
	ikeSAKey.Encr_i, err = ikeSAKey.EncrInfo.NewCrypto(ikeSAKey.SK_ei)
	require.NoError(t, err)

	ikeSAKey.SK_er, err = hex.DecodeString(
		"3ea57e7ddfb30756" +
			"a04619a9873333b0" +
			"8e94deef05b6a05d" +
			"7eb3dba075d81c6f")
	require.NoError(t, err)
	ikeSAKey.Encr_r, err = ikeSAKey.EncrInfo.NewCrypto(ikeSAKey.SK_er)
	require.NoError(t, err)

	ikeSAKey.SK_ai, err = hex.DecodeString(
		"ab8047415535cf53" +
			"e19a69e2c86feadf" +
			"ebfff1e9")
	require.NoError(t, err)
	ikeSAKey.Integ_i = ikeSAKey.IntegInfo.Init(ikeSAKey.SK_ai)

	ikeSAKey.SK_ar, err = hex.DecodeString(
		"16d5ae6f2859a73a" +
			"8c7db60bed07e245" +
			"38b19bb0")
	require.NoError(t, err)
	ikeSAKey.Integ_r = ikeSAKey.IntegInfo.Init(ikeSAKey.SK_ar)

	expIkeMsg := &message.IKEMessage{
		IKEHeader: &message.IKEHeader{
			InitiatorSPI: 0x000000000006f708,
			ResponderSPI: 0xc9e2e31f8b64053d,
			MajorVersion: 2,
			MinorVersion: 0,
			ExchangeType: message.IKE_AUTH,
			Flags:        message.InitiatorBitCheck,
			MessageID:    0x03,
			NextPayload:  uint8(message.TypeEAP),
		},
	}

	expIkePayloads := message.IKEPayloadContainer{
		&message.EAP{
			Code:       0x02,
			Identifier: 0x3b,
			EAPTypeData: message.EAPTypeDataContainer{
				&message.EAPExpanded{
					VendorID:   0x28af,
					VendorType: 0x03,
					VendorData: []byte{
						0x02, 0x00, 0x00, 0x00, 0x00, 0x15, 0x7e, 0x00,
						0x57, 0x2d, 0x10, 0xf5, 0x07, 0x36, 0x2e, 0x32,
						0x2d, 0xe3, 0x68, 0x57, 0x93, 0x65, 0xd2, 0x86,
						0x2b, 0x50, 0xed,
					},
				},
			},
		},
	}

	expIkeMsg.Payloads = append(expIkeMsg.Payloads, expIkePayloads...)

	b, err := EncodeEncrypt(expIkeMsg, ikeSAKey, message.Role_Initiator)
	require.NoError(t, err)

	ikehdr, err := message.ParseHeader(b)
	require.NoError(t, err)

	ikeMsg, err := DecodeDecrypt(b, ikehdr, ikeSAKey, message.Role_Responder)
	require.NoError(t, err)

	require.Equal(t, expIkePayloads, ikeMsg.Payloads)
}

func TestDecodeDecrypt(t *testing.T) {
	testcases := []struct {
		description                string
		b                          []byte
		ikeSAKey                   *security.IKESAKey
		sk_ei, sk_er, sk_ai, sk_ar []byte
		expErr                     bool
		expIkeMsg                  *message.IKEMessage
	}{
		{
			description: "decrypt with key",
			b:           eapRawMsg,
			ikeSAKey: &security.IKESAKey{
				EncrInfo:  encr.StrToType("ENCR_AES_CBC_256"),
				IntegInfo: integ.StrToType("AUTH_HMAC_SHA1_96"),
			},
			sk_ei: []byte{
				0x3d, 0x7a, 0x26, 0x41, 0x71, 0x22, 0xce, 0xe9,
				0xc7, 0x7c, 0x59, 0xf3, 0x75, 0xb0, 0x24, 0xcd,
				0xb9, 0xf0, 0xb5, 0x77, 0x7e, 0xa1, 0x8b, 0x50,
				0xf8, 0xa6, 0x71, 0xfd, 0x3b, 0x2d, 0xaa, 0x99,
			},
			sk_er: []byte{
				0x3e, 0xa5, 0x7e, 0x7d, 0xdf, 0xb3, 0x07, 0x56,
				0xa0, 0x46, 0x19, 0xa9, 0x87, 0x33, 0x33, 0xb0,
				0x8e, 0x94, 0xde, 0xef, 0x05, 0xb6, 0xa0, 0x5d,
				0x7e, 0xb3, 0xdb, 0xa0, 0x75, 0xd8, 0x1c, 0x6f,
			},
			sk_ai: []byte{
				0xab, 0x80, 0x47, 0x41, 0x55, 0x35, 0xcf, 0x53,
				0xe1, 0x9a, 0x69, 0xe2, 0xc8, 0x6f, 0xea, 0xdf,
				0xeb, 0xff, 0xf1, 0xe9,
			},
			sk_ar: []byte{
				0x16, 0xd5, 0xae, 0x6f, 0x28, 0x59, 0xa7, 0x3a,
				0x8c, 0x7d, 0xb6, 0x0b, 0xed, 0x07, 0xe2, 0x45,
				0x38, 0xb1, 0x9b, 0xb0,
			},
			expErr:    false,
			expIkeMsg: &eapIkeMsg,
		},
		{
			description: "decrypt without key",
			b:           eapRawMsg,
			expErr:      true,
		},
		{
			description: "msg len less than IKE_HEADER_LEN",
			b:           []byte{},
			expErr:      true,
		},
		{
			description: "no sk_ai",
			b:           eapRawMsg,
			ikeSAKey: &security.IKESAKey{
				EncrInfo:  encr.StrToType("ENCR_AES_CBC_256"),
				IntegInfo: integ.StrToType("AUTH_HMAC_SHA1_96"),
			},
			sk_ei: []byte{
				0x3d, 0x7a, 0x26, 0x41, 0x71, 0x22, 0xce, 0xe9,
				0xc7, 0x7c, 0x59, 0xf3, 0x75, 0xb0, 0x24, 0xcd,
				0xb9, 0xf0, 0xb5, 0x77, 0x7e, 0xa1, 0x8b, 0x50,
				0xf8, 0xa6, 0x71, 0xfd, 0x3b, 0x2d, 0xaa, 0x99,
			},
			sk_er: []byte{
				0x3e, 0xa5, 0x7e, 0x7d, 0xdf, 0xb3, 0x07, 0x56,
				0xa0, 0x46, 0x19, 0xa9, 0x87, 0x33, 0x33, 0xb0,
				0x8e, 0x94, 0xde, 0xef, 0x05, 0xb6, 0xa0, 0x5d,
				0x7e, 0xb3, 0xdb, 0xa0, 0x75, 0xd8, 0x1c, 0x6f,
			},
			sk_ar: []byte{
				0x16, 0xd5, 0xae, 0x6f, 0x28, 0x59, 0xa7, 0x3a,
				0x8c, 0x7d, 0xb6, 0x0b, 0xed, 0x07, 0xe2, 0x45,
				0x38, 0xb1, 0x9b, 0xb0,
			},
			expErr: true,
		},
		{
			description: "no sk_ei",
			b:           eapRawMsg,
			ikeSAKey: &security.IKESAKey{
				EncrInfo:  encr.StrToType("ENCR_AES_CBC_256"),
				IntegInfo: integ.StrToType("AUTH_HMAC_SHA1_96"),
			},
			sk_er: []byte{
				0x3e, 0xa5, 0x7e, 0x7d, 0xdf, 0xb3, 0x07, 0x56,
				0xa0, 0x46, 0x19, 0xa9, 0x87, 0x33, 0x33, 0xb0,
				0x8e, 0x94, 0xde, 0xef, 0x05, 0xb6, 0xa0, 0x5d,
				0x7e, 0xb3, 0xdb, 0xa0, 0x75, 0xd8, 0x1c, 0x6f,
			},
			sk_ai: []byte{
				0xab, 0x80, 0x47, 0x41, 0x55, 0x35, 0xcf, 0x53,
				0xe1, 0x9a, 0x69, 0xe2, 0xc8, 0x6f, 0xea, 0xdf,
				0xeb, 0xff, 0xf1, 0xe9,
			},
			sk_ar: []byte{
				0x16, 0xd5, 0xae, 0x6f, 0x28, 0x59, 0xa7, 0x3a,
				0x8c, 0x7d, 0xb6, 0x0b, 0xed, 0x07, 0xe2, 0x45,
				0x38, 0xb1, 0x9b, 0xb0,
			},
			expErr: true,
		},
		{
			description: "invalid checksum",
			b: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0xf7, 0x08,
				0xc9, 0xe2, 0xe3, 0x1f, 0x8b, 0x64, 0x05, 0x3d,
				0x2e, 0x20, 0x23, 0x08, 0x00, 0x00, 0x00, 0x03,
				0x00, 0x00, 0x00, 0x6c, 0x30, 0x00, 0x00, 0x50,
				0xec, 0x50, 0x31, 0x16, 0x2c, 0x69, 0x2f, 0xbb,
				0xfc, 0x4d, 0x20, 0x64, 0x0c, 0x91, 0x21, 0xeb,
				0xe9, 0x47, 0x5e, 0xf9, 0x4f, 0x9b, 0x02, 0x95,
				0x9d, 0x31, 0x24, 0x2e, 0x53, 0x5e, 0x9c, 0x3c,
				0x4d, 0xca, 0xec, 0xd1, 0xbf, 0xd6, 0xdd, 0x80,
				0xaa, 0x81, 0x2b, 0x07, 0xde, 0x36, 0xde, 0xe9,
				0xb7, 0x50, 0x94, 0x35, 0xf6, 0x35, 0xe1, 0xaa,
				0xae, 0x1c, 0x38, 0x25, 0xf4, 0xea, 0xe3, 0x38,
				0x49, 0x03, 0xf7, 0x24, 0xf4, 0x44, 0x17, 0x0c,
				0x00, 0x00, 0x00, 0x00,
			},
			ikeSAKey: &security.IKESAKey{
				EncrInfo:  encr.StrToType("ENCR_AES_CBC_256"),
				IntegInfo: integ.StrToType("AUTH_HMAC_SHA1_96"),
			},
			sk_ei: []byte{
				0x3d, 0x7a, 0x26, 0x41, 0x71, 0x22, 0xce, 0xe9,
				0xc7, 0x7c, 0x59, 0xf3, 0x75, 0xb0, 0x24, 0xcd,
				0xb9, 0xf0, 0xb5, 0x77, 0x7e, 0xa1, 0x8b, 0x50,
				0xf8, 0xa6, 0x71, 0xfd, 0x3b, 0x2d, 0xaa, 0x99,
			},
			sk_er: []byte{
				0x3e, 0xa5, 0x7e, 0x7d, 0xdf, 0xb3, 0x07, 0x56,
				0xa0, 0x46, 0x19, 0xa9, 0x87, 0x33, 0x33, 0xb0,
				0x8e, 0x94, 0xde, 0xef, 0x05, 0xb6, 0xa0, 0x5d,
				0x7e, 0xb3, 0xdb, 0xa0, 0x75, 0xd8, 0x1c, 0x6f,
			},
			sk_ai: []byte{
				0xab, 0x80, 0x47, 0x41, 0x55, 0x35, 0xcf, 0x53,
				0xe1, 0x9a, 0x69, 0xe2, 0xc8, 0x6f, 0xea, 0xdf,
				0xeb, 0xff, 0xf1, 0xe9,
			},
			sk_ar: []byte{
				0x16, 0xd5, 0xae, 0x6f, 0x28, 0x59, 0xa7, 0x3a,
				0x8c, 0x7d, 0xb6, 0x0b, 0xed, 0x07, 0xe2, 0x45,
				0x38, 0xb1, 0x9b, 0xb0,
			},
			expErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var err error
			var ikeMsg *message.IKEMessage

			if len(tc.sk_ai) > 0 {
				tc.ikeSAKey.Integ_i = tc.ikeSAKey.IntegInfo.Init(tc.sk_ai)
			}
			if len(tc.sk_ar) > 0 {
				tc.ikeSAKey.Integ_r = tc.ikeSAKey.IntegInfo.Init(tc.sk_ar)
			}

			if len(tc.sk_ei) > 0 {
				tc.ikeSAKey.Encr_i, err = tc.ikeSAKey.EncrInfo.NewCrypto(tc.sk_ei)
				require.NoError(t, err)
			}

			if len(tc.sk_er) > 0 {
				tc.ikeSAKey.Encr_r, err = tc.ikeSAKey.EncrInfo.NewCrypto(tc.sk_er)
				require.NoError(t, err)
			}

			ikeMsg, err = DecodeDecrypt(tc.b, nil, tc.ikeSAKey, message.Role_Responder)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expIkeMsg.Payloads, ikeMsg.Payloads)
				require.Equal(t, *tc.expIkeMsg.IKEHeader, *ikeMsg.IKEHeader)
			}
		})
	}
}

func TestEncryptMsg(t *testing.T) {
	encryptionAlgorithm := encr.StrToType("ENCR_AES_CBC_256")
	integrityAlgorithm := integ.StrToType("AUTH_HMAC_SHA1_96")

	ikeSAKey := &security.IKESAKey{
		EncrInfo:  encryptionAlgorithm,
		IntegInfo: integrityAlgorithm,
	}

	var err error
	var iv, padding, sk_ei, sk_er, sk_ai, sk_ar []byte
	var ikeMsg *message.IKEMessage
	var block cipher.Block

	iv = []byte{
		0xa2, 0xfb, 0xbc, 0xdd, 0xd3, 0x9a, 0xda, 0xdd,
		0x67, 0x10, 0xbc, 0x38, 0x33, 0xc0, 0x23, 0x72,
	}
	padding = []byte{
		0xe6, 0x59, 0x7d, 0x13, 0x9a, 0xa0, 0xd9, 0x3b,
		0x08,
	}
	sk_ei, err = hex.DecodeString(
		"b2e0279136e0477624e635e53e561c0b241d1388f3ea0873496e835b48c17508")
	require.NoError(t, err)

	block, err = aes.NewCipher(sk_ei)
	require.NoError(t, err)
	ikeSAKey.Encr_i = &encr.ENCR_AES_CBC_Crypto{
		Block:   block,
		Iv:      iv,
		Padding: padding,
	}

	sk_er, err = hex.DecodeString(
		"71919fd9d651da48fe141d0e6735d9a2ffc4512354db293c7b4c35f0fab62242")
	require.NoError(t, err)

	block, err = aes.NewCipher(sk_er)
	require.NoError(t, err)
	ikeSAKey.Encr_r = &encr.ENCR_AES_CBC_Crypto{
		Block:   block,
		Iv:      iv,
		Padding: padding,
	}

	sk_ai, err = hex.DecodeString(
		"f63878f3236929f870fe5e4f58621084b8be0c86")
	require.NoError(t, err)
	ikeSAKey.Integ_i = ikeSAKey.IntegInfo.Init(sk_ai)

	sk_ar, err = hex.DecodeString(
		"63204bde31bfd4e142081bb7beaba3819bf09aad")
	require.NoError(t, err)
	integ_r := ikeSAKey.IntegInfo.Init(sk_ar)
	ikeSAKey.Integ_r = integ_r

	ikeMsg = &message.IKEMessage{
		IKEHeader: &message.IKEHeader{
			InitiatorSPI: 0x494e377c00000000,
			ResponderSPI: 0x8ea9e2fc844bfaaf,
			MajorVersion: 2,
			MinorVersion: 0,
			ExchangeType: message.IKE_AUTH,
			Flags:        0x20,
			MessageID:    0x03,
			NextPayload:  uint8(message.TypeEAP),
		},
		Payloads: message.IKEPayloadContainer{
			&message.EAP{
				Code:       0x01,
				Identifier: 0xd9,
				EAPTypeData: []message.EAPTypeFormat{
					&message.EAPExpanded{
						VendorID:   0x28af,
						VendorType: 0x03,
						VendorData: []byte{
							0x02, 0x00, 0x00, 0x13, 0x7e, 0x03, 0x22, 0xe7,
							0x63, 0xcb, 0x00, 0x7e, 0x00, 0x5d, 0x02, 0x00,
							0x02, 0x80, 0x20, 0xe1, 0x36, 0x01, 0x02,
						},
					},
				},
			},
		},
	}
	// Successful encryption with not nil payload
	err = encryptMsg(ikeMsg, ikeSAKey, message.Role_Responder)
	require.NoError(t, err)
	expectPayload := message.IKEPayloadContainer{
		&message.Encrypted{
			NextPayload: uint8(message.NoNext),
			EncryptedData: []byte{
				0xa2, 0xfb, 0xbc, 0xdd, 0xd3, 0x9a, 0xda, 0xdd,
				0x67, 0x10, 0xbc, 0x38, 0x33, 0xc0, 0x23, 0x72,
				0xcd, 0xb2, 0xd8, 0xbd, 0x52, 0x64, 0xb4, 0xfe,
				0x07, 0x2c, 0x53, 0x18, 0x69, 0x0a, 0x89, 0x1d,
				0x23, 0x29, 0x0b, 0x19, 0xb2, 0x77, 0xfe, 0x54,
				0x96, 0x25, 0x2c, 0x86, 0x3f, 0x6b, 0x42, 0xaa,
				0x7a, 0x9e, 0x24, 0x69, 0x0a, 0xb5, 0xea, 0xcb,
				0x88, 0x65, 0xca, 0x1a, 0xf0, 0xd0, 0xc9, 0xbb,
				0xbd, 0xa2, 0xd9, 0x9b, 0x22, 0x76, 0x76, 0x7c,
				0x80, 0x84, 0xd2, 0xb4,
			},
		},
	}
	require.Equal(t, expectPayload[0].(*message.Encrypted).EncryptedData,
		ikeMsg.Payloads[0].(*message.Encrypted).EncryptedData)

	// IKE Security Association is nil
	err = encryptMsg(ikeMsg, nil, message.Role_Initiator)
	require.Error(t, err)

	// Response IKE Message is nil
	err = encryptMsg(nil, ikeSAKey, message.Role_Initiator)
	require.Error(t, err)

	// No integrity algorithm specified
	ikeSAKey.IntegInfo = nil
	err = encryptMsg(ikeMsg, ikeSAKey, message.Role_Initiator)
	require.Error(t, err)

	ikeSAKey.IntegInfo = integrityAlgorithm

	// No encryption algorithm specified
	ikeSAKey.EncrInfo = nil
	err = encryptMsg(ikeMsg, ikeSAKey, message.Role_Initiator)
	require.Error(t, err)

	ikeSAKey.EncrInfo = encryptionAlgorithm

	// No responder's integrity key
	ikeSAKey.Integ_r = nil
	err = encryptMsg(ikeMsg, ikeSAKey, message.Role_Initiator)
	require.Error(t, err)

	ikeSAKey.Integ_r = integ_r

	// No responder's encryption key
	ikeSAKey.Encr_r = nil
	err = encryptMsg(ikeMsg, ikeSAKey, message.Role_Initiator)
	require.Error(t, err)

	// Successful encryption with nil payload
	iv, err = hex.DecodeString("95b0f4844980f4aa28861a0f11253061")
	require.NoError(t, err)

	padding, err = hex.DecodeString("b78db03d231f014db091cb5214ed7b0f")
	require.NoError(t, err)

	sk_ei, err = hex.DecodeString(
		"3d3c6a1f1c693acf223aedf30ac81ae4fcd21c7e6fcefdd74280842d7feefd10")
	require.NoError(t, err)
	block, err = aes.NewCipher(sk_ei)
	require.NoError(t, err)
	ikeSAKey.Encr_i = &encr.ENCR_AES_CBC_Crypto{
		Block:   block,
		Iv:      iv,
		Padding: padding,
	}

	sk_er, err = hex.DecodeString(
		"577462e5d72cced94747c2742866d3ec5ed2ca53cf05eb59bfb88998a66c279a")
	require.NoError(t, err)
	block, err = aes.NewCipher(sk_er)
	require.NoError(t, err)
	ikeSAKey.Encr_r = &encr.ENCR_AES_CBC_Crypto{
		Block:   block,
		Iv:      iv,
		Padding: padding,
	}

	sk_ai, err = hex.DecodeString(
		"89a2b8789cc33333b01d26eaf4529f22a3420e24")
	require.NoError(t, err)
	ikeSAKey.Integ_i = ikeSAKey.IntegInfo.Init(sk_ai)

	sk_ar, err = hex.DecodeString(
		"02f3ce7b78d16bd12b9f0b462ea823b9c67cc824")
	require.NoError(t, err)
	ikeSAKey.Integ_r = ikeSAKey.IntegInfo.Init(sk_ar)
	ikeMsg = &message.IKEMessage{
		IKEHeader: &message.IKEHeader{
			InitiatorSPI: 0x172eb78b61479973,
			ResponderSPI: 0x7fff512ecf965300,
			NextPayload:  uint8(message.NoNext),
			MajorVersion: 0x2,
			MinorVersion: 0x0,
			ExchangeType: message.INFORMATIONAL,
			Flags:        0x08,
			MessageID:    0x02,
		},
		Payloads: message.IKEPayloadContainer{},
	}
	err = encryptMsg(ikeMsg, ikeSAKey, message.Role_Initiator)
	require.NoError(t, err)

	nilPayload := message.IKEPayloadContainer{
		&message.Encrypted{
			NextPayload: uint8(message.NoNext),
			EncryptedData: []byte{
				0x95, 0xb0, 0xf4, 0x84, 0x49, 0x80, 0xf4, 0xaa,
				0x28, 0x86, 0x1a, 0x0f, 0x11, 0x25, 0x30, 0x61,
				0xf2, 0x6c, 0x08, 0x2f, 0x44, 0x36, 0x8b, 0x76,
				0x94, 0x3f, 0xd6, 0xee, 0x38, 0xe5, 0x48, 0xe8,
				0x90, 0xd8, 0xc6, 0x2f, 0x5e, 0xbe, 0xbd, 0x23,
				0x45, 0x79, 0x3f, 0x7f,
			},
		},
	}
	require.Equal(t, nilPayload[0].(*message.Encrypted).EncryptedData,
		ikeMsg.Payloads[0].(*message.Encrypted).EncryptedData)
}

func TestVerifyIntegrity(t *testing.T) {
	tests := []struct {
		name          string
		key           string
		originData    []byte
		checksum      string
		ikeSAKey      *security.IKESAKey
		role          message.Role
		expectedValid bool
	}{
		{
			name:       "HMAC MD5 96 - valid",
			key:        "0123456789abcdef0123456789abcdef",
			originData: []byte("hello world"),
			checksum:   "c30f366e411540f68221d04a",
			ikeSAKey: &security.IKESAKey{
				IntegInfo: integ.StrToType("AUTH_HMAC_MD5_96"),
			},
			role:          message.Role_Responder,
			expectedValid: true,
		},
		{
			name:       "HMAC MD5 96 - invalid checksum",
			key:        "0123456789abcdef0123456789abcdef",
			originData: []byte("hello world"),
			checksum:   "01231875aa",
			ikeSAKey: &security.IKESAKey{
				IntegInfo: integ.StrToType("AUTH_HMAC_MD5_96"),
			},
			role:          message.Role_Responder,
			expectedValid: false,
		},
		{
			name:       "HMAC MD5 96 - invalid key length",
			key:        "0123",
			originData: []byte("hello world"),
			ikeSAKey: &security.IKESAKey{
				IntegInfo: integ.StrToType("AUTH_HMAC_MD5_96"),
			},
			role:          message.Role_Responder,
			expectedValid: false,
		},
		{
			name:       "HMAC SHA1 96 - valid",
			key:        "0123456789abcdef0123456789abcdef01234567",
			originData: []byte("hello world"),
			checksum:   "5089f6a86e4dafb89e3fcd23",
			ikeSAKey: &security.IKESAKey{
				IntegInfo: integ.StrToType("AUTH_HMAC_SHA1_96"),
			},
			role:          message.Role_Initiator,
			expectedValid: true,
		},
		{
			name:       "HMAC SHA1 96 - invalid checksum",
			key:        "0123456789abcdef0123456789abcdef01234567",
			originData: []byte("hello world"),
			checksum:   "01231875aa",
			ikeSAKey: &security.IKESAKey{
				IntegInfo: integ.StrToType("AUTH_HMAC_SHA1_96"),
			},
			role:          message.Role_Initiator,
			expectedValid: false,
		},
		{
			name:       "HMAC SHA1 96 - invalid key length",
			key:        "0123",
			originData: []byte("hello world"),
			ikeSAKey: &security.IKESAKey{
				IntegInfo: integ.StrToType("AUTH_HMAC_SHA1_96"),
			},
			role:          message.Role_Initiator,
			expectedValid: false,
		},
		{
			name:       "HMAC SHA256 128 - valid",
			key:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			originData: []byte("hello world"),
			checksum:   "a64166565bc1f48eb3edd4109fcaeb72",
			ikeSAKey: &security.IKESAKey{
				IntegInfo: integ.StrToType("AUTH_HMAC_SHA2_256_128"),
			},
			role:          message.Role_Initiator,
			expectedValid: true,
		},
		{
			name:       "HMAC SHA256 128 - invalid checksum",
			key:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			originData: []byte("hello world"),
			checksum:   "01231875aa",
			ikeSAKey: &security.IKESAKey{
				IntegInfo: integ.StrToType("AUTH_HMAC_SHA2_256_128"),
			},
			role:          message.Role_Initiator,
			expectedValid: false,
		},
		{
			name:       "HMAC SHA256 128 - invalid key length",
			key:        "0123",
			originData: []byte("hello world"),
			ikeSAKey: &security.IKESAKey{
				IntegInfo: integ.StrToType("AUTH_HMAC_SHA2_256_128"),
			},
			role:          message.Role_Initiator,
			expectedValid: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var key, checksum []byte
			var err error
			checksum, err = hex.DecodeString(tt.checksum)
			require.NoError(t, err, "failed to decode checksum hex string")

			key, err = hex.DecodeString(tt.key)
			require.NoError(t, err, "failed to decode key hex string")

			integ := tt.ikeSAKey.IntegInfo.Init(key)

			if tt.role == message.Role_Initiator {
				tt.ikeSAKey.Integ_i = integ
			} else {
				tt.ikeSAKey.Integ_r = integ
			}

			err = verifyIntegrity(tt.originData, checksum, tt.ikeSAKey, tt.role)
			if tt.expectedValid {
				require.NoError(t, err, "verifyIntegrity returned an error")
			}
		})
	}
}
