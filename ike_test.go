package ike

import (
	"encoding/hex"
	"testing"

	"github.com/free5gc/ike/message"
	"github.com/free5gc/ike/security"
	"github.com/free5gc/ike/security/encr"
	"github.com/free5gc/ike/security/integ"
	logger_util "github.com/free5gc/util/logger"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func newLog() *logrus.Entry {
	fieldsOrder := []string{"component", "category"}
	log := logger_util.New(fieldsOrder)
	return log.WithFields(logrus.Fields{"component": "IKE", "category": "ike"})
}

func TestEncodeDecode(t *testing.T) {
	log := newLog()

	encryptionAlgorithm := encr.StrToType("ENCR_AES_CBC_256")

	integrityAlgorithm := integ.StrToType("AUTH_HMAC_SHA1_96")

	ikeSAKey := &security.IKESAKey{
		ResponderSPI: 0xc9e2e31f8b64053d,
		InitiatorSPI: 0x000000000006f708,
		EncrInfo:     encryptionAlgorithm,
		IntegInfo:    integrityAlgorithm,
	}

	var err error
	ikeSAKey.SK_ei, err = hex.DecodeString(
		"3d7a26417122cee9c77c59f375b024cdb9f0b5777ea18b50f8a671fd3b2daa99")
	require.NoError(t, err)
	ikeSAKey.Encr_i, err = ikeSAKey.EncrInfo.NewCrypto(ikeSAKey.SK_ei)
	require.NoError(t, err)

	ikeSAKey.SK_er, err = hex.DecodeString(
		"3ea57e7ddfb30756a04619a9873333b08e94deef05b6a05d7eb3dba075d81c6f")
	require.NoError(t, err)
	ikeSAKey.Encr_r, err = ikeSAKey.EncrInfo.NewCrypto(ikeSAKey.SK_er)
	require.NoError(t, err)

	ikeSAKey.SK_ai, err = hex.DecodeString(
		"ab8047415535cf53e19a69e2c86feadfebfff1e9")
	require.NoError(t, err)
	ikeSAKey.Integ_i = ikeSAKey.IntegInfo.Init(ikeSAKey.SK_ai)

	ikeSAKey.SK_ar, err = hex.DecodeString(
		"16d5ae6f2859a73a8c7db60bed07e24538b19bb0")
	require.NoError(t, err)
	ikeSAKey.Integ_r = ikeSAKey.IntegInfo.Init(ikeSAKey.SK_ar)

	ikeMessage := &message.IKEMessage{
		ResponderSPI: 0xc9e2e31f8b64053d,
		InitiatorSPI: 0x000000000006f708,
		Version:      0x02,
		ExchangeType: message.IKE_AUTH,
		Flags:        0x08,
		MessageID:    0x03,
	}

	ikePayload := message.IKEPayloadContainer{
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

	ikeMessage.Payloads = append(ikeMessage.Payloads, ikePayload...)

	msg, err := Encode(log, ikeMessage, message.Role_Initiator, ikeSAKey)
	require.NoError(t, err)

	expectedIkeMsg, err := Decode(log, msg, message.Role_Responder, ikeSAKey)
	require.NoError(t, err)

	require.Equal(t, expectedIkeMsg.Payloads, ikePayload)
}

func TestDecryptProcedure(t *testing.T) {
	log := newLog()

	encryptionAlgorithm := encr.StrToType("ENCR_AES_CBC_256")

	integrityAlgorithm := integ.StrToType("AUTH_HMAC_SHA1_96")

	ikeSAKey := &security.IKESAKey{
		ResponderSPI: 0xc9e2e31f8b64053d,
		InitiatorSPI: 0x000000000006f708,
		EncrInfo:     encryptionAlgorithm,
		IntegInfo:    integrityAlgorithm,
	}

	var err error
	sk_ei, err := hex.DecodeString(
		"3d7a26417122cee9c77c59f375b024cdb9f0b5777ea18b50f8a671fd3b2daa99")
	require.NoError(t, err)

	sk_er, err := hex.DecodeString(
		"3ea57e7ddfb30756a04619a9873333b08e94deef05b6a05d7eb3dba075d81c6f")
	require.NoError(t, err)

	sk_ai, err := hex.DecodeString(
		"ab8047415535cf53e19a69e2c86feadfebfff1e9")
	require.NoError(t, err)

	sk_ar, err := hex.DecodeString(
		"16d5ae6f2859a73a8c7db60bed07e24538b19bb0")
	require.NoError(t, err)

	integ_i := ikeSAKey.IntegInfo.Init(sk_ai)
	ikeSAKey.Integ_i = integ_i

	ikeSAKey.Integ_r = ikeSAKey.IntegInfo.Init(sk_ar)

	encr_i, err := ikeSAKey.EncrInfo.NewCrypto(sk_ei)
	require.NoError(t, err)
	ikeSAKey.Encr_i = encr_i

	ikeSAKey.Encr_r, err = ikeSAKey.EncrInfo.NewCrypto(sk_er)
	require.NoError(t, err)

	ikeMessageRawData, err := hex.DecodeString("000000000006f708c9e2e31f8b64053d2e202308000000" +
		"030000006c30000050ec5031162c692fbbfc4d20640c9121ebe9475ef94f9b02959d31242e5" +
		"35e9c3c4dcaecd1bfd6dd80aa812b07de36dee9b7509435f635e1aaae1c3825f4eae3384903f" +
		"724f444170c6845ca80")
	require.NoError(t, err)

	encryptedPayload := &message.Encrypted{
		NextPayload:   message.TypeEAP,
		EncryptedData: []byte{},
	}
	encryptedPayload.EncryptedData, err = hex.DecodeString("ec5031162c692fbbfc4d20640c9121ebe9475ef9" +
		"4f9b02959d31242e535e9c3c4dcaecd1bfd6dd80aa812b07de36dee9b7509435f635e1aaa" +
		"e1c3825f4eae3384903f724f444170c6845ca80")
	require.NoError(t, err)

	// Successful decryption
	decryptedPayload, err := DecryptProcedure(log, message.Role_Responder, ikeSAKey, ikeMessageRawData, encryptedPayload)
	require.NoError(t, err)

	ecpectedDecryptData := message.IKEPayloadContainer{
		&message.EAP{
			Code:        0x02,
			Identifier:  0x3b,
			EAPTypeData: make(message.EAPTypeDataContainer, 1),
		},
	}
	ecpectedDecryptData[0].(*message.EAP).EAPTypeData[0] = &message.EAPExpanded{
		VendorID:   0x28af,
		VendorType: 0x03,
		VendorData: []byte{
			0x02, 0x00, 0x00, 0x00, 0x00, 0x15, 0x7e, 0x00,
			0x57, 0x2d, 0x10, 0xf5, 0x07, 0x36, 0x2e, 0x32,
			0x2d, 0xe3, 0x68, 0x57, 0x93, 0x65, 0xd2, 0x86,
			0x2b, 0x50, 0xed,
		},
	}

	require.Equal(t, ecpectedDecryptData, decryptedPayload)

	// IKE Security Association is nil
	_, err = DecryptProcedure(log, message.Role_Responder, nil, ikeMessageRawData, encryptedPayload)
	require.Error(t, err)

	// IKE Message is nil
	_, err = DecryptProcedure(log, message.Role_Responder, ikeSAKey, nil, encryptedPayload)
	require.Error(t, err)

	// Encrypted Payload is nil
	_, err = DecryptProcedure(log, message.Role_Responder, ikeSAKey, ikeMessageRawData, nil)
	require.Error(t, err)

	// No integrity algorithm specified
	ikeSAKey.IntegInfo = nil
	_, err = DecryptProcedure(log, message.Role_Responder, ikeSAKey, ikeMessageRawData, encryptedPayload)
	require.Error(t, err)

	ikeSAKey.IntegInfo = integrityAlgorithm

	// No initiator's integrity key
	ikeSAKey.Integ_i = nil
	_, err = DecryptProcedure(log, message.Role_Responder, ikeSAKey, ikeMessageRawData, encryptedPayload)
	require.Error(t, err)

	ikeSAKey.Integ_i = integ_i
	// No initiator's encryption key
	ikeSAKey.Encr_i = nil
	_, err = DecryptProcedure(log, message.Role_Responder, ikeSAKey, ikeMessageRawData, encryptedPayload)
	require.Error(t, err, "Expected an error when no initiator's encryption key is provided")

	// Checksum verification fails
	ikeSAKey.Encr_i = encr_i
	invalidEncryptPayload := &message.Encrypted{ // Invalid checksum data
		NextPayload:   message.TypeIDi,
		EncryptedData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13},
	}
	_, err = DecryptProcedure(log, message.Role_Responder, ikeSAKey, ikeMessageRawData, invalidEncryptPayload)
	require.Error(t, err)
}

func TestEncryptProcedure(t *testing.T) {
	log := newLog()

	encryptionAlgorithm := encr.StrToType("ENCR_AES_CBC_256")

	integrityAlgorithm := integ.StrToType("AUTH_HMAC_SHA1_96")

	ikeSAKey := &security.IKESAKey{
		ResponderSPI: 0xc9e2e31f8b64053d,
		InitiatorSPI: 0x000000000006f708,
		EncrInfo:     encryptionAlgorithm,
		IntegInfo:    integrityAlgorithm,
	}

	var err error
	sk_ei, err := hex.DecodeString(
		"3d7a26417122cee9c77c59f375b024cdb9f0b5777ea18b50f8a671fd3b2daa99")
	require.NoError(t, err)
	ikeSAKey.Encr_i, err = ikeSAKey.EncrInfo.NewCrypto(sk_ei)
	require.NoError(t, err)

	sk_er, err := hex.DecodeString(
		"3ea57e7ddfb30756a04619a9873333b08e94deef05b6a05d7eb3dba075d81c6f")
	require.NoError(t, err)
	ikeSAKey.Encr_r, err = ikeSAKey.EncrInfo.NewCrypto(sk_er)
	require.NoError(t, err)

	sk_ai, err := hex.DecodeString(
		"ab8047415535cf53e19a69e2c86feadfebfff1e9")
	require.NoError(t, err)
	ikeSAKey.Integ_i = ikeSAKey.IntegInfo.Init(sk_ai)

	sk_ar, err := hex.DecodeString(
		"16d5ae6f2859a73a8c7db60bed07e24538b19bb0")
	require.NoError(t, err)
	integ_r := ikeSAKey.IntegInfo.Init(sk_ar)
	ikeSAKey.Integ_r = integ_r

	ikeMessage := &message.IKEMessage{
		ResponderSPI: 0xc9e2e31f8b64053d,
		InitiatorSPI: 0x000000000006f708,
		Version:      0x02,
		ExchangeType: message.IKE_AUTH,
		Flags:        0x08,
		MessageID:    0x03,
	}

	ikePayload := message.IKEPayloadContainer{
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

	// Successful encryption
	err = EncryptProcedure(log, message.Role_Initiator, ikeSAKey, ikePayload, ikeMessage)
	require.NoError(t, err)

	rawMsg, err := ikeMessage.Encode(log)
	encryptedPayload := ikeMessage.Payloads[0].(*message.Encrypted)
	expectedPayload, err := DecryptProcedure(log, message.Role_Responder,
		ikeSAKey, rawMsg, encryptedPayload)
	require.Equal(t, expectedPayload, ikePayload)

	// IKE Security Association is nil
	err = EncryptProcedure(log, message.Role_Initiator, nil, ikePayload, ikeMessage)
	require.Error(t, err)

	// No IKE payload to be encrypted
	err = EncryptProcedure(log, message.Role_Initiator, ikeSAKey, message.IKEPayloadContainer{}, ikeMessage)
	require.Error(t, err)

	// Response IKE Message is nil
	err = EncryptProcedure(log, message.Role_Initiator, ikeSAKey, ikePayload, nil)
	require.Error(t, err)

	// No integrity algorithm specified
	ikeSAKey.IntegInfo = nil
	err = EncryptProcedure(log, message.Role_Initiator, ikeSAKey, ikePayload, ikeMessage)
	require.Error(t, err)

	ikeSAKey.IntegInfo = integrityAlgorithm

	// No encryption algorithm specified
	ikeSAKey.EncrInfo = nil
	err = EncryptProcedure(log, message.Role_Initiator, ikeSAKey, ikePayload, ikeMessage)
	require.Error(t, err)

	ikeSAKey.EncrInfo = encryptionAlgorithm

	// No responder's integrity key
	ikeSAKey.Integ_r = nil
	err = EncryptProcedure(log, message.Role_Initiator, ikeSAKey, ikePayload, ikeMessage)
	require.Error(t, err)

	ikeSAKey.Integ_r = integ_r

	// No responder's encryption key
	ikeSAKey.Encr_r = nil
	err = EncryptProcedure(log, message.Role_Initiator, ikeSAKey, ikePayload, ikeMessage)
}

func TestVerifyIntegrity(t *testing.T) {
	log := newLog()

	tests := []struct {
		name          string
		key           string
		originData    []byte
		checksum      string
		ikeSAKey      *security.IKESAKey
		role          bool
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

			valid, err := verifyIntegrity(log, tt.ikeSAKey, tt.role, tt.originData, checksum)
			if tt.expectedValid {
				require.NoError(t, err, "verifyIntegrity returned an error")
			}
			require.Equal(t, tt.expectedValid, valid)
		})
	}
}
