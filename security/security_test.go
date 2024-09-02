package security

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/ike/message"
	"github.com/free5gc/ike/security/dh"
	"github.com/free5gc/ike/security/encr"
	"github.com/free5gc/ike/security/esn"
	"github.com/free5gc/ike/security/integ"
	"github.com/free5gc/ike/security/prf"
	logger_util "github.com/free5gc/util/logger"
)

func newLog() *logrus.Entry {
	fieldsOrder := []string{"component", "category"}
	log := logger_util.New(fieldsOrder)
	return log.WithFields(logrus.Fields{"component": "LIB", "category": "Security"})
}

func TestGenerateRandomNumber(t *testing.T) {
	// Test multiple go routines call function simultaneously
	// create 100 go routines
	wg := sync.WaitGroup{}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(wg *sync.WaitGroup) {
			num, err := GenerateRandomNumber()
			require.NoError(t, err)
			if num == nil {
				fmt.Print("Generate random number failed.")
			} else {
				fmt.Printf("Random number: %v\n", num)
				wg.Done()
			}
		}(&wg)
	}
	wg.Wait()
}

func TestGenerateRandomUint8(t *testing.T) {
	// Test multiple go routines call function simultaneously
	// create 100 go routines
	wg := sync.WaitGroup{}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(wg *sync.WaitGroup) {
			num, err := GenerateRandomUint8()
			if err != nil {
				fmt.Printf("Generate random number failed. Error: %+v", err)
			} else {
				fmt.Printf("Random number: %v\n", num)
				wg.Done()
			}
		}(&wg)
	}
	wg.Wait()
}

func TestConcatenateNonceAndSPI(t *testing.T) {
	correct_result := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0}
	nonce := []byte{0x01, 0x02, 0x03, 0x04}
	ispi := uint64(0x0506070809000102)
	rspi := uint64(0x0304050607080900)
	result := concatenateNonceAndSPI(nonce, ispi, rspi)
	if !bytes.Equal(correct_result, result) {
		t.FailNow()
	}
}

func TestIKEToProposal(t *testing.T) {
	dhType := dh.StrToType("DH_1024_BIT_MODP")
	encrType := encr.StrToType("ENCR_AES_CBC_256")
	integType := integ.StrToType("AUTH_HMAC_MD5_96")
	prfType := prf.StrToType("PRF_HMAC_SHA1")

	ikesaKey := IKESAKey{
		DhInfo:    dhType,
		EncrInfo:  encrType,
		IntegInfo: integType,
		PrfInfo:   prfType,
	}

	proposal := ikesaKey.ToProposal()

	if len(proposal.DiffieHellmanGroup) != 1 ||
		len(proposal.EncryptionAlgorithm) != 1 ||
		len(proposal.IntegrityAlgorithm) != 1 ||
		len(proposal.PseudorandomFunction) != 1 ||
		len(proposal.ExtendedSequenceNumbers) != 0 {
		t.FailNow()
	}
}

func TestIKESetProposal(t *testing.T) {
	dhType := dh.StrToType("DH_1024_BIT_MODP")
	encrType := encr.StrToType("ENCR_AES_CBC_256")
	integType := integ.StrToType("AUTH_HMAC_MD5_96")
	prfType := prf.StrToType("PRF_HMAC_SHA1")

	proposal := new(message.Proposal)

	proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, dh.ToTransform(dhType))
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, encr.ToTransform(encrType))
	proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, integ.ToTransform(integType))
	proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, prf.ToTransform(prfType))

	ikesaKey := new(IKESAKey)

	err := ikesaKey.SetProposal(proposal)
	require.NoError(t, err)

	if ikesaKey.DhInfo == nil ||
		ikesaKey.EncrInfo == nil ||
		ikesaKey.IntegInfo == nil ||
		ikesaKey.PrfInfo == nil {
		t.FailNow()
	}
}

func TestVerifyIntegrity(t *testing.T) {
	log := newLog()

	tests := []struct {
		name          string
		key           string
		originData    []byte
		checksum      string
		ikeSAKey      *IKESAKey
		role          int
		expectedValid bool
	}{
		{
			name:       "HMAC MD5 96 - valid",
			key:        "0123456789abcdef0123456789abcdef",
			originData: []byte("hello world"),
			checksum:   "c30f366e411540f68221d04a",
			ikeSAKey: &IKESAKey{
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
			ikeSAKey: &IKESAKey{
				IntegInfo: integ.StrToType("AUTH_HMAC_MD5_96"),
			},
			role:          message.Role_Responder,
			expectedValid: false,
		},
		{
			name:       "HMAC MD5 96 - invalid key length",
			key:        "0123",
			originData: []byte("hello world"),
			ikeSAKey: &IKESAKey{
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
			ikeSAKey: &IKESAKey{
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
			ikeSAKey: &IKESAKey{
				IntegInfo: integ.StrToType("AUTH_HMAC_SHA1_96"),
			},
			role:          message.Role_Initiator,
			expectedValid: false,
		},
		{
			name:       "HMAC SHA1 96 - invalid key length",
			key:        "0123",
			originData: []byte("hello world"),
			ikeSAKey: &IKESAKey{
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
			ikeSAKey: &IKESAKey{
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
			ikeSAKey: &IKESAKey{
				IntegInfo: integ.StrToType("AUTH_HMAC_SHA2_256_128"),
			},
			role:          message.Role_Initiator,
			expectedValid: false,
		},
		{
			name:       "HMAC SHA256 128 - invalid key length",
			key:        "0123",
			originData: []byte("hello world"),
			ikeSAKey: &IKESAKey{
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
				tt.ikeSAKey.Integ_r = integ
			} else {
				tt.ikeSAKey.Integ_i = integ
			}

			valid, err := verifyIntegrity(log, tt.ikeSAKey, tt.role, tt.originData, checksum)
			if tt.expectedValid {
				require.NoError(t, err, "verifyIntegrity returned an error")
			}
			require.Equal(t, tt.expectedValid, valid)
		})
	}
}

func TestGenerateKeyForIKESA(t *testing.T) {
	log := newLog()

	// IKE Security Association is nil
	var ikesaKey *IKESAKey
	err := ikesaKey.GenerateKeyForIKESA(log)
	require.Error(t, err)

	ikesaKey = &IKESAKey{
		ResponderSPI: 0x123,
		InitiatorSPI: 0x456,
	}

	// Encryption algorithm is nil
	err = ikesaKey.GenerateKeyForIKESA(log)
	require.Error(t, err)

	ikesaKey.EncrInfo = encr.StrToType("ENCR_AES_CBC_256")

	// Integrity algorithm is nil
	err = ikesaKey.GenerateKeyForIKESA(log)
	require.Error(t, err)

	ikesaKey.IntegInfo = integ.StrToType("AUTH_HMAC_SHA1_96")
	// Pseudorandom function is nil
	err = ikesaKey.GenerateKeyForIKESA(log)
	require.Error(t, err)

	ikesaKey.PrfInfo = prf.StrToType("PRF_HMAC_SHA1")
	// Diffie-Hellman group is nil
	err = ikesaKey.GenerateKeyForIKESA(log)
	require.Error(t, err)

	ikesaKey.DhInfo = dh.StrToType("DH_2048_BIT_MODP")
	// Concatenated nonce is nil
	err = ikesaKey.GenerateKeyForIKESA(log)
	require.Error(t, err)

	ikesaKey.ConcatenatedNonce = []byte{0x01, 0x02, 0x03, 0x04}

	// Diffie-Hellman shared key is nil
	err = ikesaKey.GenerateKeyForIKESA(log)
	require.Error(t, err)

	ikesaKey.DiffieHellmanSharedKey = []byte{0x05, 0x06, 0x07, 0x08}

	// Normal case
	err = ikesaKey.GenerateKeyForIKESA(log)
	require.NoError(t, err)

	expectedSK_ai, err := hex.DecodeString("58a17edd463b4b5062359c1c98b1736d80219691")
	require.NoError(t, err)
	expectedInteg_i := ikesaKey.IntegInfo.Init(expectedSK_ai)

	expectedSK_ar, err := hex.DecodeString("eb2e18e9a8f9643ea0d0107a28cf5947ecd1597e")
	require.NoError(t, err)
	ecpectedInteg_r := ikesaKey.IntegInfo.Init(expectedSK_ar)

	expectedSK_ei, err := hex.DecodeString("3dcbcbb2d71d1806d5e5356a5600727eb482101de1868ae9cf71c4117d22cddb")
	require.NoError(t, err)
	ecpectedEncr_i, err := ikesaKey.EncrInfo.NewCrypto(expectedSK_ei)
	require.NoError(t, err)

	expectedSK_er, err := hex.DecodeString("ba3b43cf173435c449f3098c01944f2d9a66c2ca1d967f06a69f36e945a4754b")
	require.NoError(t, err)
	ecpectedEncr_r, err := ikesaKey.EncrInfo.NewCrypto(expectedSK_er)
	require.NoError(t, err)

	expectedSK_pi, err := hex.DecodeString("aff4def6c9113c6942f31fa2d8b74f6c054e0e73")
	require.NoError(t, err)
	ecpectedPrf_i := ikesaKey.PrfInfo.Init(expectedSK_pi)

	expectedSK_pr, err := hex.DecodeString("c06bd0c0dd3e0b3f9c5b4cbe35c88fdd3948430f")
	require.NoError(t, err)
	ecpectedPrf_r := ikesaKey.PrfInfo.Init(expectedSK_pr)

	expectedSK_d, err := hex.DecodeString("276e1a8f0d65dae5309da66277ff7c82d39a8956")
	require.NoError(t, err)
	expectedPrf_d := ikesaKey.PrfInfo.Init(expectedSK_d)

	require.Equal(t, expectedPrf_d, ikesaKey.Prf_d, "SK_d does not match expected value")
	require.Equal(t, expectedInteg_i, ikesaKey.Integ_i, "SK_ai does not match expected value")
	require.Equal(t, ecpectedInteg_r, ikesaKey.Integ_r, "SK_ar does not match expected value")
	require.Equal(t, ecpectedEncr_i, ikesaKey.Encr_i, "SK_ei does not match expected value")
	require.Equal(t, ecpectedEncr_r, ikesaKey.Encr_r, "SK_er does not match expected value")
	require.Equal(t, ecpectedPrf_i, ikesaKey.Prf_i, "SK_pi does not match expected value")
	require.Equal(t, ecpectedPrf_r, ikesaKey.Prf_r, "SK_pr does not match expected value")
}

func TestGenerateKeyForChildSA(t *testing.T) {
	// IKE Security Association is nil
	childSAKey := &ChildSAKey{}
	err := childSAKey.GenerateKeyForChildSA(nil)
	require.Error(t, err)

	ikeSAKey := &IKESAKey{
		ResponderSPI: 0x123,
		InitiatorSPI: 0x456,
	}

	// Child SecurityAssociation is nil
	var c *ChildSAKey
	err = c.GenerateKeyForChildSA(ikeSAKey)
	require.Error(t, err)

	// Pseudorandom function is nil
	err = childSAKey.GenerateKeyForChildSA(ikeSAKey)
	require.Error(t, err)

	ikeSAKey.PrfInfo = prf.StrToType("PRF_HMAC_SHA1")

	// Encryption algorithm is nil
	err = childSAKey.GenerateKeyForChildSA(ikeSAKey)
	require.Error(t, err)

	childSAKey.EncrKInfo = encr.StrToKType("ENCR_AES_CBC_256")
	childSAKey.IntegKInfo = integ.StrToKType("AUTH_HMAC_SHA1_96")

	// Deriving key is nil
	err = childSAKey.GenerateKeyForChildSA(ikeSAKey)
	require.Error(t, err)

	sk_d, err := hex.DecodeString("276e1a8f0d65dae5309da66277ff7c82d39a8956")
	require.NoError(t, err)
	ikeSAKey.Prf_d = ikeSAKey.PrfInfo.Init(sk_d)

	err = childSAKey.GenerateKeyForChildSA(ikeSAKey)
	require.NoError(t, err)

	expectedInitiatorToResponderEncryptionKey, err := hex.DecodeString(
		"8adf11fb9c3d575f9aff5ce58c4891533c44026dc537d68dcc8c08d453e9e6df")
	require.NoError(t, err)
	expectedInitiatorToResponderIntegrityKey, err := hex.DecodeString(
		"1a04be51ae650581a546411d2dbe09507e49329f")
	require.NoError(t, err)
	expectedResponderToInitiatorEncryptionKey, err := hex.DecodeString(
		"103318186d2f7837e2d8a28cf375c2552634bd610f5142f30dfb223892cdca13")
	require.NoError(t, err)
	expectedResponderToInitiatorIntegrityKey, err := hex.DecodeString(
		"f3e8e1d3b1e0e1ce731b0d4f84dc05ac9456454c")
	require.NoError(t, err)

	require.Equal(t, expectedInitiatorToResponderEncryptionKey,
		childSAKey.InitiatorToResponderEncryptionKey, "InitiatorToResponderEncryptionKey does not match expected value")
	require.Equal(t, expectedInitiatorToResponderIntegrityKey,
		childSAKey.InitiatorToResponderIntegrityKey, "InitiatorToResponderIntegrityKey does not match expected value")
	require.Equal(t, expectedResponderToInitiatorEncryptionKey,
		childSAKey.ResponderToInitiatorEncryptionKey, "ResponderToInitiatorEncryptionKey does not match expected value")
	require.Equal(t, expectedResponderToInitiatorIntegrityKey,
		childSAKey.ResponderToInitiatorIntegrityKey, "ResponderToInitiatorIntegrityKey does not match expected value")
}

func TestDecryptProcedure(t *testing.T) {
	log := newLog()

	encryptionAlgorithm := encr.StrToType("ENCR_AES_CBC_256")

	integrityAlgorithm := integ.StrToType("AUTH_HMAC_SHA1_96")

	ikeSAKey := &IKESAKey{
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

	msg, err := hex.DecodeString("000000000006f708c9e2e31f8b64053d2e202308000000" +
		"030000006c30000050ec5031162c692fbbfc4d20640c9121ebe9475ef94f9b02959d31242e5" +
		"35e9c3c4dcaecd1bfd6dd80aa812b07de36dee9b7509435f635e1aaae1c3825f4eae3384903f" +
		"724f444170c6845ca80")
	require.NoError(t, err)

	ikeMessage := new(message.IKEMessage)
	err = ikeMessage.Decode(msg)
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
	decryptedPayload, err := DecryptProcedure(log, message.Role_Responder, ikeSAKey, ikeMessage, encryptedPayload)
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
	_, err = DecryptProcedure(log, message.Role_Responder, nil, ikeMessage, encryptedPayload)
	require.Error(t, err)

	// IKE Message is nil
	_, err = DecryptProcedure(log, message.Role_Responder, ikeSAKey, nil, encryptedPayload)
	require.Error(t, err)

	// Encrypted Payload is nil
	_, err = DecryptProcedure(log, message.Role_Responder, ikeSAKey, ikeMessage, nil)
	require.Error(t, err)

	// No integrity algorithm specified
	ikeSAKey.IntegInfo = nil
	_, err = DecryptProcedure(log, message.Role_Responder, ikeSAKey, ikeMessage, encryptedPayload)
	require.Error(t, err)

	ikeSAKey.IntegInfo = integrityAlgorithm

	// No initiator's integrity key
	ikeSAKey.Integ_i = nil
	_, err = DecryptProcedure(log, message.Role_Responder, ikeSAKey, ikeMessage, encryptedPayload)
	require.Error(t, err)

	ikeSAKey.Integ_i = integ_i
	// No initiator's encryption key
	ikeSAKey.Encr_i = nil
	_, err = DecryptProcedure(log, message.Role_Responder, ikeSAKey, ikeMessage, encryptedPayload)
	require.Error(t, err, "Expected an error when no initiator's encryption key is provided")

	// Checksum verification fails
	ikeSAKey.Encr_i = encr_i
	invalidEncryptPayload := &message.Encrypted{ // Invalid checksum data
		NextPayload:   message.TypeIDi,
		EncryptedData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13},
	}
	_, err = DecryptProcedure(log, message.Role_Responder, ikeSAKey, ikeMessage, invalidEncryptPayload)
	require.Error(t, err)
}

func TestEncryptProcedure(t *testing.T) {
	encryptionAlgorithm := encr.StrToType("ENCR_AES_CBC_256")

	integrityAlgorithm := integ.StrToType("AUTH_HMAC_SHA1_96")

	ikeSAKey := &IKESAKey{
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

	// ikeSAKey.SK_er = sk_er
	// ikeSAKey.SK_ar = sk_ar

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
			Code:        0x02,
			Identifier:  0x3b,
			EAPTypeData: make(message.EAPTypeDataContainer, 1),
		},
	}
	ikePayload[0].(*message.EAP).EAPTypeData[0] = &message.EAPExpanded{
		VendorID:   0x28af,
		VendorType: 0x03,
		VendorData: []byte{
			0x02, 0x00, 0x00, 0x00, 0x00, 0x15, 0x7e, 0x00,
			0x57, 0x2d, 0x10, 0xf5, 0x07, 0x36, 0x2e, 0x32,
			0x2d, 0xe3, 0x68, 0x57, 0x93, 0x65, 0xd2, 0x86,
			0x2b, 0x50, 0xed,
		},
	}

	// Successful encryption
	err = EncryptProcedure(message.Role_Responder, ikeSAKey, ikePayload, ikeMessage)
	require.NoError(t, err)

	// IKE Security Association is nil
	err = EncryptProcedure(message.Role_Responder, nil, ikePayload, ikeMessage)
	require.Error(t, err)

	// No IKE payload to be encrypted
	err = EncryptProcedure(message.Role_Responder, ikeSAKey, message.IKEPayloadContainer{}, ikeMessage)
	require.Error(t, err)

	// Response IKE Message is nil
	err = EncryptProcedure(message.Role_Responder, ikeSAKey, ikePayload, nil)
	require.Error(t, err)

	// No integrity algorithm specified
	ikeSAKey.IntegInfo = nil
	err = EncryptProcedure(message.Role_Responder, ikeSAKey, ikePayload, ikeMessage)
	require.Error(t, err)

	ikeSAKey.IntegInfo = integrityAlgorithm

	// No encryption algorithm specified
	ikeSAKey.EncrInfo = nil
	err = EncryptProcedure(message.Role_Responder, ikeSAKey, ikePayload, ikeMessage)
	require.Error(t, err)

	ikeSAKey.EncrInfo = encryptionAlgorithm

	// No responder's integrity key
	ikeSAKey.Integ_r = nil
	err = EncryptProcedure(message.Role_Responder, ikeSAKey, ikePayload, ikeMessage)
	require.Error(t, err)

	ikeSAKey.Integ_r = integ_r

	// No responder's encryption key
	ikeSAKey.Encr_r = nil
	err = EncryptProcedure(message.Role_Responder, ikeSAKey, ikePayload, ikeMessage)
	t.Logf("err : %v", err)
	require.Error(t, err)
}

func TestChildToProposal(t *testing.T) {
	dhType := dh.StrToType("DH_1024_BIT_MODP")
	encrKType := encr.StrToKType("ENCR_AES_CBC_256")
	integKType := integ.StrToKType("AUTH_HMAC_MD5_96")
	esnType := esn.StrToType("ESN_ENABLE")

	childsaKey := ChildSAKey{
		DhInfo:     dhType,
		EncrKInfo:  encrKType,
		IntegKInfo: integKType,
		EsnInfo:    esnType,
	}

	proposal := childsaKey.ToProposal()

	if len(proposal.DiffieHellmanGroup) != 1 ||
		len(proposal.EncryptionAlgorithm) != 1 ||
		len(proposal.IntegrityAlgorithm) != 1 ||
		len(proposal.PseudorandomFunction) != 0 ||
		len(proposal.ExtendedSequenceNumbers) != 1 {
		t.FailNow()
	}
}

func TestChildSetProposal(t *testing.T) {
	dhType := dh.StrToType("DH_1024_BIT_MODP")
	encrKType := encr.StrToKType("ENCR_AES_CBC_256")
	integKType := integ.StrToKType("AUTH_HMAC_MD5_96")
	esnType := esn.StrToType("ESN_ENABLE")

	proposal := new(message.Proposal)

	proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, dh.ToTransform(dhType))
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, encr.ToTransformChildSA(encrKType))
	proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, integ.ToTransformChildSA(integKType))
	proposal.ExtendedSequenceNumbers = append(proposal.ExtendedSequenceNumbers, esn.ToTransform(esnType))

	childsaKey := new(ChildSAKey)

	childsaKey.SetProposal(proposal)

	if childsaKey.DhInfo == nil ||
		childsaKey.EncrKInfo == nil ||
		childsaKey.IntegKInfo == nil ||
		childsaKey.EsnInfo == nil {
		t.FailNow()
	}
}
