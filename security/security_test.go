package security

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/ike/message"
	"github.com/free5gc/ike/security/dh"
	"github.com/free5gc/ike/security/encr"
	"github.com/free5gc/ike/security/esn"
	"github.com/free5gc/ike/security/integ"
	"github.com/free5gc/ike/security/prf"
	"github.com/free5gc/ike/types"
)

func TestGenerateRandomNumber(t *testing.T) {
	// Test multiple go routines call function simultaneously
	// create 100 go routines
	wg := sync.WaitGroup{}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(wg *sync.WaitGroup) {
			num := GenerateRandomNumber()
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

func TestIKESelectProposal(t *testing.T) {
	// Types' pointers
	dhType1 := dh.StrToType("DH_1024_BIT_MODP")
	dhType2 := dh.StrToType("DH_2048_BIT_MODP")
	// encrType1 := encr.StrToType("ENCR_AES_CBC_128")
	// encrType2 := encr.StrToType("ENCR_AES_CBC_192")
	encrType3 := encr.StrToType("ENCR_AES_CBC_256")
	// integType1 := integ.StrToType("AUTH_HMAC_MD5_96")
	integType2 := integ.StrToType("AUTH_HMAC_SHA1_96")
	// prfType1 := prf.StrToType("PRF_HMAC_MD5")
	prfType2 := prf.StrToType("PRF_HMAC_SHA1")

	// Transforms
	t1 := &message.Transform{
		TransformType:    types.TypeDiffieHellmanGroup,
		TransformID:      types.DH_1024_BIT_MODP,
		AttributePresent: false,
	}
	t2 := &message.Transform{
		TransformType:    types.TypeDiffieHellmanGroup,
		TransformID:      types.DH_2048_BIT_MODP,
		AttributePresent: false,
	}
	t3 := &message.Transform{
		TransformType:    types.TypeDiffieHellmanGroup,
		TransformID:      types.DH_1536_BIT_MODP,
		AttributePresent: false,
	}
	t4 := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_AES_CBC,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   128,
	}
	t5 := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_AES_CBC,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   192,
	}
	t6 := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_AES_CBC,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   256,
	}
	t7 := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_AES_CBC,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   384,
	}
	t8 := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_3DES,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   128,
	}
	t9 := &message.Transform{
		TransformType:    types.TypeIntegrityAlgorithm,
		TransformID:      types.AUTH_HMAC_MD5_96,
		AttributePresent: false,
	}
	t10 := &message.Transform{
		TransformType:    types.TypeIntegrityAlgorithm,
		TransformID:      types.AUTH_HMAC_SHA1_96,
		AttributePresent: false,
	}
	t11 := &message.Transform{
		TransformType:    types.TypeIntegrityAlgorithm,
		TransformID:      types.AUTH_DES_MAC,
		AttributePresent: false,
	}
	t12 := &message.Transform{
		TransformType:    types.TypePseudorandomFunction,
		TransformID:      types.PRF_HMAC_MD5,
		AttributePresent: false,
	}
	t13 := &message.Transform{
		TransformType:    types.TypePseudorandomFunction,
		TransformID:      types.PRF_HMAC_SHA1,
		AttributePresent: false,
	}
	t14 := &message.Transform{
		TransformType:    types.TypePseudorandomFunction,
		TransformID:      types.PRF_HMAC_TIGER,
		AttributePresent: false,
	}
	t15 := &message.Transform{
		TransformType:    types.TypeExtendedSequenceNumbers,
		TransformID:      types.ESN_ENABLE,
		AttributePresent: false,
	}

	// Proposal 1
	proposal := new(message.Proposal)
	proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, t3)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t7)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t8)
	proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, t9)
	proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, t13)

	var Propsoals message.ProposalContainer
	Propsoals = append(Propsoals, proposal)
	chooseProposal := SelectProposal(Propsoals)
	require.False(t, len(chooseProposal) > 0)

	// Proposal 2
	proposal = new(message.Proposal)
	proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, t1)
	proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, t2)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t4)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t5)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t6)
	proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, t10)
	proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, t11)
	proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, t12)
	proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, t13)
	proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, t14)

	Propsoals = nil
	Propsoals = append(Propsoals, proposal)
	chooseProposal = SelectProposal(Propsoals)
	require.False(t, len(chooseProposal) == 0)

	ikesa := new(IKESA)
	err := ikesa.SetProposal(chooseProposal[0])
	require.NoError(t, err)

	if ikesa.dhInfo != dhType2 || ikesa.encrInfo != encrType3 ||
		ikesa.integInfo != integType2 || ikesa.prfInfo != prfType2 {
		t.Fatal("SelectProposal selected a false result")
	}

	newPriority := map[string]uint32{
		"DH_1024_BIT_MODP": 1,
		"DH_2048_BIT_MODP": 0,
	}
	if err = dh.SetPriority(newPriority); err != nil {
		t.Fatalf("Set priority failed: %v", err)
	}

	Propsoals = nil
	Propsoals = append(Propsoals, proposal)
	chooseProposal = SelectProposal(Propsoals)
	require.False(t, len(chooseProposal) == 0)

	ikesa = new(IKESA)
	err = ikesa.SetProposal(chooseProposal[0])
	require.NoError(t, err)

	if ikesa.dhInfo != dhType1 || ikesa.encrInfo != encrType3 ||
		ikesa.integInfo != integType2 || ikesa.prfInfo != prfType2 {
		t.Fatal("SelectProposal selected a false result")
	}

	// reset priority
	newPriority = map[string]uint32{
		"DH_1024_BIT_MODP": 0,
		"DH_2048_BIT_MODP": 1,
	}
	if err = dh.SetPriority(newPriority); err != nil {
		t.Fatalf("Set priority failed: %v", err)
	}

	// Proposal 3
	proposal = new(message.Proposal)

	Propsoals = nil
	Propsoals = append(Propsoals, proposal)
	chooseProposal = SelectProposal(Propsoals)
	require.False(t, len(chooseProposal) > 0)

	// Proposal 4
	proposal = new(message.Proposal)
	proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, t2)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t5)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t6)
	proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, t9)
	proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, t13)
	proposal.ExtendedSequenceNumbers = append(proposal.ExtendedSequenceNumbers, t15)

	Propsoals = nil
	Propsoals = append(Propsoals, proposal)
	chooseProposal = SelectProposal(Propsoals)
	require.False(t, len(chooseProposal) > 0)
}

func TestIKEToProposal(t *testing.T) {
	dhType := dh.StrToType("DH_1024_BIT_MODP")
	encrType := encr.StrToType("ENCR_AES_CBC_256")
	integType := integ.StrToType("AUTH_HMAC_MD5_96")
	prfType := prf.StrToType("PRF_HMAC_SHA1")

	ikesa := IKESA{
		dhInfo:    dhType,
		encrInfo:  encrType,
		integInfo: integType,
		prfInfo:   prfType,
	}

	proposal := ikesa.ToProposal()

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

	ikesa := new(IKESA)

	err := ikesa.SetProposal(proposal)
	require.NoError(t, err)

	if ikesa.dhInfo == nil ||
		ikesa.encrInfo == nil ||
		ikesa.integInfo == nil ||
		ikesa.prfInfo == nil {
		t.FailNow()
	}
}

func TestVerifyIntegrity(t *testing.T) {
	tests := []struct {
		name          string
		key           string
		originData    []byte
		checksum      string
		ikeSA         *IKESA
		role          int
		expectedValid bool
	}{
		{
			name:       "HMAC MD5 96 - valid",
			key:        "0123456789abcdef0123456789abcdef",
			originData: []byte("hello world"),
			checksum:   "c30f366e411540f68221d04a",
			ikeSA: &IKESA{
				integInfo: integ.StrToType("AUTH_HMAC_MD5_96"),
			},
			role:          types.Role_Responder,
			expectedValid: true,
		},
		{
			name:       "HMAC MD5 96 - invalid checksum",
			key:        "0123456789abcdef0123456789abcdef",
			originData: []byte("hello world"),
			checksum:   "01231875aa",
			ikeSA: &IKESA{
				integInfo: integ.StrToType("AUTH_HMAC_MD5_96"),
			},
			role:          types.Role_Responder,
			expectedValid: false,
		},
		{
			name:       "HMAC MD5 96 - invalid key length",
			key:        "0123",
			originData: []byte("hello world"),
			ikeSA: &IKESA{
				integInfo: integ.StrToType("AUTH_HMAC_MD5_96"),
			},
			role:          types.Role_Responder,
			expectedValid: false,
		},
		{
			name:       "HMAC SHA1 96 - valid",
			key:        "0123456789abcdef0123456789abcdef01234567",
			originData: []byte("hello world"),
			checksum:   "5089f6a86e4dafb89e3fcd23",
			ikeSA: &IKESA{
				integInfo: integ.StrToType("AUTH_HMAC_SHA1_96"),
			},
			role:          types.Role_Initiator,
			expectedValid: true,
		},
		{
			name:       "HMAC SHA1 96 - invalid checksum",
			key:        "0123456789abcdef0123456789abcdef01234567",
			originData: []byte("hello world"),
			checksum:   "01231875aa",
			ikeSA: &IKESA{
				integInfo: integ.StrToType("AUTH_HMAC_SHA1_96"),
			},
			role:          types.Role_Initiator,
			expectedValid: false,
		},
		{
			name:       "HMAC SHA1 96 - invalid key length",
			key:        "0123",
			originData: []byte("hello world"),
			ikeSA: &IKESA{
				integInfo: integ.StrToType("AUTH_HMAC_SHA1_96"),
			},
			role:          types.Role_Initiator,
			expectedValid: false,
		},
		{
			name:       "HMAC SHA256 128 - valid",
			key:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			originData: []byte("hello world"),
			checksum:   "a64166565bc1f48eb3edd4109fcaeb72",
			ikeSA: &IKESA{
				integInfo: integ.StrToType("AUTH_HMAC_SHA2_256_128"),
			},
			role:          types.Role_Initiator,
			expectedValid: true,
		},
		{
			name:       "HMAC SHA256 128 - invalid checksum",
			key:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			originData: []byte("hello world"),
			checksum:   "01231875aa",
			ikeSA: &IKESA{
				integInfo: integ.StrToType("AUTH_HMAC_SHA2_256_128"),
			},
			role:          types.Role_Initiator,
			expectedValid: false,
		},
		{
			name:       "HMAC SHA256 128 - invalid key length",
			key:        "0123",
			originData: []byte("hello world"),
			ikeSA: &IKESA{
				integInfo: integ.StrToType("AUTH_HMAC_SHA2_256_128"),
			},
			role:          types.Role_Initiator,
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

			integ := tt.ikeSA.integInfo.Init(key)

			if tt.role == types.Role_Initiator {
				tt.ikeSA.Integ_r = integ
			} else {
				tt.ikeSA.Integ_i = integ
			}

			valid, err := tt.ikeSA.verifyIntegrity(tt.role, tt.originData, checksum)
			if tt.expectedValid {
				require.NoError(t, err, "verifyIntegrity returned an error")
			}
			require.Equal(t, tt.expectedValid, valid)
		})
	}
}

func TestGenerateKeyForIKESA(t *testing.T) {
	// IKE Security Association is nil
	var ikesa *IKESA
	err := ikesa.GenerateKeyForIKESA()
	require.Error(t, err)

	ikesa = &IKESA{
		ResponderSPI: 0x123,
		InitiatorSPI: 0x456,
	}

	// Encryption algorithm is nil
	err = ikesa.GenerateKeyForIKESA()
	require.Error(t, err)

	ikesa.encrInfo = encr.StrToType("ENCR_AES_CBC_256")

	// Integrity algorithm is nil
	err = ikesa.GenerateKeyForIKESA()
	require.Error(t, err)

	ikesa.integInfo = integ.StrToType("AUTH_HMAC_SHA1_96")
	// Pseudorandom function is nil
	err = ikesa.GenerateKeyForIKESA()
	require.Error(t, err)

	ikesa.prfInfo = prf.StrToType("PRF_HMAC_SHA1")
	// Diffie-Hellman group is nil
	err = ikesa.GenerateKeyForIKESA()
	require.Error(t, err)

	ikesa.dhInfo = dh.StrToType("DH_2048_BIT_MODP")
	// Concatenated nonce is nil
	err = ikesa.GenerateKeyForIKESA()
	require.Error(t, err)

	ikesa.ConcatenatedNonce = []byte{0x01, 0x02, 0x03, 0x04}

	// Diffie-Hellman shared key is nil
	err = ikesa.GenerateKeyForIKESA()
	require.Error(t, err)

	ikesa.DiffieHellmanSharedKey = []byte{0x05, 0x06, 0x07, 0x08}

	// Normal case
	err = ikesa.GenerateKeyForIKESA()
	require.NoError(t, err)

	expectedSK_ai, err := hex.DecodeString("58a17edd463b4b5062359c1c98b1736d80219691")
	require.NoError(t, err)
	expectedInteg_i := ikesa.integInfo.Init(expectedSK_ai)

	expectedSK_ar, err := hex.DecodeString("eb2e18e9a8f9643ea0d0107a28cf5947ecd1597e")
	require.NoError(t, err)
	ecpectedInteg_r := ikesa.integInfo.Init(expectedSK_ar)

	expectedSK_ei, err := hex.DecodeString("3dcbcbb2d71d1806d5e5356a5600727eb482101de1868ae9cf71c4117d22cddb")
	require.NoError(t, err)
	ecpectedEncr_i, err := ikesa.encrInfo.Init(expectedSK_ei)
	require.NoError(t, err)

	expectedSK_er, err := hex.DecodeString("ba3b43cf173435c449f3098c01944f2d9a66c2ca1d967f06a69f36e945a4754b")
	require.NoError(t, err)
	ecpectedEncr_r, err := ikesa.encrInfo.Init(expectedSK_er)
	require.NoError(t, err)

	expectedSK_pi, err := hex.DecodeString("aff4def6c9113c6942f31fa2d8b74f6c054e0e73")
	require.NoError(t, err)
	ecpectedPrf_i := ikesa.prfInfo.Init(expectedSK_pi)

	expectedSK_pr, err := hex.DecodeString("c06bd0c0dd3e0b3f9c5b4cbe35c88fdd3948430f")
	require.NoError(t, err)
	ecpectedPrf_r := ikesa.prfInfo.Init(expectedSK_pr)

	expectedSK_d, err := hex.DecodeString("276e1a8f0d65dae5309da66277ff7c82d39a8956")
	require.NoError(t, err)
	expectedPrf_d := ikesa.prfInfo.Init(expectedSK_d)

	require.Equal(t, expectedPrf_d, ikesa.Prf_d, "SK_d does not match expected value")
	require.Equal(t, expectedInteg_i, ikesa.Integ_i, "SK_ai does not match expected value")
	require.Equal(t, ecpectedInteg_r, ikesa.Integ_r, "SK_ar does not match expected value")
	require.Equal(t, ecpectedEncr_i, ikesa.Encr_i, "SK_ei does not match expected value")
	require.Equal(t, ecpectedEncr_r, ikesa.Encr_r, "SK_er does not match expected value")
	require.Equal(t, ecpectedPrf_i, ikesa.Prf_i, "SK_pi does not match expected value")
	require.Equal(t, ecpectedPrf_r, ikesa.Prf_r, "SK_pr does not match expected value")
}

func TestGenerateKeyForChildSA(t *testing.T) {
	// IKE Security Association is nil
	childSA := &ChildSA{}
	err := childSA.GenerateKeyForChildSA(nil)
	require.Error(t, err)

	ikeSA := &IKESA{
		ResponderSPI: 0x123,
		InitiatorSPI: 0x456,
	}

	// Child SecurityAssociation is nil
	var c *ChildSA
	err = c.GenerateKeyForChildSA(ikeSA)
	require.Error(t, err)

	// Pseudorandom function is nil
	err = childSA.GenerateKeyForChildSA(ikeSA)
	require.Error(t, err)

	ikeSA.prfInfo = prf.StrToType("PRF_HMAC_SHA1")

	// Encryption algorithm is nil
	err = childSA.GenerateKeyForChildSA(ikeSA)
	require.Error(t, err)

	childSA.encrKInfo = encr.StrToKType("ENCR_AES_CBC_256")
	childSA.integKInfo = integ.StrToKType("AUTH_HMAC_SHA1_96")

	// Deriving key is nil
	err = childSA.GenerateKeyForChildSA(ikeSA)
	require.Error(t, err)

	sk_d, err := hex.DecodeString("276e1a8f0d65dae5309da66277ff7c82d39a8956")
	require.NoError(t, err)
	ikeSA.Prf_d = ikeSA.prfInfo.Init(sk_d)

	err = childSA.GenerateKeyForChildSA(ikeSA)
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
		childSA.InitiatorToResponderEncryptionKey, "InitiatorToResponderEncryptionKey does not match expected value")
	require.Equal(t, expectedInitiatorToResponderIntegrityKey,
		childSA.InitiatorToResponderIntegrityKey, "InitiatorToResponderIntegrityKey does not match expected value")
	require.Equal(t, expectedResponderToInitiatorEncryptionKey,
		childSA.ResponderToInitiatorEncryptionKey, "ResponderToInitiatorEncryptionKey does not match expected value")
	require.Equal(t, expectedResponderToInitiatorIntegrityKey,
		childSA.ResponderToInitiatorIntegrityKey, "ResponderToInitiatorIntegrityKey does not match expected value")
}

func TestDecryptProcedure(t *testing.T) {
	encryptionAlgorithm := encr.StrToType("ENCR_AES_CBC_256")

	integrityAlgorithm := integ.StrToType("AUTH_HMAC_SHA1_96")

	ikeSA := &IKESA{
		ResponderSPI: 0xc9e2e31f8b64053d,
		InitiatorSPI: 0x000000000006f708,
		encrInfo:     encryptionAlgorithm,
		integInfo:    integrityAlgorithm,
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

	integ_i := ikeSA.integInfo.Init(sk_ai)
	ikeSA.Integ_i = integ_i

	ikeSA.Integ_r = ikeSA.integInfo.Init(sk_ar)

	encr_i, err := ikeSA.encrInfo.Init(sk_ei)
	require.NoError(t, err)
	ikeSA.Encr_i = encr_i

	ikeSA.Encr_r, err = ikeSA.encrInfo.Init(sk_er)
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
		NextPayload:   types.TypeEAP,
		EncryptedData: []byte{},
	}
	encryptedPayload.EncryptedData, err = hex.DecodeString("ec5031162c692fbbfc4d20640c9121ebe9475ef9" +
		"4f9b02959d31242e535e9c3c4dcaecd1bfd6dd80aa812b07de36dee9b7509435f635e1aaa" +
		"e1c3825f4eae3384903f724f444170c6845ca80")
	require.NoError(t, err)

	// Successful decryption
	decryptedPayload, err := ikeSA.DecryptProcedure(types.Role_Responder, ikeMessage, encryptedPayload)
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
	var ikesa *IKESA
	_, err = ikesa.DecryptProcedure(types.Role_Responder, ikeMessage, encryptedPayload)
	require.Error(t, err)

	// IKE Message is nil
	_, err = ikesa.DecryptProcedure(types.Role_Responder, nil, encryptedPayload)
	require.Error(t, err)

	// Encrypted Payload is nil
	_, err = ikesa.DecryptProcedure(types.Role_Responder, ikeMessage, nil)
	require.Error(t, err)

	// No integrity algorithm specified
	ikeSA.integInfo = nil
	_, err = ikeSA.DecryptProcedure(types.Role_Responder, ikeMessage, encryptedPayload)
	require.Error(t, err)

	ikeSA.integInfo = integrityAlgorithm

	// No initiator's integrity key
	ikeSA.Integ_i = nil
	_, err = ikeSA.DecryptProcedure(types.Role_Responder, ikeMessage, encryptedPayload)
	require.Error(t, err)

	ikeSA.Integ_i = integ_i
	// No initiator's encryption key
	ikeSA.Encr_i = nil
	_, err = ikeSA.DecryptProcedure(types.Role_Responder, ikeMessage, encryptedPayload)
	require.Error(t, err, "Expected an error when no initiator's encryption key is provided")

	// Checksum verification fails
	ikeSA.Encr_i = encr_i
	invalidEncryptPayload := &message.Encrypted{ // Invalid checksum data
		NextPayload:   types.TypeIDi,
		EncryptedData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13},
	}
	_, err = ikeSA.DecryptProcedure(types.Role_Responder, ikeMessage, invalidEncryptPayload)
	require.Error(t, err)
}

func TestEncryptProcedure(t *testing.T) {
	encryptionAlgorithm := encr.StrToType("ENCR_AES_CBC_256")

	integrityAlgorithm := integ.StrToType("AUTH_HMAC_SHA1_96")

	ikeSA := &IKESA{
		ResponderSPI: 0xc9e2e31f8b64053d,
		InitiatorSPI: 0x000000000006f708,
		encrInfo:     encryptionAlgorithm,
		integInfo:    integrityAlgorithm,
	}

	var err error
	sk_ei, err := hex.DecodeString(
		"3d7a26417122cee9c77c59f375b024cdb9f0b5777ea18b50f8a671fd3b2daa99")
	require.NoError(t, err)
	ikeSA.Encr_i, err = ikeSA.encrInfo.Init(sk_ei)
	require.NoError(t, err)

	sk_er, err := hex.DecodeString(
		"3ea57e7ddfb30756a04619a9873333b08e94deef05b6a05d7eb3dba075d81c6f")
	require.NoError(t, err)
	ikeSA.Encr_r, err = ikeSA.encrInfo.Init(sk_er)
	require.NoError(t, err)

	sk_ai, err := hex.DecodeString(
		"ab8047415535cf53e19a69e2c86feadfebfff1e9")
	require.NoError(t, err)
	ikeSA.Integ_i = ikeSA.integInfo.Init(sk_ai)

	sk_ar, err := hex.DecodeString(
		"16d5ae6f2859a73a8c7db60bed07e24538b19bb0")
	require.NoError(t, err)
	integ_r := ikeSA.integInfo.Init(sk_ar)
	ikeSA.Integ_r = integ_r

	// ikeSA.SK_er = sk_er
	// ikeSA.SK_ar = sk_ar

	ikeMessage := &message.IKEMessage{
		ResponderSPI: 0xc9e2e31f8b64053d,
		InitiatorSPI: 0x000000000006f708,
		Version:      0x02,
		ExchangeType: types.IKE_AUTH,
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
	err = ikeSA.EncryptProcedure(types.Role_Responder, ikePayload, ikeMessage)
	require.NoError(t, err)

	// IKE Security Association is nil
	var ikesa *IKESA
	err = ikesa.EncryptProcedure(types.Role_Responder, ikePayload, ikeMessage)
	require.Error(t, err)

	// No IKE payload to be encrypted
	err = ikeSA.EncryptProcedure(types.Role_Responder, message.IKEPayloadContainer{}, ikeMessage)
	require.Error(t, err)

	// Response IKE Message is nil
	err = ikeSA.EncryptProcedure(types.Role_Responder, ikePayload, nil)
	require.Error(t, err)

	// No integrity algorithm specified
	ikeSA.integInfo = nil
	err = ikeSA.EncryptProcedure(types.Role_Responder, ikePayload, ikeMessage)
	require.Error(t, err)

	ikeSA.integInfo = integrityAlgorithm

	// No encryption algorithm specified
	ikeSA.encrInfo = nil
	err = ikeSA.EncryptProcedure(types.Role_Responder, ikePayload, ikeMessage)
	require.Error(t, err)

	ikeSA.encrInfo = encryptionAlgorithm

	// No responder's integrity key
	ikeSA.Integ_r = nil
	err = ikeSA.EncryptProcedure(types.Role_Responder, ikePayload, ikeMessage)
	require.Error(t, err)

	ikeSA.Integ_r = integ_r

	// No responder's encryption key
	ikeSA.Encr_r = nil
	err = ikeSA.EncryptProcedure(types.Role_Responder, ikePayload, ikeMessage)
	t.Logf("err : %v", err)
	require.Error(t, err)
}

func TestChildSelectProposal(t *testing.T) {
	// Types' pointers
	dhType1 := dh.StrToType("DH_1024_BIT_MODP")
	dhType2 := dh.StrToType("DH_2048_BIT_MODP")
	// encrKType1 := encr.StrToKType("ENCR_AES_CBC_128")
	// encrKType2 := encr.StrToKType("ENCR_AES_CBC_192")
	encrKType3 := encr.StrToKType("ENCR_AES_CBC_256")
	// integKType1 := integ.StrToKType("AUTH_HMAC_MD5_96")
	integKType2 := integ.StrToKType("AUTH_HMAC_SHA1_96")
	// prfType1 := prf.StrToType("PRF_HMAC_MD5")
	// prfType2 := prf.StrToType("PRF_HMAC_SHA1")
	// esnType1 := esn.StrToType("ESN_ENABLE")
	esnType2 := esn.StrToType("ESN_DISABLE")

	// Transforms
	t1 := &message.Transform{
		TransformType:    types.TypeDiffieHellmanGroup,
		TransformID:      types.DH_1024_BIT_MODP,
		AttributePresent: false,
	}
	t2 := &message.Transform{
		TransformType:    types.TypeDiffieHellmanGroup,
		TransformID:      types.DH_2048_BIT_MODP,
		AttributePresent: false,
	}
	t3 := &message.Transform{
		TransformType:    types.TypeDiffieHellmanGroup,
		TransformID:      types.DH_1536_BIT_MODP,
		AttributePresent: false,
	}
	t4 := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_AES_CBC,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   128,
	}
	t5 := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_AES_CBC,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   192,
	}
	t6 := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_AES_CBC,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   256,
	}
	t7 := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_AES_CBC,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   384,
	}
	t8 := &message.Transform{
		TransformType:    types.TypeEncryptionAlgorithm,
		TransformID:      types.ENCR_3DES,
		AttributePresent: true,
		AttributeFormat:  types.AttributeFormatUseTV,
		AttributeType:    types.AttributeTypeKeyLength,
		AttributeValue:   128,
	}
	t9 := &message.Transform{
		TransformType:    types.TypeIntegrityAlgorithm,
		TransformID:      types.AUTH_HMAC_MD5_96,
		AttributePresent: false,
	}
	t10 := &message.Transform{
		TransformType:    types.TypeIntegrityAlgorithm,
		TransformID:      types.AUTH_HMAC_SHA1_96,
		AttributePresent: false,
	}
	t11 := &message.Transform{
		TransformType:    types.TypeIntegrityAlgorithm,
		TransformID:      types.AUTH_DES_MAC,
		AttributePresent: false,
	}
	t12 := &message.Transform{
		TransformType:    types.TypePseudorandomFunction,
		TransformID:      types.PRF_HMAC_MD5,
		AttributePresent: false,
	}
	t13 := &message.Transform{
		TransformType:    types.TypePseudorandomFunction,
		TransformID:      types.PRF_HMAC_SHA1,
		AttributePresent: false,
	}
	t14 := &message.Transform{
		TransformType:    types.TypePseudorandomFunction,
		TransformID:      types.PRF_HMAC_TIGER,
		AttributePresent: false,
	}
	t15 := &message.Transform{
		TransformType:    types.TypeExtendedSequenceNumbers,
		TransformID:      types.ESN_ENABLE,
		AttributePresent: false,
	}
	t16 := &message.Transform{
		TransformType:    types.TypeExtendedSequenceNumbers,
		TransformID:      types.ESN_DISABLE,
		AttributePresent: false,
	}

	// Proposal 1
	proposal := new(message.Proposal)
	proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, t3)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t7)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t8)
	proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, t9)
	proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, t13)

	childsa := new(ChildSA)
	if childsa.SelectProposal(proposal) {
		t.Fatal("SelectProposal returned a false result")
	}

	// Proposal 2
	proposal = new(message.Proposal)
	proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, t1)
	proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, t2)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t4)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t5)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t6)
	proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, t10)
	proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, t11)
	proposal.ExtendedSequenceNumbers = append(proposal.ExtendedSequenceNumbers, t15)
	proposal.ExtendedSequenceNumbers = append(proposal.ExtendedSequenceNumbers, t16)

	childsa = new(ChildSA)
	if !childsa.SelectProposal(proposal) {
		t.Fatal("SelectProposal returned a false result")
	}

	if childsa.dhInfo != dhType2 || childsa.encrKInfo != encrKType3 ||
		childsa.integKInfo != integKType2 || childsa.esnInfo != esnType2 {
		t.Fatal("SelectProposal selected a false result")
	}

	newPriority := map[string]uint32{
		"DH_1024_BIT_MODP": 1,
		"DH_2048_BIT_MODP": 0,
	}
	if err := dh.SetPriority(newPriority); err != nil {
		t.Fatalf("Set priority failed: %v", err)
	}

	childsa = new(ChildSA)
	if !childsa.SelectProposal(proposal) {
		t.Fatal("SelectProposal returned a false result")
	}

	if childsa.dhInfo != dhType1 || childsa.encrKInfo != encrKType3 ||
		childsa.integKInfo != integKType2 || childsa.esnInfo != esnType2 {
		t.Fatal("SelectProposal selected a false result")
	}

	// reset priority
	newPriority = map[string]uint32{
		"DH_1024_BIT_MODP": 0,
		"DH_2048_BIT_MODP": 1,
	}
	if err := dh.SetPriority(newPriority); err != nil {
		t.Fatalf("Set priority failed: %v", err)
	}

	// Proposal 3
	proposal = new(message.Proposal)

	childsa = new(ChildSA)
	if childsa.SelectProposal(proposal) {
		t.Fatal("SelectProposal returned a false result")
	}

	// Proposal 4
	proposal = new(message.Proposal)
	proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, t2)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t5)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t6)
	proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, t9)
	proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, t12)
	proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, t13)
	proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, t14)
	proposal.ExtendedSequenceNumbers = append(proposal.ExtendedSequenceNumbers, t15)

	childsa = new(ChildSA)
	if childsa.SelectProposal(proposal) {
		t.Fatal("SelectProposal returned a false result")
	}

	// Proposal 5
	proposal = new(message.Proposal)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t5)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, t6)
	proposal.ExtendedSequenceNumbers = append(proposal.ExtendedSequenceNumbers, t15)
	proposal.ExtendedSequenceNumbers = append(proposal.ExtendedSequenceNumbers, t16)

	childsa = new(ChildSA)
	if !childsa.SelectProposal(proposal) {
		t.Fatal("SelectProposal returned a false result")
	}

	if childsa.dhInfo != nil || childsa.encrKInfo != encrKType3 ||
		childsa.integKInfo != nil || childsa.esnInfo != esnType2 {
		t.Fatal("SelectProposal selected a false result")
	}
}

func TestChildToProposal(t *testing.T) {
	dhType := dh.StrToType("DH_1024_BIT_MODP")
	encrKType := encr.StrToKType("ENCR_AES_CBC_256")
	integKType := integ.StrToKType("AUTH_HMAC_MD5_96")
	esnType := esn.StrToType("ESN_ENABLE")

	childsa := ChildSA{
		dhInfo:     dhType,
		encrKInfo:  encrKType,
		integKInfo: integKType,
		esnInfo:    esnType,
	}

	proposal := childsa.ToProposal()

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

	childsa := new(ChildSA)

	childsa.SetProposal(proposal)

	if childsa.dhInfo == nil ||
		childsa.encrKInfo == nil ||
		childsa.integKInfo == nil ||
		childsa.esnInfo == nil {
		t.FailNow()
	}
}
