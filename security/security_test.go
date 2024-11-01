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
)

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
	dhType := dh.StrToType("ike_types.DH_1024_BIT_MODP")
	encrType := encr.StrToType("ENCR_AES_CBC_256")
	integType := integ.StrToType("AUTH_HMAC_MD5_96")
	prfType := prf.StrToType("PRF_HMAC_SHA1")

	ikesaKey := IKESAKey{
		DhInfo:    dhType,
		EncrInfo:  encrType,
		IntegInfo: integType,
		PrfInfo:   prfType,
	}

	proposal, err := ikesaKey.ToProposal()
	require.NoError(t, err)

	if len(proposal.DiffieHellmanGroup) != 1 ||
		len(proposal.EncryptionAlgorithm) != 1 ||
		len(proposal.IntegrityAlgorithm) != 1 ||
		len(proposal.PseudorandomFunction) != 1 ||
		len(proposal.ExtendedSequenceNumbers) != 0 {
		t.FailNow()
	}
}

func TestIKESetProposal(t *testing.T) {
	dhType := dh.StrToType("ike_types.DH_1024_BIT_MODP")
	encrType := encr.StrToType("ENCR_AES_CBC_256")
	integType := integ.StrToType("AUTH_HMAC_MD5_96")
	prfType := prf.StrToType("PRF_HMAC_SHA1")

	proposal := new(message.Proposal)

	proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, dh.ToTransform(dhType))
	encrTranform, err := encr.ToTransform(encrType)
	require.NoError(t, err)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, encrTranform)
	proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, integ.ToTransform(integType))
	proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, prf.ToTransform(prfType))

	concatenatedNonce := []byte{0x01, 0x02, 0x03, 0x04}
	keyexChange := []byte{0x05, 0x06, 0x07, 0x08}

	ikesaKey, _, err := NewIKESAKey(proposal, keyexChange, concatenatedNonce,
		0x123, 0x456)
	require.NoError(t, err)

	if ikesaKey.DhInfo == nil ||
		ikesaKey.EncrInfo == nil ||
		ikesaKey.IntegInfo == nil ||
		ikesaKey.PrfInfo == nil {
		t.FailNow()
	}
}

func TestGenerateKeyForIKESA(t *testing.T) {
	concatenatedNonce := []byte{0x01, 0x02, 0x03, 0x04}
	diffieHellmanSharedKey := []byte{0x05, 0x06, 0x07, 0x08}
	initiatorSPI := uint64(0x456)
	responderSPI := uint64(0x123)

	// IKE Security Association is nil
	var ikesaKey *IKESAKey
	err := ikesaKey.GenerateKeyForIKESA(concatenatedNonce, diffieHellmanSharedKey,
		initiatorSPI, responderSPI)
	require.Error(t, err)

	ikesaKey = &IKESAKey{}

	// Encryption algorithm is nil
	err = ikesaKey.GenerateKeyForIKESA(concatenatedNonce, diffieHellmanSharedKey,
		initiatorSPI, responderSPI)
	require.Error(t, err)

	ikesaKey.EncrInfo = encr.StrToType("ENCR_AES_CBC_256")

	// Integrity algorithm is nil
	err = ikesaKey.GenerateKeyForIKESA(concatenatedNonce, diffieHellmanSharedKey,
		initiatorSPI, responderSPI)
	require.Error(t, err)

	ikesaKey.IntegInfo = integ.StrToType("AUTH_HMAC_SHA1_96")
	// Pseudorandom function is nil
	err = ikesaKey.GenerateKeyForIKESA(concatenatedNonce, diffieHellmanSharedKey,
		initiatorSPI, responderSPI)
	require.Error(t, err)

	ikesaKey.PrfInfo = prf.StrToType("PRF_HMAC_SHA1")
	// Diffie-Hellman group is nil
	err = ikesaKey.GenerateKeyForIKESA(concatenatedNonce, diffieHellmanSharedKey,
		initiatorSPI, responderSPI)
	require.Error(t, err)

	ikesaKey.DhInfo = dh.StrToType("ike_types.DH_2048_BIT_MODP")
	// Concatenated nonce is nil
	err = ikesaKey.GenerateKeyForIKESA(nil, diffieHellmanSharedKey,
		initiatorSPI, responderSPI)
	require.Error(t, err)

	// Diffie-Hellman shared key is nil
	err = ikesaKey.GenerateKeyForIKESA(concatenatedNonce, nil,
		initiatorSPI, responderSPI)
	require.Error(t, err)

	// Normal case
	err = ikesaKey.GenerateKeyForIKESA(concatenatedNonce, diffieHellmanSharedKey,
		initiatorSPI, responderSPI)
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
	err := childSAKey.GenerateKeyForChildSA(nil, nil)
	require.Error(t, err)

	ikeSAKey := &IKESAKey{}

	// Child SecurityAssociation is nil
	var c *ChildSAKey
	err = c.GenerateKeyForChildSA(ikeSAKey, nil)
	require.Error(t, err)

	// Pseudorandom function is nil
	err = childSAKey.GenerateKeyForChildSA(ikeSAKey, nil)
	require.Error(t, err)

	ikeSAKey.PrfInfo = prf.StrToType("PRF_HMAC_SHA1")

	// Encryption algorithm is nil
	err = childSAKey.GenerateKeyForChildSA(ikeSAKey, nil)
	require.Error(t, err)

	childSAKey.EncrKInfo = encr.StrToKType("ENCR_AES_CBC_256")
	childSAKey.IntegKInfo = integ.StrToKType("AUTH_HMAC_SHA1_96")

	// Deriving key is nil
	err = childSAKey.GenerateKeyForChildSA(ikeSAKey, nil)
	require.Error(t, err)

	sk_d, err := hex.DecodeString("276e1a8f0d65dae5309da66277ff7c82d39a8956")
	require.NoError(t, err)
	ikeSAKey.Prf_d = ikeSAKey.PrfInfo.Init(sk_d)

	err = childSAKey.GenerateKeyForChildSA(ikeSAKey, nil)
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

func TestChildToProposal(t *testing.T) {
	dhType := dh.StrToType("ike_types.DH_1024_BIT_MODP")
	encrKType := encr.StrToKType("ENCR_AES_CBC_256")
	integKType := integ.StrToKType("AUTH_HMAC_MD5_96")
	esnType, err := esn.StrToType("ESN_ENABLE")
	require.NoError(t, err)

	childsaKey := ChildSAKey{
		DhInfo:     dhType,
		EncrKInfo:  encrKType,
		IntegKInfo: integKType,
		EsnInfo:    esnType,
	}

	proposal, err := childsaKey.ToProposal()
	require.NoError(t, err)

	if len(proposal.DiffieHellmanGroup) != 1 ||
		len(proposal.EncryptionAlgorithm) != 1 ||
		len(proposal.IntegrityAlgorithm) != 1 ||
		len(proposal.PseudorandomFunction) != 0 ||
		len(proposal.ExtendedSequenceNumbers) != 1 {
		t.FailNow()
	}
}

func TestChildSetProposal(t *testing.T) {
	dhType := dh.StrToType("ike_types.DH_1024_BIT_MODP")
	encrKType := encr.StrToKType("ENCR_AES_CBC_256")
	integKType := integ.StrToKType("AUTH_HMAC_MD5_96")
	esnType, err := esn.StrToType("ESN_ENABLE")
	require.NoError(t, err)

	proposal := new(message.Proposal)

	proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, dh.ToTransform(dhType))
	encrKTranform, err := encr.ToTransformChildSA(encrKType)
	require.NoError(t, err)
	proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, encrKTranform)
	proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, integ.ToTransformChildSA(integKType))
	proposal.ExtendedSequenceNumbers = append(proposal.ExtendedSequenceNumbers, esn.ToTransform(esnType))

	childsaKey, err := NewChildSAKeyByProposal(proposal)
	require.NoError(t, err)

	if childsaKey.DhInfo == nil ||
		childsaKey.EncrKInfo == nil ||
		childsaKey.IntegKInfo == nil {
		t.FailNow()
	}
}
