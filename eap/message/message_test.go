package message_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	eap_message "github.com/free5gc/ike/eap/message"
)

func TestEapIdentity(t *testing.T) {
	tcs := []struct {
		name           string
		userName       string
		expectedResult []byte
	}{
		{
			name:           "correct",
			userName:       "test1",
			expectedResult: []byte{0x02, 0x01, 0x00, 0x0a, 0x01, 0x74, 0x65, 0x73, 0x74, 0x31},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			eap := new(eap_message.EAP)
			eap.Code = eap_message.EapCodeResponse
			eap.Identifier = 1

			eapIdentity := new(eap_message.EapIdentity)
			err := eapIdentity.Unmarshal([]byte(tc.userName))
			require.NoError(t, err)
			eap.EapTypeData = append(eap.EapTypeData, eapIdentity)

			result, err := eap.Marshal()
			require.NoError(t, err)

			require.Equal(t, tc.expectedResult, result)
		})
	}
}

func TestEapAkaPrime(t *testing.T) {
	var err error
	var val []byte

	eapAkaPrime := new(eap_message.EapAkaPrime)
	eapAkaPrime.Init(eap_message.SubtypeAkaChallenge)

	attrs := []struct {
		eapAkaPrimeAttrType eap_message.EapAkaPrimeAttrType
		value               string
	}{
		{
			eapAkaPrimeAttrType: eap_message.AT_RAND,
			value:               "25fa7d6e3232108389df876560af7c15",
		},
		{
			eapAkaPrimeAttrType: eap_message.AT_AUTN,
			value:               "c8621644d1368000cfac85416226ed27",
		},
		{
			eapAkaPrimeAttrType: eap_message.AT_KDF,
			value:               "0001",
		},
		{
			eapAkaPrimeAttrType: eap_message.AT_KDF_INPUT,
			value:               "35473a6d6e633039332e6d63633230382e336770706e6574776f726b2e6f7267",
		},
		{
			eapAkaPrimeAttrType: eap_message.AT_MAC,
			value:               "51dbe38b18f8aab6ac6e793bfabdbb0e",
		},
	}

	for i := 0; i < len(attrs); i++ {
		val, err = hex.DecodeString(attrs[i].value)
		require.NoError(t, err)
		err = eapAkaPrime.SetAttr(attrs[i].eapAkaPrimeAttrType, val)
		require.NoError(t, err)
	}

	// Test Marshal
	eapAkaPrimeBytes, err := eapAkaPrime.Marshal()
	require.NoError(t, err)

	// Test Unmarshal
	result := new(eap_message.EapAkaPrime)
	err = result.Unmarshal(eapAkaPrimeBytes)
	require.NoError(t, err)

	require.Equal(t, eapAkaPrime, result)
}
