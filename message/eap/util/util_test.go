package util_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	eap_message "github.com/free5gc/ike/message/eap"
	eap_util "github.com/free5gc/ike/message/eap/util"
)

func TestEapAkaPrimePrf(t *testing.T) {
	tcs := []struct {
		name           string
		ikPrime        string
		ckPrime        string
		identity       string
		expectedResult []string
	}{
		{
			name:     "correct",
			ikPrime:  "4bf4f64b21b59444277f2c60c417d4c7",
			ckPrime:  "403075840723643618b6fae83236c86d",
			identity: "208930123456789",
			expectedResult: []string{
				"d2e0e54aa01d48959e38ca1aff6c38fb",
				"a56e1733adf3747cfe045dacebedeb33dd53e0f5200f6697c0855e2f856c4e40",
				"c362f256003483d0766bf877191741254446986158e66d57fcdc251d531fdec4",
				"e6ad162cd2fbcf3b6df5765b51e8983f5fb3204d16930c9bbbef5a971cf1de7c" +
					"1c60f79516b4efe1b937ce510a3e52c161d6c6db3f03a62a93e33a53cc15bb70",
				"f74892a2343d64de4528bd0cbbf12edf03b47adbc72e7839175af598d87cc7d3" +
					"3cf0671517eb051345946b978e7afc9b48327e90f816e67efddc5949adab08ad",
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			ikPrime, err := hex.DecodeString(tc.ikPrime)
			require.NoError(t, err)
			ckPrime, err := hex.DecodeString(tc.ckPrime)
			require.NoError(t, err)

			k_encr, k_aut, k_re, msk, emsk := eap_util.EapAkaPrimePRF(ikPrime, ckPrime, tc.identity)
			actualResult := [][]byte{k_encr, k_aut, k_re, msk, emsk}

			for i := 0; i < len(actualResult); i++ {
				expectedResult, innerErr := hex.DecodeString(tc.expectedResult[i])
				require.NoError(t, innerErr)
				require.Equal(t, expectedResult, actualResult[i])
			}
		})
	}
}

func TestEapAkaMac(t *testing.T) {
	tcs := []struct {
		name         string
		eapID        uint8
		atRes        string
		key          string
		expectResult string
	}{
		{
			name:         "test case 1",
			eapID:        64,
			atRes:        "e2f5c0ab3685b3b4",
			key:          "7e28ba2f666944737f6c8a0a008e834895206a02725b5b4b925a399ae6f09cf0",
			expectResult: "fd69971493e2b7f873a06e72e2051e8a",
		},
		{
			name:         "test case 2",
			eapID:        2,
			atRes:        "1e4c99649c900fec",
			key:          "7ee97c273b07a773c29f670d2e688b2a70eb206963bd7d3d40a0eb18955133f8",
			expectResult: "66a5e7f1e0df7cb0043069ae5a9e181c",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			expectResult, err := hex.DecodeString(tc.expectResult)
			require.NoError(t, err)

			// Build test EAP packet
			eap := new(eap_message.EAP)
			eap.Code = eap_message.EapCodeResponse
			eap.Identifier = tc.eapID

			// Build EAP-AKA' packet
			eapAkaPrime := new(eap_message.EapAkaPrime)
			eapAkaPrime.Init(eap_message.SubtypeAkaChallenge)

			attrs := []struct {
				eapAkaPrimeAttrType eap_message.EapAkaPrimeAttrType
				value               string
			}{
				{
					eapAkaPrimeAttrType: eap_message.AT_RES,
					value:               tc.atRes,
				},
				{
					eapAkaPrimeAttrType: eap_message.AT_CHECKCODE,
					value:               "",
				},
			}

			var val []byte
			for i := 0; i < len(attrs); i++ {
				val, err = hex.DecodeString(attrs[i].value)
				require.NoError(t, err)

				err = eapAkaPrime.SetAttr(attrs[i].eapAkaPrimeAttrType, val)
				require.NoError(t, err)
			}
			err = eapAkaPrime.InitMac()
			require.NoError(t, err)

			eap.EapTypeData = eapAkaPrime
			eapPkt, err := eap.Marshal()
			require.NoError(t, err)

			// Test MAC
			macInput, err := eap_util.GenMacInput(eapPkt)
			require.NoError(t, err)

			key, err := hex.DecodeString(tc.key)
			require.NoError(t, err)

			mac, err := eap_util.CalculateAtMAC(key, macInput)
			require.NoError(t, err)

			require.Equal(t, expectResult, mac)

			err = eapAkaPrime.SetAttr(eap_message.AT_MAC, mac)
			require.NoError(t, err)
			_, err = eap.Marshal()
			require.NoError(t, err)
		})
	}
}
