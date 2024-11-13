package eap_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	eap_message "github.com/free5gc/ike/eap"
)

var (
	eapIdentity = eap_message.EAP{
		Code:       eap_message.EapCodeRequest,
		Identifier: 9,
		EapTypeData: &eap_message.EapIdentity{
			IdentityData: []byte{
				0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
				0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
				0xb8, 0x56, 0x81, 0x8a,
			},
		},
	}

	eapIdentityByte = []byte{
		0x01, 0x09, 0x00, 0x19, 0x01, 0x7d, 0x09,
		0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20, 0x56,
		0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
		0xb8, 0x56, 0x81, 0x8a,
	}

	eapNotification = eap_message.EAP{
		Code:       eap_message.EapCodeRequest,
		Identifier: 9,
		EapTypeData: &eap_message.EapNotification{
			NotificationData: []byte{
				0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
				0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
				0xb8, 0x56, 0x81, 0x8a,
			},
		},
	}

	eapNotificationByte = []byte{
		0x01, 0x09, 0x00, 0x19, 0x02, 0x7d, 0x09, 0x18,
		0x42, 0x60, 0x9c, 0x9e, 0x20, 0x56, 0x9f, 0xc0,
		0x39, 0xda, 0x3f, 0x22, 0x2a, 0xb8, 0x56, 0x81,
		0x8a,
	}

	eapNak = eap_message.EAP{
		Code:       eap_message.EapCodeRequest,
		Identifier: 9,
		EapTypeData: &eap_message.EapNak{
			NakData: []byte{
				0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
				0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
				0xb8, 0x56, 0x81, 0x8a,
			},
		},
	}

	eapNakByte = []byte{
		0x01, 0x09, 0x00, 0x19, 0x03, 0x7d, 0x09, 0x18,
		0x42, 0x60, 0x9c, 0x9e, 0x20, 0x56, 0x9f, 0xc0,
		0x39, 0xda, 0x3f, 0x22, 0x2a, 0xb8, 0x56, 0x81,
		0x8a,
	}

	eapExpanded = eap_message.EAP{
		Code:       eap_message.EapCodeRequest,
		Identifier: 9,
		EapTypeData: &eap_message.EapExpanded{
			VendorID:   eap_message.VendorId3GPP,
			VendorType: eap_message.VendorTypeEAP5G,
			VendorData: []byte{
				0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
				0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
				0xb8, 0x56, 0x81, 0x8a,
			},
		},
	}

	eapExpandedByte = []byte{
		0x01, 0x09, 0x00, 0x20, 0xfe, 0x00, 0x28, 0xaf,
		0x00, 0x00, 0x00, 0x03, 0x7d, 0x09, 0x18, 0x42,
		0x60, 0x9c, 0x9e, 0x20, 0x56, 0x9f, 0xc0, 0x39,
		0xda, 0x3f, 0x22, 0x2a, 0xb8, 0x56, 0x81, 0x8a,
	}
)

func TestEapMarshal(t *testing.T) {
	testcases := []struct {
		description string
		eap         eap_message.EAP
		expMarshal  []byte
		expErr      bool
	}{
		{
			description: "EAP identity is empty",
			eap: eap_message.EAP{
				Code:       eap_message.EapCodeRequest,
				Identifier: 9,
				EapTypeData: &eap_message.EapIdentity{
					IdentityData: nil,
				},
			},
			expErr: true,
		},
		{
			description: "EapIdentity marshal",
			eap:         eapIdentity,
			expMarshal:  eapIdentityByte,
			expErr:      false,
		},
		{
			description: "EAP notification is empty",
			eap: eap_message.EAP{
				Code:       eap_message.EapCodeRequest,
				Identifier: 9,
				EapTypeData: &eap_message.EapNotification{
					NotificationData: nil,
				},
			},
			expErr: true,
		},
		{
			description: "EapNotification marshal",
			eap:         eapNotification,
			expMarshal:  eapNotificationByte,
			expErr:      false,
		},
		{
			description: "EAP nak is empty",
			eap: eap_message.EAP{
				Code:       eap_message.EapCodeRequest,
				Identifier: 9,
				EapTypeData: &eap_message.EapNak{
					NakData: nil,
				},
			},
			expErr: true,
		},
		{
			description: "EapNak marshal",
			eap:         eapNak,
			expMarshal:  eapNakByte,
			expErr:      false,
		},
		{
			description: "EapExpanded marshal",
			eap:         eapExpanded,
			expMarshal:  eapExpandedByte,
			expErr:      false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.eap.Marshal()
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, result)
			}
		})
	}
}

func TestEapUnmarshal(t *testing.T) {
	testcases := []struct {
		description string
		b           []byte
		expMarshal  eap_message.EAP
		expErr      bool
	}{
		{
			description: "No sufficient bytes to decode next EAP payload",
			b:           []byte{0x01, 0x02, 0x03},
			expErr:      true,
		},
		{
			description: "Payload length specified in the header is too small for EAP",
			b:           []byte{0x01, 0x02, 0x00, 0x03},
			expErr:      true,
		},
		{
			description: "Received payload length not matches the length specified in header",
			b:           []byte{0x01, 0x02, 0x00, 0x07, 0x01},
			expErr:      true,
		},
		{
			description: "EapIdentity unmarshal",
			b:           eapIdentityByte,
			expMarshal:  eapIdentity,
			expErr:      false,
		},
		{
			description: "EapNotification unmarshal",
			b:           eapNotificationByte,
			expMarshal:  eapNotification,
			expErr:      false,
		},
		{
			description: "EapNak unmarshal",
			b:           eapNakByte,
			expMarshal:  eapNak,
			expErr:      false,
		},
		{
			description: "EapExpanded: No sufficient bytes to decode the EAP expanded type",
			b: []byte{
				0x01, 0x09, 0x00, 0x20, 0xfe, 0x00, 0x28,
			},
			expErr: true,
		},
		{
			description: "EapExpanded unmarshal",
			b:           eapExpandedByte,
			expMarshal:  eapExpanded,
			expErr:      false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var eap eap_message.EAP
			err := eap.Unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, eap)
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
			eap.EapTypeData = eap_message.NewEapAkaPrime(eap_message.SubtypeAkaChallenge)

			// Build EAP-AKA' packet
			eapAkaPrime := eap.EapTypeData.(*eap_message.EapAkaPrime)
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

			key, err := hex.DecodeString(tc.key)
			require.NoError(t, err)

			mac, err := eap.CalcEapAkaPrimeAtMAC(key)
			require.NoError(t, err)

			require.Equal(t, expectResult, mac)

			err = eapAkaPrime.SetAttr(eap_message.AT_MAC, mac)
			require.NoError(t, err)
			_, err = eap.Marshal()
			require.NoError(t, err)
		})
	}
}
