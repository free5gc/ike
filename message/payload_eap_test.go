package message

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	eapIdentity = EAP{
		Code:       EAPCodeRequest,
		Identifier: 9,
		EAPTypeData: EAPTypeDataContainer{
			&EAPIdentity{
				IdentityData: []byte{
					0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
					0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
					0xb8, 0x56, 0x81, 0x8a,
				},
			},
		},
	}

	eapIdentityByte = []byte{
		0x01, 0x09, 0x00, 0x19, 0x01, 0x7d, 0x09,
		0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20, 0x56,
		0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
		0xb8, 0x56, 0x81, 0x8a,
	}

	eapNotification = EAP{
		Code:       EAPCodeRequest,
		Identifier: 9,
		EAPTypeData: EAPTypeDataContainer{
			&EAPNotification{
				NotificationData: []byte{
					0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
					0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
					0xb8, 0x56, 0x81, 0x8a,
				},
			},
		},
	}

	eapNotificationByte = []byte{
		0x01, 0x09, 0x00, 0x19, 0x02, 0x7d, 0x09, 0x18,
		0x42, 0x60, 0x9c, 0x9e, 0x20, 0x56, 0x9f, 0xc0,
		0x39, 0xda, 0x3f, 0x22, 0x2a, 0xb8, 0x56, 0x81,
		0x8a,
	}

	eapNak = EAP{
		Code:       EAPCodeRequest,
		Identifier: 9,
		EAPTypeData: EAPTypeDataContainer{
			&EAPNak{
				NakData: []byte{
					0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
					0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
					0xb8, 0x56, 0x81, 0x8a,
				},
			},
		},
	}

	eapNakByte = []byte{
		0x01, 0x09, 0x00, 0x19, 0x03, 0x7d, 0x09, 0x18,
		0x42, 0x60, 0x9c, 0x9e, 0x20, 0x56, 0x9f, 0xc0,
		0x39, 0xda, 0x3f, 0x22, 0x2a, 0xb8, 0x56, 0x81,
		0x8a,
	}

	eapExpanded = EAP{
		Code:       EAPCodeRequest,
		Identifier: 9,
		EAPTypeData: EAPTypeDataContainer{
			&EAPExpanded{
				VendorID:   VendorID3GPP,
				VendorType: VendorTypeEAP5G,
				VendorData: []byte{
					0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
					0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
					0xb8, 0x56, 0x81, 0x8a,
				},
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

func TestEAPMarshal(t *testing.T) {
	testcases := []struct {
		description string
		eap         EAP
		expMarshal  []byte
		expErr      bool
	}{
		{
			description: "EAP identity is empty",
			eap: EAP{
				Code:       EAPCodeRequest,
				Identifier: 9,
				EAPTypeData: EAPTypeDataContainer{
					&EAPIdentity{
						IdentityData: nil,
					},
				},
			},
			expErr: true,
		},
		{
			description: "EAPIdentity marshal",
			eap:         eapIdentity,
			expMarshal:  eapIdentityByte,
			expErr:      false,
		},
		{
			description: "EAP notification is empty",
			eap: EAP{
				Code:       EAPCodeRequest,
				Identifier: 9,
				EAPTypeData: EAPTypeDataContainer{
					&EAPNotification{
						NotificationData: nil,
					},
				},
			},
			expErr: true,
		},
		{
			description: "EAPNotification marshal",
			eap:         eapNotification,
			expMarshal:  eapNotificationByte,
			expErr:      false,
		},
		{
			description: "EAP nak is empty",
			eap: EAP{
				Code:       EAPCodeRequest,
				Identifier: 9,
				EAPTypeData: EAPTypeDataContainer{
					&EAPNak{
						NakData: nil,
					},
				},
			},
			expErr: true,
		},
		{
			description: "EAPNak marshal",
			eap:         eapNak,
			expMarshal:  eapNakByte,
			expErr:      false,
		},
		{
			description: "EAPExpanded marshal",
			eap:         eapExpanded,
			expMarshal:  eapExpandedByte,
			expErr:      false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.eap.marshal()
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, result)
			}
		})
	}
}

func TestEAPUnmarshal(t *testing.T) {
	testcases := []struct {
		description string
		b           []byte
		expMarshal  EAP
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
			description: "EAPIdentity unmarshal",
			b:           eapIdentityByte,
			expMarshal:  eapIdentity,
			expErr:      false,
		},
		{
			description: "EAPNotification unmarshal",
			b:           eapNotificationByte,
			expMarshal:  eapNotification,
			expErr:      false,
		},
		{
			description: "EAPNak unmarshal",
			b:           eapNakByte,
			expMarshal:  eapNak,
			expErr:      false,
		},
		{
			description: "EAPExpanded: No sufficient bytes to decode the EAP expanded type",
			b: []byte{
				0x01, 0x09, 0x00, 0x20, 0xfe, 0x00, 0x28,
			},
			expErr: true,
		},
		{
			description: "EAPExpanded unmarshal",
			b:           eapExpandedByte,
			expMarshal:  eapExpanded,
			expErr:      false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var eap EAP
			err := eap.unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, eap)
			}
		})
	}
}
