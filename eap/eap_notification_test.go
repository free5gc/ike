package eap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	validEapNotification = EapNotification{
		NotificationData: []byte{
			0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
			0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
			0xb8, 0x56, 0x81, 0x8a,
		},
	}

	validEapNotificationByte = []byte{
		0x02, 0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e,
		0x20, 0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22,
		0x2a, 0xb8, 0x56, 0x81, 0x8a,
	}
)

func TestEapNotificationMarshal(t *testing.T) {
	testcases := []struct {
		description string
		eap         EapNotification
		expMarshal  []byte
		expErr      bool
	}{
		{
			description: "EAP notification is empty",
			eap: EapNotification{
				NotificationData: nil,
			},
			expErr: true,
		},
		{
			description: "EapNotification Marshal",
			eap:         validEapNotification,
			expMarshal:  validEapNotificationByte,
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

func TestEapNotificationUnmarshal(t *testing.T) {
	testcases := []struct {
		description string
		b           []byte
		expMarshal  EapNotification
	}{
		{
			description: "EapNotification Unmarshal",
			b:           validEapNotificationByte,
			expMarshal:  validEapNotification,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var eap EapNotification
			err := eap.Unmarshal(tc.b)
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, eap)
		})
	}
}
