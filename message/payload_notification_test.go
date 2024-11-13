package message

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	validNotification = Notification{
		ProtocolID:        TypeNone,
		NotifyMessageType: NAT_DETECTION_SOURCE_IP,
		SPI:               []byte{0x01, 0x02, 0x03},
		NotificationData: []byte{
			0x50, 0xc4, 0xc2, 0xbe, 0x8e, 0x3f, 0xd9, 0x16,
			0x19, 0x24, 0x65, 0x0d, 0x14, 0x5d, 0x4f, 0xf6,
			0x46, 0xd8, 0x9d, 0x75,
		},
	}

	validNotificationByte = []byte{
		0x00, 0x03, 0x40, 0x04, 0x01, 0x02, 0x03, 0x50,
		0xc4, 0xc2, 0xbe, 0x8e, 0x3f, 0xd9, 0x16, 0x19,
		0x24, 0x65, 0x0d, 0x14, 0x5d, 0x4f, 0xf6, 0x46,
		0xd8, 0x9d, 0x75,
	}
)

func TestNotification(t *testing.T) {
	testcasesMarshal := []struct {
		description  string
		notification Notification
		expMarshal   []byte
	}{
		{
			description:  "Notification marshal",
			notification: validNotification,
			expMarshal:   validNotificationByte,
		},
	}

	for _, tc := range testcasesMarshal {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.notification.Marshal()
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, result)
		})
	}

	testcasesUnmarshal := []struct {
		description string
		b           []byte
		expErr      bool
		expMarshal  Notification
	}{
		{
			description: "No sufficient bytes to decode next notification",
			b:           []byte{0x01, 0x02, 0x03},
			expErr:      true,
		},
		{
			description: "No sufficient bytes to get SPI according to the length specified in header",
			b:           []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expErr:      true,
		},
		{
			description: "Notification Unmarshal",
			b:           validNotificationByte,
			expMarshal:  validNotification,
			expErr:      false,
		},
	}

	for _, tc := range testcasesUnmarshal {
		t.Run(tc.description, func(t *testing.T) {
			var notification Notification
			err := notification.Unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, notification)
			}
		})
	}
}
