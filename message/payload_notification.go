package message

import (
	"encoding/binary"
	"math"

	"github.com/pkg/errors"
)

var _ IKEPayload = &Notification{}

type Notification struct {
	ProtocolID        uint8
	NotifyMessageType uint16
	SPI               []byte
	NotificationData  []byte
}

func (notification *Notification) Type() IkePayloadType { return TypeN }

func (notification *Notification) Marshal() ([]byte, error) {
	notificationData := make([]byte, 4)

	notificationData[0] = notification.ProtocolID
	numberofSPI := len(notification.SPI)
	if numberofSPI > math.MaxUint8 {
		return nil, errors.Errorf("Notification: Number of SPI exceeds uint8 limit: %d", numberofSPI)
	}
	if len(notificationData) < 2 {
		return nil, errors.Errorf("Notification: data buffer too short")
	}
	notificationData[1] = uint8(numberofSPI)
	binary.BigEndian.PutUint16(notificationData[2:4], notification.NotifyMessageType)

	notificationData = append(notificationData, notification.SPI...)
	notificationData = append(notificationData, notification.NotificationData...)
	return notificationData, nil
}

func (notification *Notification) Unmarshal(b []byte) error {
	if len(b) > 0 {
		// bounds checking
		if len(b) < 4 {
			return errors.Errorf("Notification: No sufficient bytes to decode next notification")
		}
		spiSize := b[1]
		// spiSize is a uint8, so 4+spiSize overflows for spiSize >= 252; promote to
		// int once and use it for every subsequent bound/slice to avoid a wrapped index.
		spiEnd := 4 + int(spiSize)
		if len(b) < spiEnd {
			return errors.Errorf("Notification: No sufficient bytes to get SPI according to the length specified in header")
		}

		notification.ProtocolID = b[0]
		notification.NotifyMessageType = binary.BigEndian.Uint16(b[2:4])

		notification.SPI = append(notification.SPI, b[4:spiEnd]...)
		notification.NotificationData = append(notification.NotificationData, b[spiEnd:]...)
	}

	return nil
}
