package message

import (
	"encoding/binary"

	"github.com/pkg/errors"

	ike_types "github.com/free5gc/ike/types"
)

var _ IKEPayload = &Notification{}

type Notification struct {
	ProtocolID        uint8
	NotifyMessageType uint16
	SPI               []byte
	NotificationData  []byte
}

func (notification *Notification) Type() ike_types.IkePayloadType { return ike_types.TypeN }

func (notification *Notification) Marshal() ([]byte, error) {
	notificationData := make([]byte, 4)

	notificationData[0] = notification.ProtocolID
	numberofSPI := len(notification.SPI)
	if numberofSPI > 0xFF {
		return nil, errors.Errorf("Notification: Number of SPI exceeds uint8 limit: %d", numberofSPI)
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
		if len(b) < int(4+spiSize) {
			return errors.Errorf("Notification: No sufficient bytes to get SPI according to the length specified in header")
		}

		notification.ProtocolID = b[0]
		notification.NotifyMessageType = binary.BigEndian.Uint16(b[2:4])

		notification.SPI = append(notification.SPI, b[4:4+spiSize]...)
		notification.NotificationData = append(notification.NotificationData, b[4+spiSize:]...)
	}

	return nil
}
