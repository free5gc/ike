package eap

import "github.com/pkg/errors"

// Definition of EAP Notification

var _ EapTypeFormat = &EapNotification{}

type EapNotification struct {
	NotificationData []byte
}

func (eapNotification *EapNotification) Type() EapType { return EapTypeNotification }

func (eapNotification *EapNotification) Marshal() ([]byte, error) {
	if len(eapNotification.NotificationData) == 0 {
		return nil, errors.New("EapNotification: EAP notification is empty")
	}

	eapNotificationData := []byte{byte(EapTypeNotification)}
	eapNotificationData = append(eapNotificationData, eapNotification.NotificationData...)

	return eapNotificationData, nil
}

func (eapNotification *EapNotification) Unmarshal(b []byte) error {
	if len(b) > 1 {
		// Check type code
		typeCode := EapType(b[0])
		if typeCode != EapTypeNotification {
			return errors.Errorf("EapNotification: expect %d but got %d", EapTypeNotification, typeCode)
		}
		eapNotification.NotificationData = append(eapNotification.NotificationData, b[1:]...)
	}

	return nil
}
