package message

import "github.com/pkg/errors"

var _ EAPTypeFormat = &EAPNotification{}

type EAPNotification struct {
	NotificationData []byte
}

func (eapNotification *EAPNotification) Type() EAPType { return EAPTypeNotification }

func (eapNotification *EAPNotification) marshal() ([]byte, error) {
	if len(eapNotification.NotificationData) == 0 {
		return nil, errors.Errorf("EAPNotification: EAP notification is empty")
	}

	eapNotificationData := []byte{byte(EAPTypeNotification)}
	eapNotificationData = append(eapNotificationData, eapNotification.NotificationData...)
	return eapNotificationData, nil
}

func (eapNotification *EAPNotification) unmarshal(b []byte) error {
	if len(b) > 1 {
		eapNotification.NotificationData = append(eapNotification.NotificationData, b[1:]...)
	}
	return nil
}
