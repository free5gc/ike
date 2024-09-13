package message

import "github.com/pkg/errors"

var _ EAPTypeFormat = &EAPNak{}

type EAPNak struct {
	NakData []byte
}

func (eapNak *EAPNak) Type() EAPType { return EAPTypeNak }

func (eapNak *EAPNak) marshal() ([]byte, error) {
	if len(eapNak.NakData) == 0 {
		return nil, errors.Errorf("EAPNak: EAP nak is empty")
	}

	eapNakData := []byte{byte(EAPTypeNak)}
	eapNakData = append(eapNakData, eapNak.NakData...)
	return eapNakData, nil
}

func (eapNak *EAPNak) unmarshal(b []byte) error {
	if len(b) > 1 {
		eapNak.NakData = append(eapNak.NakData, b[1:]...)
	}
	return nil
}
