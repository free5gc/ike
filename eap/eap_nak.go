package eap

import "github.com/pkg/errors"

var _ EapTypeData = &EapNak{}

type EapNak struct {
	NakData []byte
}

func (eapNak *EapNak) Type() EapType { return EapTypeNak }

func (eapNak *EapNak) Marshal() ([]byte, error) {
	if len(eapNak.NakData) == 0 {
		return nil, errors.New("EapNak: EAP nak is empty")
	}

	eapNakData := []byte{byte(EapTypeNak)}
	eapNakData = append(eapNakData, eapNak.NakData...)
	return eapNakData, nil
}

func (eapNak *EapNak) Unmarshal(b []byte) error {
	if len(b) > 1 {
		// Check type code
		typeCode := EapType(b[0])
		if typeCode != EapTypeNak {
			return errors.Errorf("EapNak: expect %d but got %d", EapTypeNak, typeCode)
		}
		eapNak.NakData = append(eapNak.NakData, b[1:]...)
	}
	return nil
}
