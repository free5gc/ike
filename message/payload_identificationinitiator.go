package message

import (
	"github.com/pkg/errors"
)

var _ IKEPayload = &IdentificationInitiator{}

type IdentificationInitiator struct {
	IDType uint8
	IDData []byte
}

func (identification *IdentificationInitiator) Type() IkePayloadType {
	return TypeIDi
}

func (identification *IdentificationInitiator) Marshal() ([]byte, error) {
	identificationData := make([]byte, 4)
	identificationData[0] = identification.IDType
	identificationData = append(identificationData, identification.IDData...)
	return identificationData, nil
}

func (identification *IdentificationInitiator) Unmarshal(b []byte) error {
	if len(b) > 0 {
		// bounds checking
		if len(b) <= 4 {
			return errors.Errorf("Identification: No sufficient bytes to decode next identification")
		}

		identification.IDType = b[0]
		identification.IDData = append(identification.IDData, b[4:]...)
	}

	return nil
}
