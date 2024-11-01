package message

import (
	"github.com/pkg/errors"

	ike_types "github.com/free5gc/ike/types"
)

var _ IKEPayload = &IdentificationResponder{}

type IdentificationResponder struct {
	IDType uint8
	IDData []byte
}

func (identification *IdentificationResponder) Type() ike_types.IkePayloadType {
	return ike_types.TypeIDr
}

func (identification *IdentificationResponder) Marshal() ([]byte, error) {
	identificationData := make([]byte, 4)
	identificationData[0] = identification.IDType
	identificationData = append(identificationData, identification.IDData...)
	return identificationData, nil
}

func (identification *IdentificationResponder) Unmarshal(b []byte) error {
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
