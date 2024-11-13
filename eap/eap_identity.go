package eap

import "github.com/pkg/errors"

var _ EapTypeData = &EapIdentity{}

type EapIdentity struct {
	IdentityData []byte
}

func (eapIdentity *EapIdentity) Type() EapType { return EapTypeIdentity }

func (eapIdentity *EapIdentity) Marshal() ([]byte, error) {
	if len(eapIdentity.IdentityData) == 0 {
		return nil, errors.Errorf("EapIdentity: EAP identity is empty")
	}

	eapIdentityData := []byte{byte(EapTypeIdentity)}
	eapIdentityData = append(eapIdentityData, eapIdentity.IdentityData...)
	return eapIdentityData, nil
}

func (eapIdentity *EapIdentity) Unmarshal(b []byte) error {
	if len(b) > 1 {
		// Check type code
		typeCode := EapType(b[0])
		if typeCode != EapTypeIdentity {
			return errors.Errorf("EapIdentity: expect %d but got %d", EapTypeIdentity, typeCode)
		}
		eapIdentity.IdentityData = append(eapIdentity.IdentityData, b[1:]...)
	}
	return nil
}
