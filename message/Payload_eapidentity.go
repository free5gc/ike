package message

import "github.com/pkg/errors"

var _ EAPTypeFormat = &EAPIdentity{}

type EAPIdentity struct {
	IdentityData []byte
}

func (eapIdentity *EAPIdentity) Type() EAPType { return EAPTypeIdentity }

func (eapIdentity *EAPIdentity) marshal() ([]byte, error) {
	if len(eapIdentity.IdentityData) == 0 {
		return nil, errors.Errorf("EAPIdentity: EAP identity is empty")
	}

	eapIdentityData := []byte{byte(EAPTypeIdentity)}
	eapIdentityData = append(eapIdentityData, eapIdentity.IdentityData...)
	return eapIdentityData, nil
}

func (eapIdentity *EAPIdentity) unmarshal(b []byte) error {
	if len(b) > 1 {
		eapIdentity.IdentityData = append(eapIdentity.IdentityData, b[1:]...)
	}
	return nil
}
