package message

import (
	"github.com/pkg/errors"

	ike_types "github.com/free5gc/ike/types"
)

var _ IKEPayload = &Encrypted{}

type Encrypted struct {
	NextPayload   uint8
	EncryptedData []byte
}

func (encrypted *Encrypted) Type() ike_types.IkePayloadType { return ike_types.TypeSK }

func (encrypted *Encrypted) Marshal() ([]byte, error) {
	if len(encrypted.EncryptedData) == 0 {
		return nil, errors.Errorf("[Encrypted] The encrypted data is empty")
	}

	return encrypted.EncryptedData, nil
}

func (encrypted *Encrypted) Unmarshal(b []byte) error {
	encrypted.EncryptedData = append(encrypted.EncryptedData, b...)
	return nil
}
