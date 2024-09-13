package message

import "github.com/pkg/errors"

var _ IKEPayload = &Encrypted{}

type Encrypted struct {
	NextPayload   uint8
	EncryptedData []byte
}

func (encrypted *Encrypted) Type() IKEPayloadType { return TypeSK }

func (encrypted *Encrypted) marshal() ([]byte, error) {
	if len(encrypted.EncryptedData) == 0 {
		return nil, errors.Errorf("[Encrypted] The encrypted data is empty")
	}

	return encrypted.EncryptedData, nil
}

func (encrypted *Encrypted) unmarshal(b []byte) error {
	encrypted.EncryptedData = append(encrypted.EncryptedData, b...)
	return nil
}
