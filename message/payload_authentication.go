package message

import (
	"github.com/pkg/errors"
)

var _ IKEPayload = &Authentication{}

type Authentication struct {
	AuthenticationMethod uint8
	AuthenticationData   []byte
}

func (authentication *Authentication) Type() IkePayloadType { return TypeAUTH }

func (authentication *Authentication) Marshal() ([]byte, error) {
	authenticationData := make([]byte, 4)
	authenticationData[0] = authentication.AuthenticationMethod
	authenticationData = append(authenticationData, authentication.AuthenticationData...)
	return authenticationData, nil
}

func (authentication *Authentication) Unmarshal(b []byte) error {
	if len(b) > 0 {
		// bounds checking
		if len(b) <= 4 {
			return errors.Errorf("Authentication: No sufficient bytes to decode next authentication")
		}

		authentication.AuthenticationMethod = b[0]
		authentication.AuthenticationData = append(authentication.AuthenticationData, b[4:]...)
	}

	return nil
}
