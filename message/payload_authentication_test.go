package message

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	validAuthentication = Authentication{
		AuthenticationMethod: SharedKeyMesageIntegrityCode,
		AuthenticationData: []byte{
			0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
			0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
			0xb8, 0x56, 0x81, 0x8a,
		},
	}

	validAuthenticationByte = []byte{
		0x02, 0x00, 0x00, 0x00, 0x7d, 0x09, 0x18, 0x42,
		0x60, 0x9c, 0x9e, 0x20, 0x56, 0x9f, 0xc0, 0x39,
		0xda, 0x3f, 0x22, 0x2a, 0xb8, 0x56, 0x81, 0x8a,
	}
)

func TestAuthenticationMarshal(t *testing.T) {
	testcases := []struct {
		description    string
		authentication Authentication
		expMarshal     []byte
	}{
		{
			description:    "Authentication marshal",
			authentication: validAuthentication,
			expMarshal:     validAuthenticationByte,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.authentication.marshal()
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, result)
		})
	}
}

func TestAuthenticationUnmarshal(t *testing.T) {
	testcases := []struct {
		description string
		b           []byte
		expErr      bool
		expMarshal  Authentication
	}{
		{
			description: "No sufficient bytes to decode next Authentication",
			b: []byte{
				0x01, 0x02, 0x03, 0x04,
			},
			expErr: true,
		},
		{
			description: "Authentication Unmarshal",
			b:           validAuthenticationByte,
			expMarshal:  validAuthentication,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var authentication Authentication
			err := authentication.unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, authentication)
			}
		})
	}
}
