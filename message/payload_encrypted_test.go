package message

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	validEncrypted = Encrypted{
		EncryptedData: []byte{
			0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
			0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
			0xb8, 0x56, 0x81, 0x8a,
		},
	}

	validEncryptedByte = []byte{
		0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
		0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
		0xb8, 0x56, 0x81, 0x8a,
	}
)

func TestEncryptedMarshal(t *testing.T) {
	testcases := []struct {
		description string
		encrypted   Encrypted
		expMarshal  []byte
		expErr      bool
	}{
		{
			description: "The encrypted data is empty",
			encrypted: Encrypted{
				EncryptedData: nil,
			},
			expErr: true,
		},
		{
			description: "Encrypted marshal",
			encrypted:   validEncrypted,
			expMarshal:  validEncryptedByte,
			expErr:      false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.encrypted.marshal()
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, result)
			}
		})
	}
}

func TestEncryptedUnmarshal(t *testing.T) {
	testcases := []struct {
		description string
		b           []byte
		expMarshal  Encrypted
	}{
		{
			description: "Encrypted Unmarshal",
			b:           validEncryptedByte,
			expMarshal:  validEncrypted,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var encrypted Encrypted
			err := encrypted.unmarshal(tc.b)
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, encrypted)
		})
	}
}
