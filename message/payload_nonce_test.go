package message

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	validNonce = Nonce{
		NonceData: []byte{
			0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
			0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
			0xb8, 0x56, 0x81, 0x8a,
		},
	}

	validNonceByte = []byte{
		0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
		0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
		0xb8, 0x56, 0x81, 0x8a,
	}
)

func TestNonceMarshal(t *testing.T) {
	testcases := []struct {
		description string
		nonce       Nonce
		expMarshal  []byte
	}{
		{
			description: "Nonce marshal",
			nonce:       validNonce,
			expMarshal:  validNonceByte,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.nonce.Marshal()
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, result)
		})
	}
}

func TestNonceUnmarshal(t *testing.T) {
	testcases := []struct {
		description string
		b           []byte
		expErr      bool
		expMarshal  Nonce
	}{
		{
			description: "Nonce Unmarshal",
			b:           validNonceByte,
			expMarshal:  validNonce,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var nonce Nonce
			err := nonce.Unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, nonce)
			}
		})
	}
}
