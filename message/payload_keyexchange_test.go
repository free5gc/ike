package message

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	validDH1024 = KeyExchange{
		DiffieHellmanGroup: DH_1024_BIT_MODP,
		KeyExchangeData: []byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		},
	}
	validDH1024Byte = []byte{
		0x00, 0x02, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
	}

	validDH2048 = KeyExchange{
		DiffieHellmanGroup: DH_2048_BIT_MODP,
		KeyExchangeData: []byte{
			0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		},
	}
	validDH2048Byte = []byte{
		0x00, 0x0e, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44,
		0x55, 0x66, 0x77, 0x88,
	}
)

func TestKeyExchangeMarshal(t *testing.T) {
	testcases := []struct {
		description string
		keyExchange KeyExchange
		expMarshal  []byte
	}{
		{
			description: "Marshal 1024 bit MODP group",
			keyExchange: validDH1024,
			expMarshal:  validDH1024Byte,
		},
		{
			description: "Marshal 2048 bit MODP group",
			keyExchange: validDH2048,
			expMarshal:  validDH2048Byte,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.keyExchange.Marshal()
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, result)
		})
	}
}

func TestKeyExchangeUnmarshal(t *testing.T) {
	testcases := []struct {
		description string
		b           []byte
		expKE       KeyExchange
		expErr      bool
	}{
		{
			description: "No sufficient bytes to decode next key exchange data",
			b: []byte{
				0x01, 0x02, 0x03,
			},
			expErr: true,
		},
		{
			description: "Unmarshal 1024 bit MODP group",
			b:           validDH1024Byte,
			expKE:       validDH1024,
			expErr:      false,
		},
		{
			description: "Unmarshal 2048 bit MODP group",
			b:           validDH2048Byte,
			expKE:       validDH2048,
			expErr:      false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var ke KeyExchange
			err := ke.Unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expKE, ke)
			}
		})
	}
}
