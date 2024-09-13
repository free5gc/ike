package message

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIdentificationInitiatorMarshal(t *testing.T) {
	testcases := []struct {
		description string
		id          IdentificationInitiator
		expMarshal  []byte
	}{
		{
			description: "IdentificationInitiator marshal",
			id: IdentificationInitiator{
				IDType: ID_KEY_ID,
				IDData: []byte{
					0x55, 0x45,
				},
			},
			expMarshal: []byte{
				0xb, 0x0, 0x0, 0x0, 0x55, 0x45,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.id.marshal()
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, result)
		})
	}
}

func TestIdentificationInitiatorUnmarshal(t *testing.T) {
	testcases := []struct {
		description string
		b           []byte
		expErr      bool
		expMarshal  IdentificationInitiator
	}{
		{
			description: "No sufficient bytes to decode next identification",
			b: []byte{
				0x01, 0x02, 0x03,
			},
			expErr: true,
		},
		{
			description: "IdentificationInitiator Unmarshal",
			b: []byte{
				0xb, 0x0, 0x0, 0x0, 0x55, 0x45,
			},
			expMarshal: IdentificationInitiator{
				IDType: ID_KEY_ID,
				IDData: []byte{
					0x55, 0x45,
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var id IdentificationInitiator
			err := id.unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, id)
			}
		})
	}
}
