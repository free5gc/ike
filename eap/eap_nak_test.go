package eap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	validEapNak = EapNak{
		NakData: []byte{
			0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
			0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
			0xb8, 0x56, 0x81, 0x8a,
		},
	}

	validEapNakByte = []byte{
		0x03, 0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e,
		0x20, 0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22,
		0x2a, 0xb8, 0x56, 0x81, 0x8a,
	}
)

func TestEapNakMarshal(t *testing.T) {
	testcases := []struct {
		description string
		eap         EapNak
		expMarshal  []byte
		expErr      bool
	}{
		{
			description: "EAP nak is empty",
			eap: EapNak{
				NakData: nil,
			},
			expErr: true,
		},
		{
			description: "EapNak Marshal",
			eap:         validEapNak,
			expMarshal:  validEapNakByte,
			expErr:      false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.eap.Marshal()
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, result)
			}
		})
	}
}

func TestEapNakUnmarshal(t *testing.T) {
	testcases := []struct {
		description string
		b           []byte
		expMarshal  EapNak
	}{
		{
			description: "EapNak Unmarshal",
			b:           validEapNakByte,
			expMarshal:  validEapNak,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var eap EapNak
			err := eap.Unmarshal(tc.b)
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, eap)
		})
	}
}
