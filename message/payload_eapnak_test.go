package message

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	validEAPNak = EAPNak{
		NakData: []byte{
			0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
			0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
			0xb8, 0x56, 0x81, 0x8a,
		},
	}

	validEAPNakByte = []byte{
		0x03, 0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e,
		0x20, 0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22,
		0x2a, 0xb8, 0x56, 0x81, 0x8a,
	}
)

func TestEAPNakMarshal(t *testing.T) {
	testcases := []struct {
		description string
		eap         EAPNak
		expMarshal  []byte
		expErr      bool
	}{
		{
			description: "EAP nak is empty",
			eap: EAPNak{
				NakData: nil,
			},
			expErr: true,
		},
		{
			description: "EAPNak marshal",
			eap:         validEAPNak,
			expMarshal:  validEAPNakByte,
			expErr:      false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.eap.marshal()
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, result)
			}
		})
	}
}

func TestEAPNakUnmarshal(t *testing.T) {
	testcases := []struct {
		description string
		b           []byte
		expMarshal  EAPNak
	}{
		{
			description: "EAPNak Unmarshal",
			b:           validEAPNakByte,
			expMarshal:  validEAPNak,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var eap EAPNak
			err := eap.unmarshal(tc.b)
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, eap)
		})
	}
}
