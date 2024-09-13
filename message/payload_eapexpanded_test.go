package message

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	validEAPExpanded = EAPExpanded{
		VendorID:   VendorID3GPP,
		VendorType: VendorTypeEAP5G,
		VendorData: []byte{
			0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
			0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
			0xb8, 0x56, 0x81, 0x8a,
		},
	}

	validEAPExpandedByte = []byte{
		0xfe, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x00, 0x03,
		0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
		0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
		0xb8, 0x56, 0x81, 0x8a,
	}
)

func TestEAPExpandedMarshal(t *testing.T) {
	testcases := []struct {
		description string
		eap         EAPExpanded
		expMarshal  []byte
		expErr      bool
	}{
		{
			description: "EAPExpanded marshal",
			eap:         validEAPExpanded,
			expMarshal:  validEAPExpandedByte,
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

func TestEAPExpandedUnmarshal(t *testing.T) {
	testcases := []struct {
		description string
		b           []byte
		expMarshal  EAPExpanded
		expErr      bool
	}{
		{
			description: "No sufficient bytes to decode the EAP expanded type",
			b: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			},
			expErr: true,
		},
		{
			description: "EAPExpanded Unmarshal",
			b:           validEAPExpandedByte,
			expMarshal:  validEAPExpanded,
			expErr:      false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var eap EAPExpanded
			err := eap.unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, eap)
			}
		})
	}
}
