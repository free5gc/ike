package message

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	validVendorID = VendorID{
		VendorIDData: []byte{
			0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
			0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
			0xb8, 0x56, 0x81, 0x8a,
		},
	}

	validVendorIDByte = []byte{
		0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
		0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
		0xb8, 0x56, 0x81, 0x8a,
	}
)

func TestVendorIDMarshal(t *testing.T) {
	testcases := []struct {
		description string
		vendorID    VendorID
		expMarshal  []byte
	}{
		{
			description: "VendorID marshal",
			vendorID:    validVendorID,
			expMarshal:  validVendorIDByte,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.vendorID.marshal()
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, result)
		})
	}
}

func TestVendorIDUnmarshal(t *testing.T) {
	testcases := []struct {
		description string
		b           []byte
		expMarshal  VendorID
	}{
		{
			description: "VendorID Unmarshal",
			b:           validVendorIDByte,
			expMarshal:  validVendorID,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var vendorID VendorID
			err := vendorID.unmarshal(tc.b)
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, vendorID)
		})
	}
}
