package message

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeleteMarshal(t *testing.T) {
	testcases := []struct {
		description string
		delete      Delete
		expMarshal  []byte
		expErr      bool
	}{
		{
			description: "Number of SPI not correct",
			delete: Delete{
				ProtocolID:  TypeESP,
				SPISize:     4,
				NumberOfSPI: 1,
				SPIs:        []uint32{0x01, 0x02, 0x03},
			},
			expErr: true,
		},
		{
			description: "Delete marshal TypeIKE",
			delete: Delete{
				ProtocolID:  TypeIKE,
				SPISize:     0,
				NumberOfSPI: 0,
				SPIs:        nil,
			},
			expMarshal: []byte{
				0x01, 0x00, 0x00, 0x00,
			},
			expErr: false,
		},
		{
			description: "Delete marshal TypeESP",
			delete: Delete{
				ProtocolID:  TypeESP,
				SPISize:     4,
				NumberOfSPI: 4,
				SPIs:        []uint32{0x01, 0x02, 0x03, 0x04},
			},
			expMarshal: []byte{
				0x03, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03,
				0x00, 0x00, 0x00, 0x04,
			},
			expErr: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.delete.Marshal()
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, result)
			}
		})
	}
}

func TestDeleteUnmarshal(t *testing.T) {
	testcases := []struct {
		description string
		b           []byte
		expErr      bool
		expMarshal  Delete
	}{
		{
			description: "No sufficient bytes to decode next delete",
			b:           []byte{0x01, 0x02, 0x03},
			expErr:      true,
		},
		{
			description: "No Sufficient bytes to get SPIs according to the length specified in header",
			b:           []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expErr:      true,
		},
		{
			description: "Delete Unmarshal",
			b: []byte{
				0x03, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03,
				0x00, 0x00, 0x00, 0x04,
			},
			expMarshal: Delete{
				ProtocolID:  TypeESP,
				SPISize:     4,
				NumberOfSPI: 4,
				SPIs:        []uint32{0x01, 0x02, 0x03, 0x04},
			},
			expErr: false,
		},
		{
			description: "SPI data is not a whole number of 4-byte words",
			// The header declares one 4-byte SPI but the payload body is one byte longer, so
			// the trailing partial word used to be read as a whole one.
			b: []byte{
				0x03, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
			},
			expErr: true,
		},
		{
			description: "No SPI is declared but the body still carries trailing bytes",
			b: []byte{
				0x01, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC,
			},
			expErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var d Delete
			err := d.Unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, d)
			}
		})
	}
}
