package message

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	validEAPIdentity = EAPIdentity{
		IdentityData: []byte{
			0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
			0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
			0xb8, 0x56, 0x81, 0x8a,
		},
	}

	validEAPIdentityByte = []byte{
		0x01, 0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e,
		0x20, 0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22,
		0x2a, 0xb8, 0x56, 0x81, 0x8a,
	}
)

func TestEAPIdentityMarshal(t *testing.T) {
	testcases := []struct {
		description string
		eap         EAPIdentity
		expMarshal  []byte
		expErr      bool
	}{
		{
			description: "EAP identity is empty",
			eap: EAPIdentity{
				IdentityData: nil,
			},
			expErr: true,
		},
		{
			description: "EAPIdentity marshal",
			eap:         validEAPIdentity,
			expMarshal:  validEAPIdentityByte,
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

func TestEAPIdentityUnmarshal(t *testing.T) {
	testcases := []struct {
		description string
		b           []byte
		expMarshal  EAPIdentity
	}{
		{
			description: "EAPIdentity Unmarshal",
			b:           validEAPIdentityByte,
			expMarshal:  validEAPIdentity,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var eap EAPIdentity
			err := eap.unmarshal(tc.b)
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, eap)
		})
	}
}
