package message

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	validCertificate = Certificate{
		CertificateEncoding: ID_FQDN,
		CertificateData: []byte{
			0x6e, 0x33, 0x69, 0x77, 0x66, 0x2e, 0x73, 0x61,
			0x76, 0x69, 0x61, 0x68, 0x35, 0x67, 0x63, 0x2e,
			0x6f, 0x72, 0x67,
		},
	}

	validCertificateByte = []byte{
		0x02, 0x6e, 0x33, 0x69, 0x77, 0x66, 0x2e, 0x73,
		0x61, 0x76, 0x69, 0x61, 0x68, 0x35, 0x67, 0x63,
		0x2e, 0x6f, 0x72, 0x67,
	}
)

func TestCertificateMarshal(t *testing.T) {
	testcases := []struct {
		description string
		crt         Certificate
		expMarshal  []byte
	}{
		{
			description: "Certificate marshal",
			crt:         validCertificate,
			expMarshal:  validCertificateByte,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.crt.marshal()
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, result)
		})
	}
}

func TestCertificateUnmarshal(t *testing.T) {
	testcases := []struct {
		description string
		b           []byte
		expErr      bool
		expMarshal  Certificate
	}{
		{
			description: "No sufficient bytes to decode next certificate",
			b: []byte{
				0x01,
			},
			expErr: true,
		},
		{
			description: "Certificate Unmarshal",
			b:           validCertificateByte,
			expMarshal:  validCertificate,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var crt Certificate
			err := crt.unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, crt)
			}
		})
	}
}
