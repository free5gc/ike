package message

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	validCertificateRequest = CertificateRequest{
		CertificateEncoding: ID_FQDN,
		CertificationAuthority: []byte{
			0x6e, 0x33, 0x69, 0x77, 0x66, 0x2e, 0x73, 0x61,
			0x76, 0x69, 0x61, 0x68, 0x35, 0x67, 0x63, 0x2e,
			0x6f, 0x72, 0x67,
		},
	}

	validCertificateRequestByte = []byte{
		0x02, 0x6e, 0x33, 0x69, 0x77, 0x66, 0x2e, 0x73,
		0x61, 0x76, 0x69, 0x61, 0x68, 0x35, 0x67, 0x63,
		0x2e, 0x6f, 0x72, 0x67,
	}
)

func TestCertificateRequestMarshal(t *testing.T) {
	testcases := []struct {
		description string
		crt         CertificateRequest
		expMarshal  []byte
	}{
		{
			description: "CertificateRequest marshal",
			crt:         validCertificateRequest,
			expMarshal:  validCertificateRequestByte,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.crt.Marshal()
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, result)
		})
	}
}

func TestCertificateRequestUnmarshal(t *testing.T) {
	testcases := []struct {
		description string
		b           []byte
		expErr      bool
		expMarshal  CertificateRequest
	}{
		{
			description: "No sufficient bytes to decode next certificate request",
			b: []byte{
				0x01,
			},
			expErr: true,
		},
		{
			description: "CertificateRequest Unmarshal",
			b:           validCertificateRequestByte,
			expMarshal:  validCertificateRequest,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var crt CertificateRequest
			err := crt.Unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, crt)
			}
		})
	}
}
