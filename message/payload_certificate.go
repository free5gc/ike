package message

import (
	"github.com/pkg/errors"

	ike_types "github.com/free5gc/ike/types"
)

var _ IKEPayload = &Certificate{}

type Certificate struct {
	CertificateEncoding uint8
	CertificateData     []byte
}

func (certificate *Certificate) Type() ike_types.IkePayloadType { return ike_types.TypeCERT }

func (certificate *Certificate) Marshal() ([]byte, error) {
	certificateData := make([]byte, 1)
	certificateData[0] = certificate.CertificateEncoding
	certificateData = append(certificateData, certificate.CertificateData...)
	return certificateData, nil
}

func (certificate *Certificate) Unmarshal(b []byte) error {
	if len(b) > 0 {
		// bounds checking
		if len(b) <= 1 {
			return errors.Errorf("Certificate: No sufficient bytes to decode next certificate")
		}

		certificate.CertificateEncoding = b[0]
		certificate.CertificateData = append(certificate.CertificateData, b[1:]...)
	}

	return nil
}
