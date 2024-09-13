package message

import "github.com/pkg/errors"

var _ IKEPayload = &Certificate{}

type Certificate struct {
	CertificateEncoding uint8
	CertificateData     []byte
}

func (certificate *Certificate) Type() IKEPayloadType { return TypeCERT }

func (certificate *Certificate) marshal() ([]byte, error) {
	certificateData := make([]byte, 1)
	certificateData[0] = certificate.CertificateEncoding
	certificateData = append(certificateData, certificate.CertificateData...)
	return certificateData, nil
}

func (certificate *Certificate) unmarshal(b []byte) error {
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
