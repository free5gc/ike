package message

import (
	"github.com/pkg/errors"
)

var _ IKEPayload = &CertificateRequest{}

type CertificateRequest struct {
	CertificateEncoding    uint8
	CertificationAuthority []byte
}

func (certificateRequest *CertificateRequest) Type() IkePayloadType {
	return TypeCERTreq
}

func (certificateRequest *CertificateRequest) Marshal() ([]byte, error) {
	certificateRequestData := make([]byte, 1)
	certificateRequestData[0] = certificateRequest.CertificateEncoding
	certificateRequestData = append(certificateRequestData, certificateRequest.CertificationAuthority...)
	return certificateRequestData, nil
}

func (certificateRequest *CertificateRequest) Unmarshal(b []byte) error {
	if len(b) > 0 {
		// bounds checking
		if len(b) <= 1 {
			return errors.Errorf("CertificateRequest: No sufficient bytes to decode next certificate request")
		}

		certificateRequest.CertificateEncoding = b[0]
		certificateRequest.CertificationAuthority = append(certificateRequest.CertificationAuthority, b[1:]...)
	}

	return nil
}
