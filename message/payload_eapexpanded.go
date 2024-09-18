package message

import (
	"encoding/binary"

	"github.com/pkg/errors"
)

var _ EAPTypeFormat = &EAPExpanded{}

type EAPExpanded struct {
	VendorID   uint32
	VendorType uint32
	VendorData []byte
}

func (eapExpanded *EAPExpanded) Type() EAPType { return EAPTypeExpanded }

func (eapExpanded *EAPExpanded) marshal() ([]byte, error) {
	eapExpandedData := make([]byte, 8)

	vendorID := eapExpanded.VendorID & 0x00ffffff
	typeAndVendorID := (uint32(EAPTypeExpanded)<<24 | vendorID)

	binary.BigEndian.PutUint32(eapExpandedData[0:4], typeAndVendorID)
	binary.BigEndian.PutUint32(eapExpandedData[4:8], eapExpanded.VendorType)

	if len(eapExpanded.VendorData) == 0 {
		return eapExpandedData, nil
	}

	eapExpandedData = append(eapExpandedData, eapExpanded.VendorData...)
	return eapExpandedData, nil
}

func (eapExpanded *EAPExpanded) unmarshal(b []byte) error {
	if len(b) > 0 {
		if len(b) < 8 {
			return errors.Errorf("EAPExpanded: No sufficient bytes to decode the EAP expanded type")
		}

		typeAndVendorID := binary.BigEndian.Uint32(b[0:4])
		eapExpanded.VendorID = typeAndVendorID & 0x00ffffff

		eapExpanded.VendorType = binary.BigEndian.Uint32(b[4:8])

		if len(b) > 8 {
			eapExpanded.VendorData = append(eapExpanded.VendorData, b[8:]...)
		}
	}
	return nil
}
