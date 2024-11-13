package eap

import (
	"encoding/binary"

	"github.com/pkg/errors"
)

// Refer to 3GPP TS 24.502 - 9.3.2 EAP-5G method
// 3GPP Vendor-Id of 10415 (decimal) registered with IANA under the SMI Private Enterprise Code registry.
const VendorId3GPP = 10415

// EAP-5G method (3GPP TS 33.402 - annex C)
const VendorTypeEAP5G = 3

var _ EapTypeData = &EapExpanded{}

// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |               Vendor-Id                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Vendor-Type                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Vendor data...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

type EapExpanded struct {
	VendorID   uint32 // 3 bytes
	VendorType uint32 // 4 bytes
	VendorData []byte
}

func (eapExpanded *EapExpanded) Type() EapType { return EapTypeExpanded }

func (eapExpanded *EapExpanded) Marshal() ([]byte, error) {
	eapExpandedData := make([]byte, 8)

	vendorID := eapExpanded.VendorID & 0x00ffffff
	typeAndVendorID := (uint32(EapTypeExpanded)<<24 | vendorID)

	binary.BigEndian.PutUint32(eapExpandedData[0:4], typeAndVendorID)
	binary.BigEndian.PutUint32(eapExpandedData[4:8], eapExpanded.VendorType)

	if len(eapExpanded.VendorData) == 0 {
		return eapExpandedData, nil
	}

	eapExpandedData = append(eapExpandedData, eapExpanded.VendorData...)

	return eapExpandedData, nil
}

func (eapExpanded *EapExpanded) Unmarshal(b []byte) error {
	if len(b) > 0 {
		if len(b) < 8 {
			return errors.New("EapExpanded: No sufficient bytes to decode the EAP expanded type")
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
