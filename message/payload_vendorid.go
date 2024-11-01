package message

import (
	ike_types "github.com/free5gc/ike/types"
)

var _ IKEPayload = &VendorID{}

type VendorID struct {
	VendorIDData []byte
}

func (vendorID *VendorID) Type() ike_types.IkePayloadType { return ike_types.TypeV }

func (vendorID *VendorID) Marshal() ([]byte, error) {
	return vendorID.VendorIDData, nil
}

func (vendorID *VendorID) Unmarshal(b []byte) error {
	if len(b) > 0 {
		vendorID.VendorIDData = append(vendorID.VendorIDData, b...)
	}
	return nil
}
