package message

var _ IKEPayload = &VendorID{}

type VendorID struct {
	VendorIDData []byte
}

func (vendorID *VendorID) Type() IKEPayloadType { return TypeV }

func (vendorID *VendorID) marshal() ([]byte, error) {
	return vendorID.VendorIDData, nil
}

func (vendorID *VendorID) unmarshal(b []byte) error {
	if len(b) > 0 {
		vendorID.VendorIDData = append(vendorID.VendorIDData, b...)
	}
	return nil
}
