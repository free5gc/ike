package message

import (
	"encoding/binary"

	"github.com/pkg/errors"
)

var _ IKEPayload = &Delete{}

type Delete struct {
	ProtocolID  uint8
	SPISize     uint8
	NumberOfSPI uint16
	SPIs        []byte
}

func (d *Delete) Type() IKEPayloadType { return TypeD }

func (d *Delete) marshal() ([]byte, error) {
	if len(d.SPIs) != (int(d.SPISize) * int(d.NumberOfSPI)) {
		return nil, errors.Errorf("Total bytes of all SPIs not correct")
	}

	deleteData := make([]byte, 4)

	deleteData[0] = d.ProtocolID
	deleteData[1] = d.SPISize
	binary.BigEndian.PutUint16(deleteData[2:4], d.NumberOfSPI)

	if int(d.NumberOfSPI) > 0 {
		deleteData = append(deleteData, d.SPIs...)
	}

	return deleteData, nil
}

func (d *Delete) unmarshal(b []byte) error {
	if len(b) > 0 {
		// bounds checking
		if len(b) <= 3 {
			return errors.Errorf("Delete: No sufficient bytes to decode next delete")
		}
		spiSize := b[1]
		numberOfSPI := binary.BigEndian.Uint16(b[2:4])
		if len(b) < (4 + (int(spiSize) * int(numberOfSPI))) {
			return errors.Errorf("Delete: No Sufficient bytes to get SPIs according to the length specified in header")
		}

		d.ProtocolID = b[0]
		d.SPISize = spiSize
		d.NumberOfSPI = numberOfSPI

		d.SPIs = append(d.SPIs, b[4:]...)
	}

	return nil
}
