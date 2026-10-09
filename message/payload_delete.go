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
	SPIs        []uint32
}

func (d *Delete) Type() IkePayloadType { return TypeD }

func (d *Delete) Marshal() ([]byte, error) {
	if len(d.SPIs) != int(d.NumberOfSPI) {
		return nil, errors.Errorf("Number of SPI not correct")
	}

	deleteData := make([]byte, 4)

	deleteData[0] = d.ProtocolID
	deleteData[1] = d.SPISize
	binary.BigEndian.PutUint16(deleteData[2:4], d.NumberOfSPI)

	if int(d.NumberOfSPI) > 0 {
		byteSlice := make([]byte, d.SPISize)
		for _, v := range d.SPIs {
			binary.BigEndian.PutUint32(byteSlice, v)
			deleteData = append(deleteData, byteSlice...)
		}
	}

	return deleteData, nil
}

func (d *Delete) Unmarshal(b []byte) error {
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
		// The SPIs are read as 4-byte words below, so the bytes after the 4-byte header have to
		// be a whole number of them. A body that is not a multiple of 4 used to read its trailing
		// partial word as a whole one and panic with "slice bounds out of range".
		if (len(b)-4)%4 != 0 {
			return errors.Errorf("Delete: SPI data length %d is not a multiple of 4", len(b)-4)
		}

		d.ProtocolID = b[0]
		d.SPISize = spiSize
		d.NumberOfSPI = numberOfSPI

		b = b[4:]
		var spi uint32
		for i := 0; i < len(b); i += 4 {
			spi = binary.BigEndian.Uint32(b[i : i+4])
			d.SPIs = append(d.SPIs, spi)
		}
	}

	return nil
}
