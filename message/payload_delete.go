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
		// RFC 7296 gives the Delete payload no padding: the body after the generic header is
		// exactly SPI Size x Num of SPIs bytes. Requiring equality (not just a lower bound)
		// also rejects a body with trailing garbage, which the loop below would read as SPIs.
		if len(b) != (4 + (int(spiSize) * int(numberOfSPI))) {
			return errors.Errorf("Delete: body length %d does not match header (spiSize %d x %d SPIs)",
				len(b), spiSize, numberOfSPI)
		}
		// The SPIs are read as 4-byte words below, so the bytes after the 4-byte header have to
		// be a whole number of them. The length-match check above does not guarantee that on its
		// own (e.g. spiSize 2 with one SPI gives a 6-byte body), and a body that is not a
		// multiple of 4 used to read its trailing partial word as a whole one and panic with
		// "slice bounds out of range".
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
