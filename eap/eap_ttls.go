package eap

import (
	"encoding/binary"

	"github.com/pkg/errors"
)

var _ EapTypeData = &EapTtls{}

// EAP-TTLS flag bits (shared EAP-TLS framing, RFC 5281 / RFC 5216).
const (
	EapTlsFlagLengthIncluded byte = 0x80
	EapTlsFlagMoreFragments  byte = 0x40
	EapTlsFlagStart          byte = 0x20
)

// EapTtls is one EAP-TTLS packet's type-data (excluding the shared EAP header).
// Wire format: [Type=21][Flags][Message-Length(4, present iff L flag)][TLS data].
type EapTtls struct {
	Flags         byte
	MessageLength uint32
	TLSData       []byte
}

func (*EapTtls) Type() EapType { return EapTypeTtls }

func (e *EapTtls) Marshal() ([]byte, error) {
	out := []byte{byte(EapTypeTtls), e.Flags}
	if e.Flags&EapTlsFlagLengthIncluded != 0 {
		lenField := make([]byte, 4)
		binary.BigEndian.PutUint32(lenField, e.MessageLength)
		out = append(out, lenField...)
	}
	out = append(out, e.TLSData...)
	return out, nil
}

func (e *EapTtls) Unmarshal(b []byte) error {
	// b starts at the Type byte.
	if len(b) < 2 {
		return errors.Errorf("EapTtls: too short (%d bytes)", len(b))
	}
	if EapType(b[0]) != EapTypeTtls {
		return errors.Errorf("EapTtls: expect type %d but got %d", EapTypeTtls, b[0])
	}
	e.Flags = b[1]
	pos := 2
	if e.Flags&EapTlsFlagLengthIncluded != 0 {
		if len(b) < pos+4 {
			return errors.Errorf("EapTtls: L flag set but no room for Message-Length")
		}
		e.MessageLength = binary.BigEndian.Uint32(b[pos : pos+4])
		pos += 4
	}
	e.TLSData = append([]byte(nil), b[pos:]...)
	return nil
}
