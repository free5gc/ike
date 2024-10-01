package message

import (
	"encoding/binary"

	"github.com/pkg/errors"
)

// Flags
const (
	ResponseBitCheck  = 0x20
	VersionBitCheck   = 0x10
	InitiatorBitCheck = 0x08
)

const IKE_HEADER_LEN int = 28

type IKEHeader struct {
	InitiatorSPI uint64
	ResponderSPI uint64
	MajorVersion uint8
	MinorVersion uint8
	ExchangeType uint8
	Flags        uint8
	MessageID    uint32
	NextPayload  uint8
	PayloadBytes []byte
}

func NewHeader(
	iSPI, rSPI uint64, exchgType uint8,
	response, initiator bool, mId uint32,
	nextPayload uint8, payloadBytes []byte,
) *IKEHeader {
	h := &IKEHeader{
		InitiatorSPI: iSPI,
		ResponderSPI: rSPI,
		ExchangeType: exchgType,
		MajorVersion: 2,
		MinorVersion: 0,
		MessageID:    mId,
		NextPayload:  nextPayload,
		PayloadBytes: payloadBytes,
	}
	if response {
		h.Flags |= ResponseBitCheck
	}
	if initiator {
		h.Flags |= InitiatorBitCheck
	}
	return h
}

func (h *IKEHeader) Marshal() ([]byte, error) {
	b := make([]byte, IKE_HEADER_LEN)

	binary.BigEndian.PutUint64(b[0:8], h.InitiatorSPI)
	binary.BigEndian.PutUint64(b[8:16], h.ResponderSPI)
	b[16] = h.NextPayload
	b[17] = (h.MajorVersion << 4) | (h.MinorVersion & 0x0F)
	b[18] = h.ExchangeType
	b[19] = h.Flags
	binary.BigEndian.PutUint32(b[20:24], h.MessageID)

	totalLen := IKE_HEADER_LEN + len(h.PayloadBytes)
	if totalLen > 0xFFFFFFFF {
		return nil, errors.Errorf("length exceeds uint32 limit: %d", totalLen)
	}

	binary.BigEndian.PutUint32(b[24:IKE_HEADER_LEN], uint32(totalLen))
	if len(h.PayloadBytes) > 0 {
		b = append(b, h.PayloadBytes...)
	}
	return b, nil
}

func (h *IKEHeader) IsResponse() bool {
	return (h.Flags & ResponseBitCheck) != 0
}

func (h *IKEHeader) IsInitiator() bool {
	return (h.Flags & InitiatorBitCheck) != 0
}

func ParseHeader(b []byte) (*IKEHeader, error) {
	// IKE message packet format this implementation referenced is
	// defined in RFC 7296, Section 3.1
	// bounds checking
	if len(b) < IKE_HEADER_LEN {
		return nil, errors.Errorf("ParseHeader(): Received broken IKE header")
	}

	totalLen := binary.BigEndian.Uint32(b[24:IKE_HEADER_LEN])
	if totalLen < uint32(IKE_HEADER_LEN) {
		return nil, errors.Errorf("ParseHeader(): Illegal IKE message length %d < header length %d",
			totalLen, IKE_HEADER_LEN)
	}

	h := &IKEHeader{
		InitiatorSPI: binary.BigEndian.Uint64(b[:8]),
		ResponderSPI: binary.BigEndian.Uint64(b[8:16]),
		NextPayload:  b[16],
		MajorVersion: b[17] >> 4,
		MinorVersion: b[17] & 0x0F,
		ExchangeType: b[18],
		Flags:        b[19],
		MessageID:    binary.BigEndian.Uint32(b[20:24]),
		PayloadBytes: b[IKE_HEADER_LEN:],
	}

	return h, nil
}
