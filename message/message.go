package message

import (
	"encoding/binary"

	"github.com/pkg/errors"
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
}

type IKEMessage struct {
	*IKEHeader
	Payloads IKEPayloadContainer
}

func ParseIkeHeader(b []byte) (*IKEHeader, error) {
	// IKE message packet format this implementation referenced is
	// defined in RFC 7296, Section 3.1
	// bounds checking
	if len(b) < IKE_HEADER_LEN {
		return nil, errors.Errorf("ParseIkeHeader(): Received broken IKE header")
	}
	ikeMessageLength := binary.BigEndian.Uint32(b[24:IKE_HEADER_LEN])
	if ikeMessageLength < uint32(IKE_HEADER_LEN) {
		return nil, errors.Errorf("ParseIkeHeader(): Illegal IKE message length %d < header length %d",
			ikeMessageLength, IKE_HEADER_LEN)
	}
	// len() return int, which is 64 bit on 64-bit host and 32 bit
	// on 32-bit host, so this implementation may potentially cause
	// problem on 32-bit machine
	if len(b) != int(ikeMessageLength) {
		return nil, errors.Errorf("ParseIkeHeader(): The length of received message " +
			"not matchs the length specified in header")
	}

	ikeHeader := new(IKEHeader)

	ikeHeader.InitiatorSPI = binary.BigEndian.Uint64(b[:8])
	ikeHeader.ResponderSPI = binary.BigEndian.Uint64(b[8:16])
	ikeHeader.MajorVersion = b[17] >> 4
	ikeHeader.MinorVersion = b[17] & 0x0F
	ikeHeader.ExchangeType = b[18]
	ikeHeader.Flags = b[19]
	ikeHeader.MessageID = binary.BigEndian.Uint32(b[20:24])
	ikeHeader.NextPayload = b[16]

	return ikeHeader, nil
}

func (ikeMessage *IKEMessage) Encode() ([]byte, error) {
	ikeMessageData := make([]byte, IKE_HEADER_LEN)

	binary.BigEndian.PutUint64(ikeMessageData[0:8], ikeMessage.InitiatorSPI)
	binary.BigEndian.PutUint64(ikeMessageData[8:16], ikeMessage.ResponderSPI)
	ikeMessageData[17] = (ikeMessage.MajorVersion << 4) | (ikeMessage.MinorVersion & 0x0F)
	ikeMessageData[18] = ikeMessage.ExchangeType
	ikeMessageData[19] = ikeMessage.Flags
	binary.BigEndian.PutUint32(ikeMessageData[20:24], ikeMessage.MessageID)

	if len(ikeMessage.Payloads) > 0 {
		ikeMessageData[16] = byte(ikeMessage.Payloads[0].Type())
	} else {
		ikeMessageData[16] = byte(NoNext)
	}

	ikeMessagePayloadData, err := ikeMessage.Payloads.Encode()
	if err != nil {
		return nil, errors.Errorf("Encode(): EncodePayload failed: %+v", err)
	}

	ikeMessageData = append(ikeMessageData, ikeMessagePayloadData...)
	ikeMsgDataLen := len(ikeMessageData)
	if ikeMsgDataLen > 0xFFFFFFFF {
		return nil, errors.Errorf("Encode(): ikeMessageData length exceeds uint32 limit: %d", ikeMsgDataLen)
	}
	binary.BigEndian.PutUint32(ikeMessageData[24:IKE_HEADER_LEN], uint32(ikeMsgDataLen))
	return ikeMessageData, nil
}

func (ikeMessage *IKEMessage) Decode(b []byte) error {
	var err error
	ikeMessage.IKEHeader, err = ParseIkeHeader(b)
	if err != nil {
		return errors.Wrapf(err, "Decode()")
	}

	err = ikeMessage.DecodePayload(b[IKE_HEADER_LEN:])
	if err != nil {
		return errors.Errorf("Decode(): DecodePayload failed: %+v", err)
	}

	return nil
}

func (ikeMessage *IKEMessage) DecodePayload(b []byte) error {
	err := ikeMessage.Payloads.Decode(ikeMessage.NextPayload, b)
	if err != nil {
		return errors.Errorf("DecodePayload(): DecodePayload failed: %+v", err)
	}

	return nil
}

type IKEPayloadContainer []IKEPayload

func (container *IKEPayloadContainer) Encode() ([]byte, error) {
	ikeMessagePayloadData := make([]byte, 0)

	for index, payload := range *container {
		payloadData := make([]byte, 4)     // IKE payload general header
		if (index + 1) < len(*container) { // if it has next payload
			payloadData[0] = uint8((*container)[index+1].Type())
		} else {
			if payload.Type() == TypeSK {
				payloadData[0] = payload.(*Encrypted).NextPayload
			} else {
				payloadData[0] = byte(NoNext)
			}
		}

		data, err := payload.marshal()
		if err != nil {
			return nil, errors.Errorf("EncodePayload(): Failed to marshal payload: %+v", err)
		}

		payloadData = append(payloadData, data...)
		payloadDataLen := len(payloadData)
		if payloadDataLen > 0xFFFF {
			return nil, errors.Errorf("EncodePayload(): payloadData length exceeds uint16 limit: %d", payloadDataLen)
		}
		binary.BigEndian.PutUint16(payloadData[2:4], uint16(payloadDataLen))

		ikeMessagePayloadData = append(ikeMessagePayloadData, payloadData...)
	}

	return ikeMessagePayloadData, nil
}

func (container *IKEPayloadContainer) Decode(nextPayload uint8, b []byte) error {
	for len(b) > 0 {
		// bounds checking
		if len(b) < 4 {
			return errors.Errorf("DecodePayload(): No sufficient bytes to decode next payload")
		}
		payloadLength := binary.BigEndian.Uint16(b[2:4])
		if payloadLength < 4 {
			return errors.Errorf("DecodePayload(): Illegal payload length %d < header length 4", payloadLength)
		}
		if len(b) < int(payloadLength) {
			return errors.Errorf("DecodePayload(): The length of received message not matchs"+
				" the length specified in header: %v", len(b))
		}

		criticalBit := (b[1] & 0x80) >> 7

		var payload IKEPayload

		switch IKEPayloadType(nextPayload) {
		case TypeSA:
			payload = new(SecurityAssociation)
		case TypeKE:
			payload = new(KeyExchange)
		case TypeIDi:
			payload = new(IdentificationInitiator)
		case TypeIDr:
			payload = new(IdentificationResponder)
		case TypeCERT:
			payload = new(Certificate)
		case TypeCERTreq:
			payload = new(CertificateRequest)
		case TypeAUTH:
			payload = new(Authentication)
		case TypeNiNr:
			payload = new(Nonce)
		case TypeN:
			payload = new(Notification)
		case TypeD:
			payload = new(Delete)
		case TypeV:
			payload = new(VendorID)
		case TypeTSi:
			payload = new(TrafficSelectorInitiator)
		case TypeTSr:
			payload = new(TrafficSelectorResponder)
		case TypeSK:
			encryptedPayload := new(Encrypted)
			encryptedPayload.NextPayload = b[0]
			payload = encryptedPayload
		case TypeCP:
			payload = new(Configuration)
		case TypeEAP:
			payload = new(EAP)
		default:
			if criticalBit == 0 {
				// Skip this payload
				nextPayload = b[0]
				b = b[payloadLength:]
				continue
			} else {
				// TODO: Reject this IKE message
				return errors.Errorf("Unknown payload type: %d", nextPayload)
			}
		}

		if err := payload.unmarshal(b[4:payloadLength]); err != nil {
			return errors.Errorf("DecodePayload(): Unmarshal payload failed: %+v", err)
		}

		*container = append(*container, payload)

		nextPayload = b[0]
		b = b[payloadLength:]
	}

	return nil
}

type IKEPayload interface {
	// Type specifies the IKE payload types
	Type() IKEPayloadType

	// Called by Encode() or Decode()
	marshal() ([]byte, error)
	unmarshal(b []byte) error
}
