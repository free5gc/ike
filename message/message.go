package message

import (
	"encoding/binary"

	"github.com/pkg/errors"

	eap_message "github.com/free5gc/ike/message/eap"
	ike_types "github.com/free5gc/ike/types"
)

type IKEMessage struct {
	*IKEHeader
	Payloads IKEPayloadContainer
}

func NewMessage(
	iSPI, rSPI uint64, exchgType uint8,
	response, initiator bool, mId uint32,
	payloads IKEPayloadContainer,
) *IKEMessage {
	m := &IKEMessage{
		IKEHeader: NewHeader(iSPI, rSPI, exchgType,
			response, initiator, mId, uint8(ike_types.NoNext), nil),
		Payloads: payloads,
	}
	return m
}

func (m *IKEMessage) Encode() ([]byte, error) {
	if len(m.Payloads) > 0 {
		m.IKEHeader.NextPayload = uint8(m.Payloads[0].Type())
	} else {
		m.IKEHeader.NextPayload = uint8(ike_types.NoNext)
	}

	var err error
	m.IKEHeader.PayloadBytes, err = m.Payloads.Encode()
	if err != nil {
		return nil, errors.Errorf("Encode(): EncodePayload failed: %+v", err)
	}
	return m.IKEHeader.Marshal()
}

func (m *IKEMessage) Decode(b []byte) error {
	var err error
	m.IKEHeader, err = ParseHeader(b)
	if err != nil {
		return errors.Wrapf(err, "Decode()")
	}

	err = m.DecodePayload(m.PayloadBytes)
	if err != nil {
		return errors.Errorf("Decode(): DecodePayload failed: %v", err)
	}

	return nil
}

func (m *IKEMessage) DecodePayload(b []byte) error {
	err := m.Payloads.Decode(m.NextPayload, b)
	if err != nil {
		return errors.Errorf("DecodePayload(): DecodePayload failed: %v", err)
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
			if payload.Type() == ike_types.TypeSK {
				payloadData[0] = payload.(*Encrypted).NextPayload
			} else {
				payloadData[0] = byte(ike_types.NoNext)
			}
		}

		data, err := payload.Marshal()
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

		switch ike_types.IkePayloadType(nextPayload) {
		case ike_types.TypeSA:
			payload = new(SecurityAssociation)
		case ike_types.TypeKE:
			payload = new(KeyExchange)
		case ike_types.TypeIDi:
			payload = new(IdentificationInitiator)
		case ike_types.TypeIDr:
			payload = new(IdentificationResponder)
		case ike_types.TypeCERT:
			payload = new(Certificate)
		case ike_types.TypeCERTreq:
			payload = new(CertificateRequest)
		case ike_types.TypeAUTH:
			payload = new(Authentication)
		case ike_types.TypeNiNr:
			payload = new(Nonce)
		case ike_types.TypeN:
			payload = new(Notification)
		case ike_types.TypeD:
			payload = new(Delete)
		case ike_types.TypeV:
			payload = new(VendorID)
		case ike_types.TypeTSi:
			payload = new(TrafficSelectorInitiator)
		case ike_types.TypeTSr:
			payload = new(TrafficSelectorResponder)
		case ike_types.TypeSK:
			encryptedPayload := new(Encrypted)
			encryptedPayload.NextPayload = b[0]
			payload = encryptedPayload
		case ike_types.TypeCP:
			payload = new(Configuration)
		case ike_types.TypeEAP:
			payload = new(eap_message.EAP)
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

		if err := payload.Unmarshal(b[4:payloadLength]); err != nil {
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
	Type() ike_types.IkePayloadType

	// Called by Encode() or Decode()
	Marshal() ([]byte, error)
	Unmarshal(b []byte) error
}
