package message

import (
	"encoding/binary"

	"github.com/pkg/errors"
)

var _ IKEPayload = &EAP{}

type EAP struct {
	Code        uint8
	Identifier  uint8
	EAPTypeData EAPTypeDataContainer
}

type EAPTypeDataContainer []EAPTypeFormat

type EAPTypeFormat interface {
	// Type specifies EAP types
	Type() EAPType

	// Called by EAP.marshal() or EAP.unmarshal()
	marshal() ([]byte, error)
	unmarshal(b []byte) error
}

func (eap *EAP) Type() IKEPayloadType { return TypeEAP }

func (eap *EAP) marshal() ([]byte, error) {
	eapData := make([]byte, 4)

	eapData[0] = eap.Code
	eapData[1] = eap.Identifier

	if len(eap.EAPTypeData) > 0 {
		eapTypeData, err := eap.EAPTypeData[0].marshal()
		if err != nil {
			return nil, errors.Errorf("EAP: EAP type data marshal failed: %+v", err)
		}

		eapData = append(eapData, eapTypeData...)
	}

	eapDataLen := len(eapData)
	if eapDataLen > 0xFFFF {
		return nil, errors.Errorf("EAP: eapData length exceeds uint16 limit: %d", eapDataLen)
	}
	binary.BigEndian.PutUint16(eapData[2:4], uint16(eapDataLen))
	return eapData, nil
}

func (eap *EAP) unmarshal(b []byte) error {
	if len(b) > 0 {
		// bounds checking
		if len(b) < 4 {
			return errors.Errorf("EAP: No sufficient bytes to decode next EAP payload")
		}
		eapPayloadLength := binary.BigEndian.Uint16(b[2:4])
		if eapPayloadLength < 4 {
			return errors.Errorf("EAP: Payload length specified in the header is too small for EAP")
		}
		if len(b) != int(eapPayloadLength) {
			return errors.Errorf("EAP: Received payload length not matches the length specified in header")
		}

		eap.Code = b[0]
		eap.Identifier = b[1]

		// EAP Success or Failed
		if eapPayloadLength == 4 {
			return nil
		}

		eapType := b[4]
		var eapTypeData EAPTypeFormat

		switch EAPType(eapType) {
		case EAPTypeIdentity:
			eapTypeData = new(EAPIdentity)
		case EAPTypeNotification:
			eapTypeData = new(EAPNotification)
		case EAPTypeNak:
			eapTypeData = new(EAPNak)
		case EAPTypeExpanded:
			eapTypeData = new(EAPExpanded)
		default:
			// TODO: Create unsupprted type to handle it
			return errors.Errorf("EAP: Not supported EAP type")
		}

		if err := eapTypeData.unmarshal(b[4:]); err != nil {
			return errors.Errorf("EAP: Unamrshal EAP type data failed: %+v", err)
		}

		eap.EAPTypeData = append(eap.EAPTypeData, eapTypeData)
	}

	return nil
}
