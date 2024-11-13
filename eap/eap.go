package eap

import (
	"encoding/binary"

	"github.com/pkg/errors"
)

// EAP related spec
// RFC 3748 - Extensible Authentication Protocol (EAP)

// EAP types
type EapType uint8

const (
	EapTypeIdentity EapType = iota + 1
	EapTypeNotification
	EapTypeNak
	EapTypeAkaPrime EapType = 50
	EapTypeExpanded EapType = 254
)

// Length of EAP header
const (
	EapHeaderCodeLen       = 1
	EapHeaderIdentifierLen = 1
	EapHeaderLengthLen     = 2
	EapHeaderTypeLen       = 1
)

// Length of EAP-AKA' header
const (
	EapAkaHeaderSubtypeLen  = 1
	EapAkaHeaderReservedLen = 2

	EapAkaAttrTypeLen     = 1
	EapAkaAttrLengthLen   = 1
	EapAkaAttrReservedLen = 2
)

// Types for EAP-5G
// Used in IKE EAP expanded for vendor ID
const VendorId3GPP = 10415

// Used in IKE EAP expanded for vendor data
const VendorTypeEAP5G = 3

const (
	// 	0                   1                   2                   3
	//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//    |     Code      |  Identifier   |            Length             |
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//    |     Type      |  Type-Data ...
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

	EapCodeRequest = iota + 1
	EapCodeResponse
	//     0                   1                   2                   3
	//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//    |     Code      |  Identifier   |            Length             |
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	EapCodeSuccess
	EapCodeFailure
)

type EapTypeData interface {
	// Called by EAP.Marshal() or EAP.Unmarshal()
	Marshal() ([]byte, error)
	Unmarshal(b []byte) error
}

// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Code      |  Identifier   |            Length             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    Data ...
// +-+-+-+-+

type EAP struct {
	Code        uint8
	Identifier  uint8
	EapTypeData EapTypeData
}

func (eap *EAP) Marshal() ([]byte, error) {
	eapData := make([]byte, 4)

	eapData[0] = eap.Code
	eapData[1] = eap.Identifier

	if eap.EapTypeData != nil {
		eapTypeData, err := eap.EapTypeData.Marshal()
		if err != nil {
			return nil, errors.Errorf("EAP: EAP type data marshal failed: %+v", err)
		}

		eapData = append(eapData, eapTypeData...)
	}

	binary.BigEndian.PutUint16(eapData[2:4], uint16(len(eapData)))

	return eapData, nil
}

func (eap *EAP) Unmarshal(b []byte) error {
	if len(b) > 0 {
		// bounds checking
		if len(b) < 4 {
			return errors.New("EAP: No sufficient bytes to decode next EAP payload")
		}
		eapPayloadLength := binary.BigEndian.Uint16(b[2:4])
		if eapPayloadLength < 4 {
			return errors.New("EAP: Payload length specified in the header is too small for EAP")
		}
		if len(b) != int(eapPayloadLength) {
			return errors.New("EAP: Received payload length not matches the length specified in header")
		}

		eap.Code = b[0]
		eap.Identifier = b[1]

		// EAP Success or Failure
		if eapPayloadLength == 4 {
			return nil
		}

		eapType := EapType(b[4])
		var eapTypeData EapTypeData

		switch eapType {
		case EapTypeIdentity:
			eapTypeData = new(EapIdentity)
		case EapTypeNotification:
			eapTypeData = new(EapNotification)
		case EapTypeNak:
			eapTypeData = new(EapNak)
		case EapTypeAkaPrime:
			eapTypeData = new(EapAkaPrime)
		case EapTypeExpanded:
			eapTypeData = new(EapExpanded)
		default:
			return errors.Errorf("EAP: EAP type[%d] is not supported", eapType)
		}

		if err := eapTypeData.Unmarshal(b[4:]); err != nil {
			return errors.Wrapf(err, "EAP: EAP type data unamrshal failed")
		}

		eap.EapTypeData = eapTypeData
	}

	return nil
}
