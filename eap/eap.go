package eap

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

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

var typeStr = map[EapType]string{
	EapTypeIdentity:     "EAP-Identity",
	EapTypeNotification: "EAP-Notification",
	EapTypeNak:          "EAP-Nak",
	EapTypeAkaPrime:     "EAP-AKA'",
	EapTypeExpanded:     "EAP-Expanded",
}

func (eapType EapType) String() string {
	s, ok := typeStr[eapType]
	if !ok {
		return fmt.Sprintf("EAP type[%d] is not supported", eapType)
	}
	return s
}

// Length of EAP header
const (
	EapHeaderCodeLen       = 1
	EapHeaderIdentifierLen = 1
	EapHeaderLengthLen     = 2
	EapHeaderTypeLen       = 1
)

type EapCode uint8

const (
	// 	0                   1                   2                   3
	//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//    |     Code      |  Identifier   |            Length             |
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//    |     Type      |  Type-Data ...
	//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

	EapCodeRequest EapCode = iota + 1
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
	// Type specifies EAP types
	Type() EapType

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
	Code        EapCode
	Identifier  uint8
	EapTypeData EapTypeData
}

func (eap *EAP) Marshal() ([]byte, error) {
	eapData := make([]byte, 4)

	eapData[0] = byte(eap.Code)
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

		eap.Code = EapCode(b[0])
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

// key is k_aut
func (eap *EAP) CalcEapAkaPrimeAtMAC(key []byte) ([]byte, error) {
	// check EAP type is EAP-AKA'
	dataType := eap.EapTypeData.Type()
	if dataType != EapTypeAkaPrime {
		return nil, errors.Errorf("Expected EAP-AKA' type, but got %s", dataType.String())
	}
	eapAkaPrime := eap.EapTypeData.(*EapAkaPrime)

	// Reset AT_MAC
	err := eapAkaPrime.InitMac()
	if err != nil {
		return nil, errors.Wrapf(err, "EAP init EAP-AKA' AT_MAC failed")
	}

	// It will need the whole EAP message to calculate AT_MAC
	eapBytes, err := eap.Marshal()
	if err != nil {
		return nil, errors.Wrapf(err, "EAP marshal failed")
	}

	// Calculate AT_MAC
	h := hmac.New(sha256.New, key)
	_, err = h.Write(eapBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "EAP calculate EAP-AKA' AT_MAC failed")
	}
	sum := h.Sum(nil)

	return sum[:16], nil
}
