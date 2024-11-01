package message

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"unsafe"

	"github.com/pkg/errors"
)

// EAP types
type EapType uint8

const (
	EapTypeIdentity = iota + 1
	EapTypeNotification
	EapTypeNak
	EapTypeExpanded = 254
	EapTypeAkaPrime = 50
)

const (
	EapCodeRequest = iota + 1
	EapCodeResponse
	EapCodeSuccess
	EapCodeFailure
)

// Length of Attribute field
const (
	EapHeaderLen            = 5
	EapAkaHeaderSubtypeLen  = 1
	EapAkaHeaderReservedLen = 2
	EapAkaAttrTypeLen       = 1
	EapAkaAttrLengthLen     = 1
	EapAkaAttrReservedLen   = 2
)

// EAP AKA' SubType
// RFC 4187 - Section 11
const (
	SubtypeAkaChallenge              = 1
	SubtypeAkaAuthenticationReject   = 2
	SubtypeAkaSynchronizationFailure = 4
	SubtypeAkaIdentity               = 5
	SubtypeAkaNotification           = 12
	SubtypeAkaReauthentication       = 13
	SubtypeAkaClientError            = 14
)

// Attribute Types for EAP-AKA'
type EapAkaPrimeAttrType uint8

var (
	AT_RAND              EapAkaPrimeAttrType = 1
	AT_AUTN              EapAkaPrimeAttrType = 2
	AT_RES               EapAkaPrimeAttrType = 3
	AT_AUTS              EapAkaPrimeAttrType = 4
	AT_MAC               EapAkaPrimeAttrType = 11
	AT_NOTIFICATION      EapAkaPrimeAttrType = 12
	AT_IDENTITY          EapAkaPrimeAttrType = 14
	AT_CLIENT_ERROR_CODE EapAkaPrimeAttrType = 22
	AT_KDF_INPUT         EapAkaPrimeAttrType = 23
	AT_KDF               EapAkaPrimeAttrType = 24
	AT_CHECKCODE         EapAkaPrimeAttrType = 134
)

func (t EapAkaPrimeAttrType) String() string {
	var s string

	switch t {
	case AT_RAND:
		s = "AT_RAND"
	case AT_AUTN:
		s = "AT_AUTN"
	case AT_RES:
		s = "AT_RES"
	case AT_AUTS:
		s = "AT_AUTS"
	case AT_MAC:
		s = "AT_MAC"
	case AT_NOTIFICATION:
		s = "AT_NOTIFICATION"
	case AT_IDENTITY:
		s = "AT_IDENTITY"
	case AT_CLIENT_ERROR_CODE:
		s = "AT_CLIENT_ERROR_CODE"
	case AT_KDF_INPUT:
		s = "AT_KDF_INPUT"
	case AT_KDF:
		s = "AT_KDF"
	case AT_CHECKCODE:
		s = "AT_CHECKCODE"
	default:
		s = "Unsupported type"
	}

	return s
}

func (t EapAkaPrimeAttrType) Value() uint8 { return uint8(t) }

/*
Definition of EAP
Code: 1 byte
Identifier: 1 byte
Length: 2 bytes
Type: 1 byte
*/
type EAP struct {
	Code        uint8
	Identifier  uint8
	EapTypeData EapTypeDataContainer
}

func (eap *EAP) Marshal() ([]byte, error) {
	eapData := make([]byte, 5)

	eapData[0] = eap.Code
	eapData[1] = eap.Identifier

	if len(eap.EapTypeData) > 0 {
		eapTypeData, err := eap.EapTypeData[0].Marshal()
		if err != nil {
			return nil, fmt.Errorf("EAP: EAP type data Marshal failed: %+v", err)
		}

		eapData[4] = byte(eap.EapTypeData[0].Type())
		eapData = append(eapData, eapTypeData...)
	}

	binary.BigEndian.PutUint16(eapData[2:4], uint16(len(eapData)))

	return eapData, nil
}

func (eap *EAP) Unmarshal(rawData []byte) error {
	if len(rawData) > 0 {
		// bounds checking
		if len(rawData) < 4 {
			return errors.New("EAP: No sufficient bytes to decode next EAP payload")
		}
		eapPayloadLength := binary.BigEndian.Uint16(rawData[2:4])
		if eapPayloadLength < 4 {
			return errors.New("EAP: Payload length specified in the header is too small for EAP")
		}
		if len(rawData) != int(eapPayloadLength) {
			return errors.New("EAP: Received payload length not matches the length specified in header")
		}

		eap.Code = rawData[0]
		eap.Identifier = rawData[1]

		// EAP Success or Failed
		if eapPayloadLength == 4 {
			return nil
		}

		eapType := rawData[4]
		var eapTypeData EapTypeFormat

		switch eapType {
		case EapTypeIdentity:
			eapTypeData = new(EapIdentity)
		case EapTypeNotification:
			eapTypeData = new(EapNotification)
		case EapTypeNak:
			eapTypeData = new(EapNak)
		case EapTypeExpanded:
			eapTypeData = new(EapExpanded)
		case EapTypeAkaPrime:
			eapTypeData = new(EapAkaPrime)
		default:
			// TODO: Create unsupprted type to handle it
			return errors.New("EAP: Not supported EAP type")
		}

		if err := eapTypeData.Unmarshal(rawData[5:]); err != nil {
			return fmt.Errorf("EAP: Unamrshal EAP type data failed: %+v", err)
		}

		eap.EapTypeData = append(eap.EapTypeData, eapTypeData)
	}

	return nil
}

type EapTypeDataContainer []EapTypeFormat

type EapTypeFormat interface {
	// Type specifies EAP types
	Type() EapType

	// Called by EAP.Marshal() or EAP.Unmarshal()
	Marshal() ([]byte, error)
	Unmarshal(rawData []byte) error
}

// Definition of EAP Identity

var _ EapTypeFormat = &EapIdentity{}

type EapIdentity struct {
	IdentityData []byte
}

func (eapIdentity *EapIdentity) Type() EapType { return EapTypeIdentity }

func (eapIdentity *EapIdentity) Marshal() ([]byte, error) {
	if len(eapIdentity.IdentityData) == 0 {
		return nil, errors.New("EapIdentity: EAP identity is empty")
	}

	eapIdentityData := make([]byte, 0)
	eapIdentityData = append(eapIdentityData, eapIdentity.IdentityData...)

	return eapIdentityData, nil
}

func (eapIdentity *EapIdentity) Unmarshal(rawData []byte) error {
	if len(rawData) > 1 {
		eapIdentity.IdentityData = append(eapIdentity.IdentityData, rawData...)
	}

	return nil
}

// Definition of EAP Notification

var _ EapTypeFormat = &EapNotification{}

type EapNotification struct {
	NotificationData []byte
}

func (eapNotification *EapNotification) Type() EapType { return EapTypeNotification }

func (eapNotification *EapNotification) Marshal() ([]byte, error) {
	if len(eapNotification.NotificationData) == 0 {
		return nil, errors.New("EapNotification: EAP notification is empty")
	}

	eapNotificationData := make([]byte, 0)
	eapNotificationData = append(eapNotificationData, eapNotification.NotificationData...)

	return eapNotificationData, nil
}

func (eapNotification *EapNotification) Unmarshal(rawData []byte) error {
	if len(rawData) > 1 {
		eapNotification.NotificationData = append(eapNotification.NotificationData, rawData...)
	}

	return nil
}

// Definition of EAP Nak

var _ EapTypeFormat = &EapNak{}

type EapNak struct {
	NakData []byte
}

func (eapNak *EapNak) Type() EapType { return EapTypeNak }

func (eapNak *EapNak) Marshal() ([]byte, error) {
	if len(eapNak.NakData) == 0 {
		return nil, errors.New("EapNak: EAP nak is empty")
	}

	eapNakData := make([]byte, 0)
	eapNakData = append(eapNakData, eapNak.NakData...)

	return eapNakData, nil
}

func (eapNak *EapNak) Unmarshal(rawData []byte) error {
	if len(rawData) > 1 {
		eapNak.NakData = append(eapNak.NakData, rawData...)
	}

	return nil
}

// Definition of EAP expanded

var _ EapTypeFormat = &EapExpanded{}

type EapExpanded struct {
	VendorID   uint32
	VendorType uint32
	VendorData []byte
}

func (eapExpanded *EapExpanded) Type() EapType { return EapTypeExpanded }

func (eapExpanded *EapExpanded) Marshal() ([]byte, error) {
	eapExpandedData := make([]byte, 8)

	vendorID := eapExpanded.VendorID & 0x00ffffff
	typeAndVendorID := (uint32(EapTypeExpanded)<<24 | vendorID)

	binary.BigEndian.PutUint32(eapExpandedData[0:4], typeAndVendorID)
	binary.BigEndian.PutUint32(eapExpandedData[4:8], eapExpanded.VendorType)

	if len(eapExpanded.VendorData) == 0 {
		return eapExpandedData, nil
	}

	eapExpandedData = append(eapExpandedData, eapExpanded.VendorData...)

	return eapExpandedData, nil
}

func (eapExpanded *EapExpanded) Unmarshal(rawData []byte) error {
	if len(rawData) > 0 {
		if len(rawData) < 8 {
			return errors.New("EapExpanded: No sufficient bytes to decode the EAP expanded type")
		}

		typeAndVendorID := binary.BigEndian.Uint32(rawData[0:4])
		eapExpanded.VendorID = typeAndVendorID & 0x00ffffff

		eapExpanded.VendorType = binary.BigEndian.Uint32(rawData[4:8])

		if len(rawData) > 8 {
			eapExpanded.VendorData = append(eapExpanded.VendorData, rawData[8:]...)
		}
	}

	return nil
}

// Definition of EAP-AKA'
var _ EapTypeFormat = &EapAkaPrime{}

type EapAkaPrime struct {
	SubType    uint8
	Reserved   uint16
	Attributes map[EapAkaPrimeAttrType]*EapAkaPrimeAttr
	MacInput   []byte // TODO: Consider the field if is needed
}

func (eapAkaPrime *EapAkaPrime) Type() EapType { return EapTypeAkaPrime }

func (eapAkaPrime *EapAkaPrime) Init(subType uint8) {
	eapAkaPrime.SubType = subType
	eapAkaPrime.Attributes = make(map[EapAkaPrimeAttrType]*EapAkaPrimeAttr)
}

func (eapAkaPrime *EapAkaPrime) Marshal() ([]byte, error) {
	buffer := new(bytes.Buffer)

	err := binary.Write(buffer, binary.BigEndian, eapAkaPrime.SubType)
	if err != nil {
		return nil, errors.Wrapf(err, "EAP-AKA' Marshal(): write subtype failed")
	}
	err = binary.Write(buffer, binary.BigEndian, eapAkaPrime.Reserved)
	if err != nil {
		return nil, errors.Wrapf(err, "EAP-AKA' Marshal(): write reserved failed")
	}

	for _, key := range eapAkaPrime.getAttrsKeys() {
		attr := eapAkaPrime.Attributes[key]

		err = binary.Write(buffer, binary.BigEndian, attr.typeData.Value())
		if err != nil {
			return nil, errors.Wrapf(err, "EAP-AKA' Marshal(): write payload/type failed")
		}

		err = binary.Write(buffer, binary.BigEndian, attr.length)
		if err != nil {
			return nil, errors.Wrapf(err, "EAP-AKA' Marshal(): write payload/length failed")
		}

		if attr.typeData != AT_KDF {
			err = binary.Write(buffer, binary.BigEndian, attr.reserved)
			if err != nil {
				return nil, errors.Wrapf(err, "EAP-AKA' Marshal(): write payload/reserved failed")
			}
		}

		err = binary.Write(buffer, binary.BigEndian, attr.value)
		if err != nil {
			return nil, errors.Wrapf(err, "EAP-AKA' Marshal(): write payload/value failed")
		}
	}

	return buffer.Bytes(), nil
}

func (eapAkaPrime *EapAkaPrime) Unmarshal(rawData []byte) error {
	var err error

	if len(rawData) < 4 {
		return errors.New("EapAkaPrime: No sufficient bytes to decode the EAP AKA' type")
	}
	bufReader := bufio.NewReader(bytes.NewReader(rawData))

	eapAkaPrime.SubType, err = bufReader.ReadByte()
	if err != nil {
		return errors.Wrapf(err, "Read EAP-AKA' SubType failed")
	}

	buf := make([]byte, unsafe.Sizeof(eapAkaPrime.Reserved))
	_, err = io.ReadFull(bufReader, buf)
	if err != nil {
		return errors.Wrapf(err, "Read EAP-AKA' Reserved failed")
	}
	binary.BigEndian.PutUint16(buf, eapAkaPrime.Reserved)

	if eapAkaPrime.Attributes == nil {
		eapAkaPrime.Attributes = map[EapAkaPrimeAttrType]*EapAkaPrimeAttr{}
	}

	for {
		attr := new(EapAkaPrimeAttr)
		var typeData uint8

		// Read EAP-AKA' Attribute type
		typeData, err = bufReader.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return errors.Wrapf(err, "Read EAP-AKA' Attribute type failed")
		}
		attr.typeData = EapAkaPrimeAttrType(typeData)

		// Read EAP-AKA' Attribute length
		attr.length, err = bufReader.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return errors.Wrapf(err, "Read EAP-AKA' Attribute length failed")
		}

		switch attr.typeData {
		case AT_MAC:
			fallthrough
		case AT_RAND:
			fallthrough
		case AT_AUTN:
			// In this case, reserved is no meaning
			reserved := make([]byte, EapAkaAttrReservedLen)
			_, err = io.ReadFull(bufReader, reserved)
			if err != nil {
				if err == io.EOF {
					break
				}
				return errors.Wrapf(err, "Read EAP-AKA' %s reserved failed", attr.typeData)
			}

			valLen := 4*attr.length - EapAkaAttrTypeLen - EapAkaAttrLengthLen - EapAkaAttrReservedLen
			attr.value = make([]byte, valLen)
			_, err = io.ReadFull(bufReader, attr.value)
			if err != nil {
				if err == io.EOF {
					break
				}
				return errors.Wrapf(err, "Read EAP-AKA' %s value failed", attr.typeData)
			}
		case AT_KDF_INPUT:
			fallthrough
		case AT_RES:
			// In this case, reserved will contains the actual length of value
			reserved := make([]byte, EapAkaAttrReservedLen) // The unit of reserved is bit
			_, err = io.ReadFull(bufReader, reserved)
			if err != nil {
				if err == io.EOF {
					break
				}
				return errors.Wrapf(err, "Read EAP-AKA' %s reserved failed", attr.typeData)
			}
			valBitsLen := binary.BigEndian.Uint16(reserved)
			attr.reserved = valBitsLen
			valBytesLen := valBitsLen / 8

			attr.value = make([]byte, valBytesLen)
			_, err = io.ReadFull(bufReader, attr.value)
			if err != nil {
				if err == io.EOF {
					break
				}
				return errors.Wrapf(err, "Read EAP-AKA' %s value failed", attr.typeData)
			}
			// TODO: AT_RES may have padding
		case AT_KDF:
			valLen := 4*attr.length - EapAkaAttrTypeLen - EapAkaAttrLengthLen
			attr.value = make([]byte, valLen)
			_, err = io.ReadFull(bufReader, attr.value)
			if err != nil {
				if err == io.EOF {
					break
				}
				return errors.Wrapf(err, "Read EAP-AKA' %s value failed", attr.typeData)
			}
		}

		eapAkaPrime.Attributes[attr.typeData] = attr
	}

	return nil
}

func (eapAkaPrime *EapAkaPrime) SetAttr(typeData EapAkaPrimeAttrType, value []byte) error {
	attr := new(EapAkaPrimeAttr)

	err := attr.setAttr(typeData, value)
	if err != nil {
		return err
	}

	eapAkaPrime.Attributes[attr.typeData] = attr
	return nil
}

func (eapAkaPrime *EapAkaPrime) GetAttr(typeData EapAkaPrimeAttrType) (EapAkaPrimeAttr, error) {
	for _, attr := range eapAkaPrime.Attributes {
		if attr.typeData == typeData {
			return *attr, nil
		}
	}
	return EapAkaPrimeAttr{}, fmt.Errorf("EapAkaPrimeAttr[%s] not found", typeData)
}

func (eapAkaPrime *EapAkaPrime) InitMac() error {
	zeros := make([]byte, 16)
	return eapAkaPrime.SetAttr(AT_MAC, zeros)
}

func (eapAkaPrime *EapAkaPrime) getAttrsKeys() []EapAkaPrimeAttrType {
	result := make([]EapAkaPrimeAttrType, 0, len(eapAkaPrime.Attributes))

	for key := range eapAkaPrime.Attributes {
		result = append(result, key)
	}

	sort.Slice(result, func(i, j int) bool {
		return uint8(result[i]) < uint8(result[j])
	})

	return result
}

// Len(EapAkaPrimeAttr) = EapAkaPrimeAttr.Length * 4
type EapAkaPrimeAttr struct {
	typeData EapAkaPrimeAttrType
	length   uint8
	reserved uint16
	value    []byte
}

func (attr *EapAkaPrimeAttr) setAttr(typeData EapAkaPrimeAttrType, value []byte) error {
	var err error

	attr.typeData = typeData

	switch typeData {
	case AT_MAC:
		/*
			RFC 5448:
			   When used within EAP-AKA', the AT_MAC attribute is changed as
			   follows.  The MAC algorithm is HMAC-SHA-256-128, a keyed hash value.
			   The HMAC-SHA-256-128 value is obtained from the 32-byte HMAC-SHA-256
			   value by truncating the output to the first 16 bytes.  Hence, the
			   length of the MAC is 16 bytes.
		*/
		/*
		    0                   1                   2                   3
		    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		   |     AT_MAC    | Length = 5    |           Reserved            |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		   |                                                               |
		   |                           MAC                                 |
		   |                                                               |
		   |                                                               |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		*/
		fallthrough
	case AT_RAND:
		/*
			RFC 4187:
			   The value field of this attribute contains two reserved bytes
			   followed by the AKA RAND parameter, 16 bytes (128 bits).
		*/
		/*
		    0                   1                   2                   3
		    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		   |    AT_RAND    | Length = 5    |           Reserved            |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		   |                                                               |
		   |                             RAND                              |
		   |                                                               |
		   |                                                               |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		*/
		fallthrough
	case AT_AUTN:
		/*
			RFC 4187:
			   The value field of this attribute contains two reserved bytes
			   followed by the AKA AUTN parameter, 16 bytes (128 bits).
		*/
		/*
		    0                   1                   2                   3
		    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		   |    AT_AUTN    | Length = 5    |           Reserved            |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		   |                                                               |
		   |                        AUTN                                   |
		   |                                                               |
		   |                                                               |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		*/
		attr.reserved = 0
		valLen := len(value)
		if valLen != 16 {
			return fmt.Errorf("Set %s failed: expect 16 bytes, but got %d bytes", typeData, valLen)
		}
		attr.length = uint8((EapAkaAttrTypeLen + EapAkaAttrTypeLen + EapAkaAttrReservedLen + valLen) / 4)
		attr.value = make([]byte, valLen)
		copy(attr.value, value)
	case AT_KDF_INPUT:
		/*
		    0                   1                   2                   3
		    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		   | AT_KDF_INPUT  | Length        | Actual Network Name Length    |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		   |                                                               |
		   .                        Network Name                           .
		   .                                                               .
		   |                                                               |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		*/
		fallthrough
	case AT_RES:
		/*
			RFC 4187:
			   The value field of this attribute begins with the 2-byte RES Length,
			   which identifies the exact length of the RES in bits.  The RES length
			   is followed by the AKA RES parameter.  According to [TS33.105], the
			   length of the AKA RES can vary between 32 and 128 bits.  Because the
			   length of the AT_RES attribute must be a multiple of 4 bytes, the
			   sender pads the RES with zero bits where necessary.
		*/
		/*
		    0                   1                   2                   3
		    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		   |     AT_RES    |    Length     |          RES Length           |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
		   |                                                               |
		   |                             RES                               |
		   |                                                               |
		   |                                                               |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		*/
		// TODO: Add padding
		valBytesLen := len(value)
		valBitsLen := valBytesLen * 8

		if typeData == AT_RES {
			if valBitsLen > 128 || valBitsLen < 32 {
				return fmt.Errorf("%s needs between 32 and 128 bits, but got %d bits", typeData, valBitsLen)
			}
		}

		attr.reserved = uint16(valBitsLen) // The unit of reserved is bit
		attr.length = uint8((EapAkaAttrTypeLen + EapAkaAttrTypeLen + EapAkaAttrReservedLen + valBytesLen) / 4)
		attr.value = make([]byte, valBytesLen)
		copy(attr.value, value)
	case AT_KDF:
		/*
			RFC 5448:
				The length of the attribute, MUST be set to 1.
		*/
		/*
		    0                   1                   2                   3
		    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		   | AT_KDF        | Length        |    Key Derivation Function    |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		*/
		valLen := len(value)
		if valLen != 2 {
			return fmt.Errorf("%s needs exactly 2 bytes, but got %d bytes", typeData, valLen)
		}
		attr.length = 1
		attr.value = make([]byte, valLen)
		copy(attr.value, value)
	case AT_CHECKCODE:
		/*
			RFC 4187:
			   The value field of AT_CHECKCODE begins with two reserved bytes, which
			   may be followed by a 20-byte checkcode.  If the checkcode is not
			   included in AT_CHECKCODE, then the attribute indicates that no EAP/-
			   AKA-Identity messages were exchanged.  This may occur in both full
			   authentication and fast re-authentication.  The reserved bytes are
			   set to zero when sending and ignored on reception.
		*/
		/*
		    0                   1                   2                   3
		    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		   | AT_CHECKCODE  | Length        |           Reserved            |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		   |                                                               |
		   |                     Checkcode (0 or 20 bytes)                 |
		   |                                                               |
		   |                                                               |
		   |                                                               |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		*/
		attr.reserved = 0
		valLen := len(value)
		attr.length = uint8((EapAkaAttrTypeLen + EapAkaAttrTypeLen + EapAkaAttrReservedLen + valLen) / 4)
		attr.value = make([]byte, valLen)
		copy(attr.value, value)

	default:
		err = fmt.Errorf("%s is not supported", typeData)
	}

	return err
}

func (attr *EapAkaPrimeAttr) GetValue() []byte { return attr.value }