package eap

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

// Definition of EAP-AKA'

// RFC 4187 - Section 11:
// EAP-AKA' SubType
type EapAkaSubtype uint8

const (
	SubtypeAkaChallenge              EapAkaSubtype = 1
	SubtypeAkaAuthenticationReject   EapAkaSubtype = 2
	SubtypeAkaSynchronizationFailure EapAkaSubtype = 4
	SubtypeAkaIdentity               EapAkaSubtype = 5
	SubtypeAkaNotification           EapAkaSubtype = 12
	SubtypeAkaReauthentication       EapAkaSubtype = 13
	SubtypeAkaClientError            EapAkaSubtype = 14
)

// Attribute Types for EAP-AKA'
type EapAkaPrimeAttrType uint8

const (
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
		s = fmt.Sprintf("Unsupported type[%d]", t.Value())
	}

	return s
}

func (t EapAkaPrimeAttrType) Value() uint8 { return uint8(t) }

var _ EapTypeData = &EapAkaPrime{}

type EapAkaPrime struct {
	subType    EapAkaSubtype
	reserved   uint16
	attributes map[EapAkaPrimeAttrType]*EapAkaPrimeAttr
}

func (eapAkaPrime *EapAkaPrime) Type() EapType { return EapTypeAkaPrime }

func (eapAkaPrime *EapAkaPrime) SubType() EapAkaSubtype { return eapAkaPrime.subType }

func (eapAkaPrime *EapAkaPrime) Init(subType EapAkaSubtype) {
	eapAkaPrime.subType = subType
	eapAkaPrime.attributes = make(map[EapAkaPrimeAttrType]*EapAkaPrimeAttr)
}

func (eapAkaPrime *EapAkaPrime) SetAttr(attrType EapAkaPrimeAttrType, value []byte) error {
	attr := new(EapAkaPrimeAttr)

	err := attr.setAttr(attrType, value)
	if err != nil {
		return errors.Wrapf(err, "EAP-AKA' SetAttr failed")
	}

	eapAkaPrime.attributes[attr.attrType] = attr
	return nil
}

func (eapAkaPrime *EapAkaPrime) GetAttr(attrType EapAkaPrimeAttrType) (EapAkaPrimeAttr, error) {
	for _, attr := range eapAkaPrime.attributes {
		if attr.attrType == attrType {
			return *attr, nil
		}
	}
	return EapAkaPrimeAttr{}, errors.Errorf("EAP-AKA' attribute[%s] is not found", attrType)
}

func (eapAkaPrime *EapAkaPrime) InitMac() error {
	zeros := make([]byte, 16)
	return eapAkaPrime.SetAttr(AT_MAC, zeros)
}

func (eapAkaPrime *EapAkaPrime) Marshal() ([]byte, error) {
	buffer := new(bytes.Buffer)

	err := binary.Write(buffer, binary.BigEndian, EapTypeAkaPrime)
	if err != nil {
		return nil, errors.Wrapf(err, "EAP-AKA' Marshal(): write type failed")
	}

	err = binary.Write(buffer, binary.BigEndian, eapAkaPrime.subType)
	if err != nil {
		return nil, errors.Wrapf(err, "EAP-AKA' Marshal(): write subtype failed")
	}
	err = binary.Write(buffer, binary.BigEndian, eapAkaPrime.reserved)
	if err != nil {
		return nil, errors.Wrapf(err, "EAP-AKA' Marshal(): write reserved failed")
	}

	for _, key := range eapAkaPrime.getAttrsKeys() {
		attr := eapAkaPrime.attributes[key]

		err = binary.Write(buffer, binary.BigEndian, attr.attrType.Value())
		if err != nil {
			return nil, errors.Wrapf(err, "EAP-AKA' Marshal(): write attribute/type failed")
		}

		err = binary.Write(buffer, binary.BigEndian, attr.length)
		if err != nil {
			return nil, errors.Wrapf(err, "EAP-AKA' Marshal(): write attribute/length failed")
		}

		if attr.attrType != AT_KDF {
			err = binary.Write(buffer, binary.BigEndian, attr.reserved)
			if err != nil {
				return nil, errors.Wrapf(err, "EAP-AKA' Marshal(): write attribute/reserved failed")
			}
		}

		err = binary.Write(buffer, binary.BigEndian, attr.value)
		if err != nil {
			return nil, errors.Wrapf(err, "EAP-AKA' Marshal(): write attribute/value failed")
		}
	}

	return buffer.Bytes(), nil
}

func (eapAkaPrime *EapAkaPrime) Unmarshal(rawData []byte) error {
	var err error

	if len(rawData) < 4 {
		return errors.New("EAP-AKA' Unmarshal(): no sufficient bytes to decode the EAP-AKA' type")
	}
	bufReader := bufio.NewReader(bytes.NewReader(rawData))

	code, err := bufReader.ReadByte()
	if err != nil {
		return errors.Wrapf(err, "EAP-AKA' Unmarshal(): read EAP type failed")
	}
	typeCode := EapType(code)
	if typeCode != EapTypeAkaPrime {
		return errors.Errorf("EAP-AKA' Unmarshal(): expect EAP type is %d but got %d", EapTypeAkaPrime, typeCode)
	}

	subType, err := bufReader.ReadByte()
	if err != nil {
		return errors.Wrapf(err, "EAP-AKA' Unmarshal(): read subtype failed")
	}
	eapAkaPrime.subType = EapAkaSubtype(subType)

	buf := make([]byte, unsafe.Sizeof(eapAkaPrime.reserved))
	_, err = io.ReadFull(bufReader, buf)
	if err != nil {
		return errors.Wrapf(err, "EAP-AKA' Unmarshal(): read reserved failed")
	}
	binary.BigEndian.PutUint16(buf, eapAkaPrime.reserved)

	if eapAkaPrime.attributes == nil {
		eapAkaPrime.attributes = map[EapAkaPrimeAttrType]*EapAkaPrimeAttr{}
	}

	for {
		attr := new(EapAkaPrimeAttr)
		var attrType uint8

		// Read EAP-AKA' attribute type
		attrType, err = bufReader.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return errors.Wrapf(err, "EAP-AKA' Unmarshal(): read attribute/type failed")
		}
		attr.attrType = EapAkaPrimeAttrType(attrType)

		// Read EAP-AKA' Attribute length
		attr.length, err = bufReader.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return errors.Wrapf(err, "EAP-AKA' Unmarshal(): read attribute/length failed")
		}

		switch attr.attrType {
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
				return errors.Wrapf(err, "EAP-AKA' Unmarshal(): read %s attribute/reserved failed", attr.attrType)
			}

			valLen := 4*attr.length - EapAkaAttrTypeLen - EapAkaAttrLengthLen - EapAkaAttrReservedLen
			attr.value = make([]byte, valLen)
			_, err = io.ReadFull(bufReader, attr.value)
			if err != nil {
				if err == io.EOF {
					break
				}
				return errors.Wrapf(err, "EAP-AKA' Unmarshal(): read %s attribute/value failed", attr.attrType)
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
				return errors.Wrapf(err, "EAP-AKA' Unmarshal(): read %s attribute/reserved failed", attr.attrType)
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
				return errors.Wrapf(err, "EAP-AKA' Unmarshal(): read %s attribute/value failed", attr.attrType)
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
				return errors.Wrapf(err, "EAP-AKA' Unmarshal(): read %s attribute/value failed", attr.attrType)
			}
		}

		eapAkaPrime.attributes[attr.attrType] = attr
	}

	return nil
}

func (eapAkaPrime *EapAkaPrime) getAttrsKeys() []EapAkaPrimeAttrType {
	result := make([]EapAkaPrimeAttrType, 0, len(eapAkaPrime.attributes))

	for key := range eapAkaPrime.attributes {
		result = append(result, key)
	}

	sort.Slice(result, func(i, j int) bool {
		return uint8(result[i]) < uint8(result[j])
	})

	return result
}

// Len(EapAkaPrimeAttr) = EapAkaPrimeAttr.length * 4
type EapAkaPrimeAttr struct {
	attrType EapAkaPrimeAttrType
	length   uint8
	reserved uint16
	value    []byte
}

func (attr *EapAkaPrimeAttr) setAttr(attrType EapAkaPrimeAttrType, value []byte) error {
	var err error

	attr.attrType = attrType

	switch attrType {
	case AT_MAC:
		// RFC 5448:
		//    When used within EAP-AKA', the AT_MAC attribute is changed as
		//    follows.  The MAC algorithm is HMAC-SHA-256-128, a keyed hash value.
		//    The HMAC-SHA-256-128 value is obtained from the 32-byte HMAC-SHA-256
		//    value by truncating the output to the first 16 bytes.  Hence, the
		//    length of the MAC is 16 bytes.

		// 0                   1                   2                   3
		// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |     AT_MAC    | Length = 5    |           Reserved            |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// |                           MAC                                 |
		// |                                                               |
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		fallthrough
	case AT_RAND:
		// RFC 4187:
		//    The value field of this attribute contains two reserved bytes
		//    followed by the AKA RAND parameter, 16 bytes (128 bits).

		// 0                   1                   2                   3
		// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |    AT_RAND    | Length = 5    |           Reserved            |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// |                             RAND                              |
		// |                                                               |
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		fallthrough
	case AT_AUTN:
		// RFC 4187:
		//    The value field of this attribute contains two reserved bytes
		//    followed by the AKA AUTN parameter, 16 bytes (128 bits).

		// 0                   1                   2                   3
		// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |    AT_AUTN    | Length = 5    |           Reserved            |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// |                        AUTN                                   |
		// |                                                               |
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		attr.reserved = 0
		valLen := len(value)
		if valLen != 16 {
			return errors.Errorf("Set %s failed: expect 16 bytes, but got %d bytes", attrType, valLen)
		}
		attr.length = uint8((EapAkaAttrTypeLen + EapAkaAttrTypeLen + EapAkaAttrReservedLen + valLen) / 4)
		attr.value = make([]byte, valLen)
		copy(attr.value, value)
	case AT_KDF_INPUT:
		// 0                   1                   2                   3
		// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// | AT_KDF_INPUT  | Length        | Actual Network Name Length    |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// .                        Network Name                           .
		// .                                                               .
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		fallthrough
	case AT_RES:
		// RFC 4187:
		//    The value field of this attribute begins with the 2-byte RES Length,
		//    which identifies the exact length of the RES in bits.  The RES length
		//    is followed by the AKA RES parameter.  According to [TS33.105], the
		//    length of the AKA RES can vary between 32 and 128 bits.  Because the
		//    length of the AT_RES attribute must be a multiple of 4 bytes, the
		//    sender pads the RES with zero bits where necessary.

		// 0                   1                   2                   3
		// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |     AT_RES    |    Length     |          RES Length           |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
		// |                                                               |
		// |                             RES                               |
		// |                                                               |
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		// TODO: Add padding
		valBytesLen := len(value)
		valBitsLen := valBytesLen * 8

		if attrType == AT_RES {
			if valBitsLen > 128 || valBitsLen < 32 {
				return errors.Errorf("%s needs between 32 and 128 bits, but got %d bits", attrType, valBitsLen)
			}
		}

		attr.reserved = uint16(valBitsLen) // The unit of reserved is bit
		attr.length = uint8((EapAkaAttrTypeLen + EapAkaAttrTypeLen + EapAkaAttrReservedLen + valBytesLen) / 4)
		attr.value = make([]byte, valBytesLen)
		copy(attr.value, value)
	case AT_KDF:
		// RFC 5448:
		// 	The length of the attribute, MUST be set to 1.

		// 0                   1                   2                   3
		// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// | AT_KDF        | Length        |    Key Derivation Function    |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		valLen := len(value)
		if valLen != 2 {
			return errors.Errorf("%s needs exactly 2 bytes, but got %d bytes", attrType, valLen)
		}
		attr.length = 1
		attr.value = make([]byte, valLen)
		copy(attr.value, value)
	case AT_CHECKCODE:
		// RFC 4187:
		//    The value field of AT_CHECKCODE begins with two reserved bytes, which
		//    may be followed by a 20-byte checkcode.  If the checkcode is not
		//    included in AT_CHECKCODE, then the attribute indicates that no EAP/-
		//    AKA-Identity messages were exchanged.  This may occur in both full
		//    authentication and fast re-authentication.  The reserved bytes are
		//    set to zero when sending and ignored on reception.

		// 0                   1                   2                   3
		// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// | AT_CHECKCODE  | Length        |           Reserved            |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                                                               |
		// |                     Checkcode (0 or 20 bytes)                 |
		// |                                                               |
		// |                                                               |
		// |                                                               |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		attr.reserved = 0
		valLen := len(value)
		attr.length = uint8((EapAkaAttrTypeLen + EapAkaAttrTypeLen + EapAkaAttrReservedLen + valLen) / 4)
		attr.value = make([]byte, valLen)
		copy(attr.value, value)
	default:
		err = errors.Errorf("%s is not supported", attrType)
	}

	return err
}

func (attr *EapAkaPrimeAttr) GetValue() []byte { return attr.value }
