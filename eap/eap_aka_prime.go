package eap

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"maps"
	"math"
	"slices"

	"github.com/pkg/errors"
)

// Length of EAP-AKA' header (in bytes)
const (
	EapAkaHeaderSubtypeLen  = 1
	EapAkaHeaderReservedLen = 2

	EapAkaAttrTypeLen     = 1
	EapAkaAttrLengthLen   = 1
	EapAkaAttrReservedLen = 2
)

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
	AT_PERMANENT_ID_REQ  EapAkaPrimeAttrType = 10
	AT_MAC               EapAkaPrimeAttrType = 11
	AT_NOTIFICATION      EapAkaPrimeAttrType = 12
	AT_ANY_ID_REQ        EapAkaPrimeAttrType = 13
	AT_IDENTITY          EapAkaPrimeAttrType = 14
	AT_FULLAUTH_ID_REQ   EapAkaPrimeAttrType = 17
	AT_CLIENT_ERROR_CODE EapAkaPrimeAttrType = 22
	AT_KDF_INPUT         EapAkaPrimeAttrType = 23
	AT_KDF               EapAkaPrimeAttrType = 24
	AT_CHECKCODE         EapAkaPrimeAttrType = 134
)

// Also the set of non-skippable attribute types accepted by Unmarshal().
var attrTypeStr map[EapAkaPrimeAttrType]string = map[EapAkaPrimeAttrType]string{
	AT_RAND:              "AT_RAND",
	AT_AUTN:              "AT_AUTN",
	AT_RES:               "AT_RES",
	AT_AUTS:              "AT_AUTS",
	AT_PERMANENT_ID_REQ:  "AT_PERMANENT_ID_REQ",
	AT_MAC:               "AT_MAC",
	AT_NOTIFICATION:      "AT_NOTIFICATION",
	AT_ANY_ID_REQ:        "AT_ANY_ID_REQ",
	AT_IDENTITY:          "AT_IDENTITY",
	AT_FULLAUTH_ID_REQ:   "AT_FULLAUTH_ID_REQ",
	AT_CLIENT_ERROR_CODE: "AT_CLIENT_ERROR_CODE",
	AT_KDF_INPUT:         "AT_KDF_INPUT",
	AT_KDF:               "AT_KDF",
	AT_CHECKCODE:         "AT_CHECKCODE",
}

func (t EapAkaPrimeAttrType) String() string {
	s, ok := attrTypeStr[t]
	if !ok {
		return fmt.Sprintf("EAP-AKA' attribute type[%d] is not supported", t.Value())
	}
	return s
}

func (t EapAkaPrimeAttrType) Value() uint8 { return uint8(t) }

// Definition of EAP-AKA'

var _ EapTypeData = &EapAkaPrime{}

type EapAkaPrime struct {
	subType    EapAkaSubtype
	reserved   uint16
	attributes map[EapAkaPrimeAttrType]*EapAkaPrimeAttr

	// raw holds the bytes given to Unmarshal, so Marshal can reproduce the
	// received message exactly (required for AT_MAC verification) even when
	// it has duplicate or unrecognized attributes that the map cannot keep.
	// It is dropped once any attribute is set.
	raw          []byte
	rawMACOffset int // offset of the AT_MAC value in raw, -1 if absent
}

func NewEapAkaPrime(subType EapAkaSubtype) *EapAkaPrime {
	return &EapAkaPrime{
		subType:    subType,
		attributes: make(map[EapAkaPrimeAttrType]*EapAkaPrimeAttr),
	}
}

func (eapAkaPrime *EapAkaPrime) Type() EapType { return EapTypeAkaPrime }

func (eapAkaPrime *EapAkaPrime) SubType() EapAkaSubtype { return eapAkaPrime.subType }

func (eapAkaPrime *EapAkaPrime) SetAttr(attrType EapAkaPrimeAttrType, value []byte) error {
	if eapAkaPrime.attributes == nil {
		eapAkaPrime.attributes = make(map[EapAkaPrimeAttrType]*EapAkaPrimeAttr)
	}

	attr := new(EapAkaPrimeAttr)

	err := attr.setAttr(attrType, value)
	if err != nil {
		return errors.Wrapf(err, "EAP-AKA' SetAttr failed")
	}

	// The message is modified, so it can no longer be reproduced from raw
	eapAkaPrime.raw = nil

	eapAkaPrime.attributes[attr.attrType] = attr
	return nil
}

func (eapAkaPrime *EapAkaPrime) GetAttr(attrType EapAkaPrimeAttrType) (EapAkaPrimeAttr, error) {
	if eapAkaPrime.attributes == nil {
		return EapAkaPrimeAttr{}, errors.Errorf("EAP-AKA' attributes map is nil")
	}

	for _, attr := range eapAkaPrime.attributes {
		if attr.attrType == attrType {
			return *attr, nil
		}
	}
	return EapAkaPrimeAttr{}, errors.Errorf("EAP-AKA' attribute[%s] is not found", attrType)
}

func (eapAkaPrime *EapAkaPrime) Marshal() ([]byte, error) {
	if eapAkaPrime.raw != nil {
		return bytes.Clone(eapAkaPrime.raw), nil
	}

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

	// Constructed or modified messages are written in attribute type order
	for _, key := range slices.Sorted(maps.Keys(eapAkaPrime.attributes)) {
		attr := eapAkaPrime.attributes[key]

		err = binary.Write(buffer, binary.BigEndian, attr.attrType.Value())
		if err != nil {
			return nil, errors.Wrapf(err, "EAP-AKA' Marshal(): write attribute/type failed")
		}

		err = binary.Write(buffer, binary.BigEndian, attr.length)
		if err != nil {
			return nil, errors.Wrapf(err, "EAP-AKA' Marshal(): write attribute/length failed")
		}

		if attrHeaderLen(attr.attrType) > EapAkaAttrTypeLen+EapAkaAttrLengthLen {
			err = binary.Write(buffer, binary.BigEndian, attr.reserved)
			if err != nil {
				return nil, errors.Wrapf(err, "EAP-AKA' Marshal(): write attribute/reserved failed")
			}
		}

		err = binary.Write(buffer, binary.BigEndian, attr.value)
		if err != nil {
			return nil, errors.Wrapf(err, "EAP-AKA' Marshal(): write attribute/value failed")
		}

		// AT_KDF_INPUT/AT_RES values are stored without their zero padding,
		// so pad up to the declared length.
		writtenLen := attrHeaderLen(attr.attrType) + len(attr.value)
		if paddingLen := int(attr.length)*4 - writtenLen; paddingLen > 0 {
			buffer.Write(make([]byte, paddingLen))
		}
	}

	return buffer.Bytes(), nil
}

func (eapAkaPrime *EapAkaPrime) Unmarshal(rawData []byte) error {
	var err error
	var n int

	if len(rawData) < 4 {
		return errors.New("EAP-AKA' Unmarshal(): no sufficient bytes to decode the EAP-AKA' type")
	}
	bufReader := bytes.NewReader(rawData)

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

	buf := make([]byte, EapAkaHeaderReservedLen)
	n, err = io.ReadFull(bufReader, buf)
	if err != nil {
		return errors.Wrapf(err, "EAP-AKA' Unmarshal(): read reserved failed")
	}
	if n != EapAkaHeaderReservedLen {
		return errors.New("EAP-AKA' Unmarshal(): incomplete reserved bytes")
	}
	eapAkaPrime.reserved = binary.BigEndian.Uint16(buf)

	eapAkaPrime.attributes = map[EapAkaPrimeAttrType]*EapAkaPrimeAttr{}
	eapAkaPrime.raw = nil
	eapAkaPrime.rawMACOffset = -1
	macOffset := -1

	for bufReader.Len() > 0 {
		attrStart := int(bufReader.Size()) - bufReader.Len()

		// Read EAP-AKA' attribute type and length
		typeAndLength := make([]byte, EapAkaAttrTypeLen+EapAkaAttrLengthLen)
		if _, err = io.ReadFull(bufReader, typeAndLength); err != nil {
			return errors.New("EAP-AKA' Unmarshal(): incomplete attribute header")
		}
		attr := &EapAkaPrimeAttr{
			attrType: EapAkaPrimeAttrType(typeAndLength[0]),
			length:   typeAndLength[1],
		}

		// RFC 4187 section 8.1: attribute types 0-127 are non-skippable, so an
		// unrecognized one must be rejected. Types 128-255 are skippable.
		// attrTypeStr defines the recognized types. AT_PADDING, AT_COUNTER,
		// AT_COUNTER_TOO_SMALL and AT_NONCE_S are deliberately left out: they are
		// only valid inside AT_ENCR_DATA, which is not decrypted here. AT_NONCE_MT,
		// AT_VERSION_LIST and AT_SELECTED_VERSION are EAP-SIM only.
		if _, ok := attrTypeStr[attr.attrType]; !ok && attr.attrType < 128 {
			return errors.Errorf("EAP-AKA' Unmarshal(): unrecognized non-skippable attribute type %d",
				attr.attrType.Value(),
			)
		}

		// Read the whole attribute at once. Length counts 4-byte units,
		// including the Type and Length bytes.
		totalLen := int(attr.length) * 4
		headerLen := attrHeaderLen(attr.attrType)
		if headerLen > totalLen {
			return errors.Errorf("EAP-AKA' Unmarshal(): %s header length %d exceeds attribute length %d",
				attr.attrType, headerLen, totalLen,
			)
		}
		body := make([]byte, totalLen-EapAkaAttrTypeLen-EapAkaAttrLengthLen)
		n, err = io.ReadFull(bufReader, body)
		if err != nil {
			return errors.Errorf("EAP-AKA' Unmarshal(): %s attribute value length mismatch, "+
				"expect %d bytes but got %d bytes",
				attr.attrType, len(body), n,
			)
		}
		if attr.attrType != AT_AUTS {
			attr.reserved = binary.BigEndian.Uint16(body[:EapAkaAttrReservedLen])
			body = body[EapAkaAttrReservedLen:]
		}

		// By default the value is the rest of the attribute, kept as-is
		// including any padding. This covers AT_CHECKCODE and attributes
		// without dedicated handling (e.g. AT_IDENTITY, or skippable ones such
		// as AT_RESULT_IND).
		valLen := len(body)
		switch attr.attrType {
		case AT_MAC, AT_RAND, AT_AUTN:
			if attr.length != 5 {
				return errors.Errorf("EAP-AKA' Unmarshal(): %s attribute length must be 5", attr.attrType)
			}
		case AT_AUTS:
			if attr.length != 4 {
				return errors.Errorf("EAP-AKA' Unmarshal(): %s attribute length must be 4", attr.attrType)
			}
		case AT_KDF_INPUT:
			// For AT_KDF_INPUT, the reserved field is the actual network name
			// length in bytes, not bits.
			valLen = int(attr.reserved)
		case AT_RES:
			// The reserved field is the length of the RES in bits
			if attr.reserved < 32 || attr.reserved > 128 {
				return errors.Errorf("EAP-AKA' Unmarshal(): %s needs between 32 and 128 bits, but got %d bits",
					attr.attrType, attr.reserved,
				)
			}
			// Round up: the unused trailing bits of the last byte are zero padding
			valLen = (int(attr.reserved) + 7) / 8
		case AT_KDF, AT_NOTIFICATION:
			// The reserved field carries the value
			valLen = 0
		}
		if valLen > len(body) {
			return errors.Errorf("EAP-AKA' Unmarshal(): %s value length %d exceeds attribute length %d",
				attr.attrType, valLen, totalLen,
			)
		}
		// The remaining bytes are padding
		attr.value = body[:valLen]

		if attr.attrType == AT_MAC {
			// RFC 4187 section 8.1: an attribute must not appear more than once
			// unless otherwise specified, and AT_MAC is not an exception
			if macOffset >= 0 {
				return errors.New("EAP-AKA' Unmarshal(): duplicate AT_MAC attribute")
			}
			macOffset = attrStart + headerLen
		}

		eapAkaPrime.attributes[attr.attrType] = attr
	}

	eapAkaPrime.raw = make([]byte, len(rawData))
	copy(eapAkaPrime.raw, rawData)
	eapAkaPrime.rawMACOffset = macOffset

	return nil
}

func (eapAkaPrime *EapAkaPrime) initMAC() error {
	zeros := make([]byte, 16)
	return eapAkaPrime.SetAttr(AT_MAC, zeros)
}

// withZeroMAC returns a copy of the message with the AT_MAC value zeroed (added
// if absent), as required for AT_MAC calculation. eapAkaPrime is not modified.
func (eapAkaPrime *EapAkaPrime) withZeroMAC() (*EapAkaPrime, error) {
	c := *eapAkaPrime
	c.attributes = maps.Clone(eapAkaPrime.attributes)
	if c.raw != nil && c.rawMACOffset >= 0 {
		c.raw = bytes.Clone(c.raw)
		clear(c.raw[c.rawMACOffset : c.rawMACOffset+16])
		return &c, nil
	}
	if err := c.initMAC(); err != nil {
		return nil, err
	}
	return &c, nil
}

// attrHeaderLen returns the length of the Type, Length and (if present)
// Reserved fields of an attribute.
func attrHeaderLen(attrType EapAkaPrimeAttrType) int {
	// AT_AUTS has no reserved field
	if attrType == AT_AUTS {
		return EapAkaAttrTypeLen + EapAkaAttrLengthLen
	}
	return EapAkaAttrTypeLen + EapAkaAttrLengthLen + EapAkaAttrReservedLen
}

// maxAttrValueLen is the longest value an attribute with a 4-byte header can
// carry: the 1-byte Length field caps the attribute at 255*4 bytes.
const maxAttrValueLen = math.MaxUint8*4 - EapAkaAttrTypeLen - EapAkaAttrLengthLen - EapAkaAttrReservedLen

// paddedAttrLen returns the Length field (in 4-byte units) of an attribute
// with a 4-byte header and a valLen-byte value zero-padded to a multiple of 4,
// along with valLen as uint16 for the length carried in the Reserved field.
func paddedAttrLen(valLen int) (length uint8, valLen16 uint16, err error) {
	if valLen < 0 || valLen > maxAttrValueLen {
		return 0, 0, errors.Errorf("value of %d bytes exceeds the maximum of %d bytes", valLen, maxAttrValueLen)
	}
	return uint8((EapAkaAttrTypeLen + EapAkaAttrLengthLen + EapAkaAttrReservedLen + valLen + 3) / 4), uint16(valLen), nil
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
		calcLen := (EapAkaAttrTypeLen + EapAkaAttrTypeLen + EapAkaAttrReservedLen + valLen) / 4
		if calcLen < 0 || calcLen > math.MaxUint8 {
			return fmt.Errorf("eap aka prime attr length overflow")
		}
		attr.length = uint8(calcLen)
		attr.value = make([]byte, valLen)
		copy(attr.value, value)
	case AT_AUTS:
		// RFC 4187 section 10.9: AT_AUTS
		//     0                   1                   2                   3
		//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
		//    |    AT_AUTS    | Length = 4    |                               |
		//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
		//    |                                                               |
		//    |                             AUTS                              |
		//    |                                                               |
		//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		valLen := len(value)
		if valLen != 14 {
			return errors.Errorf("Set %s failed: expect 14 bytes, but got %d bytes", attrType, valLen)
		}
		attr.length = 4
		attr.reserved = 0
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
		// The network name can be at most 255*4 - 4 = 1016 bytes
		// The unit of reserved is byte
		if attr.length, attr.reserved, err = paddedAttrLen(len(value)); err != nil {
			return errors.Wrapf(err, "%s network name too long", attrType)
		}

		// Padding is added by Marshal
		attr.value = make([]byte, len(value))
		copy(attr.value, value)
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

		valBytesLen := len(value)
		if valBytesLen < 4 || valBytesLen > 16 {
			return errors.Errorf("%s needs between 32 and 128 bits, but got %d bits", attrType, valBytesLen*8)
		}
		var valBytesLen16 uint16
		if attr.length, valBytesLen16, err = paddedAttrLen(valBytesLen); err != nil {
			return errors.Wrapf(err, "%s", attrType)
		}
		attr.reserved = valBytesLen16 * 8 // The unit of reserved is bit

		// Padding is added by Marshal
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
		attr.reserved = binary.BigEndian.Uint16(value)
		attr.value = nil
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
		calcLen := (EapAkaAttrTypeLen + EapAkaAttrTypeLen + EapAkaAttrReservedLen + valLen) / 4
		if calcLen < 0 || calcLen > math.MaxUint8 {
			return errors.Errorf("eap aka prime attr length overflow")
		}
		attr.length = uint8(calcLen)
		attr.value = make([]byte, valLen)
		copy(attr.value, value)
	case AT_NOTIFICATION:
		// RFC 4187 Section 10.19:
		// 0                   1                   2                   3
		// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |AT_NOTIFICATION| Length = 1    |S|P|  Notification Code        |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		valLen := len(value)
		if valLen != 2 {
			return errors.Errorf("%s needs exactly 2 bytes for Notification Code, but got %d bytes", attrType, valLen)
		}
		attr.length = 1
		attr.reserved = binary.BigEndian.Uint16(value)
		attr.value = nil
	default:
		err = errors.Errorf("%s is not supported", attrType)
	}

	return err
}

func (attr *EapAkaPrimeAttr) GetAttrType() EapAkaPrimeAttrType { return attr.attrType }

func (attr *EapAkaPrimeAttr) GetValue() []byte {
	var b []byte
	if attr.attrType == AT_KDF || attr.attrType == AT_NOTIFICATION {
		b = make([]byte, EapAkaAttrReservedLen)
		binary.BigEndian.PutUint16(b, attr.reserved)
		return b
	} else {
		b = make([]byte, len(attr.value))
		copy(b, attr.value)
	}
	return b
}

// RFC 9048 - 3.4.1. PRF'
func EapAkaPrimePRF(
	ikPrime, ckPrime []byte,
	identity string,
) (k_encr, k_aut, k_re, msk, emsk []byte, err error) {
	// PRF'(K,S) = T1 | T2 | T3 | T4 | ...
	// where:
	// T1 = HMAC-SHA-256 (K, S | 0x01)
	// T2 = HMAC-SHA-256 (K, T1 | S | 0x02)
	// T3 = HMAC-SHA-256 (K, T2 | S | 0x03)
	// T4 = HMAC-SHA-256 (K, T3 | S | 0x04)
	// ...

	if len(ikPrime) == 0 || len(ckPrime) == 0 {
		return nil, nil, nil, nil, nil, errors.New("EAP-AKA' PRF: invalid input key length")
	}

	key := make([]byte, 0, len(ikPrime)+len(ckPrime))
	key = append(key, ikPrime...)
	key = append(key, ckPrime...)
	sBase := []byte("EAP-AKA'" + identity)
	sBaseLen := len(sBase)

	MK := make([]byte, 0) // MK = PRF'(IK'|CK',"EAP-AKA'"|Identity)
	prev := make([]byte, 0)
	const prfRounds = 208/32 + 1

	for i := 0; i < prfRounds; i++ {
		// Create a new HMAC by defining the hash type and the key (as byte array)
		h := hmac.New(sha256.New, key)
		hexNum := (byte)(i + 1)

		sBaseWithNum := make([]byte, sBaseLen+1)
		copy(sBaseWithNum, sBase)
		sBaseWithNum[sBaseLen] = hexNum

		s := make([]byte, len(prev))
		copy(s, prev)
		s = append(s, sBaseWithNum...)

		// Write Data to it
		_, err = h.Write(s)
		if err != nil {
			return nil, nil, nil, nil, nil, errors.Wrap(err, "EAP-AKA' PRF: HMAC computation failed")
		}

		// Get result
		sha := h.Sum(nil)
		MK = append(MK, sha...)
		prev = sha
	}

	if len(MK) < 208 {
		return nil, nil, nil, nil, nil, errors.New("EAP-AKA' PRF: insufficient key material generated")
	}

	k_encr = MK[0:16]  // K_encr = MK[0..127]
	k_aut = MK[16:48]  // K_aut  = MK[128..383]
	k_re = MK[48:80]   // K_re   = MK[384..639]
	msk = MK[80:144]   // MSK    = MK[640..1151]
	emsk = MK[144:208] // EMSK   = MK[1152..1663]

	return k_encr, k_aut, k_re, msk, emsk, nil
}
