package esn

import (
	"github.com/free5gc/ike/message"
)

var (
	esnString map[uint16]func(uint16, uint16, []byte) string
	esnTypes  map[string]ESNType
)

func init() {
	// ESN String
	esnString = make(map[uint16]func(uint16, uint16, []byte) string)
	esnString[message.ESN_ENABLE] = toString_ESN_ENABLE
	esnString[message.ESN_DISABLE] = toString_ESN_DISABLE

	// ESN Types
	esnTypes = make(map[string]ESNType)

	esnTypes[string_ESN_ENABLE] = &ESN_ENABLE{}
	esnTypes[string_ESN_DISABLE] = &ESN_DISABLE{}
}

func StrToType(algo string) ESNType {
	if t, ok := esnTypes[algo]; ok {
		return t
	} else {
		return nil
	}
}

func DecodeTransform(transform *message.Transform) ESNType {
	if f, ok := esnString[transform.TransformID]; ok {
		s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
		if s != "" {
			if esnType, ok := esnTypes[s]; ok {
				return esnType
			} else {
				return nil
			}
		} else {
			return nil
		}
	} else {
		return nil
	}
}

func ToTransform(esnType ESNType) *message.Transform {
	t := new(message.Transform)
	t.TransformType = message.TypeExtendedSequenceNumbers
	t.TransformID = esnType.transformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = esnType.getAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = message.AttributeFormatUseTV
	}
	return t
}

type ESNType interface {
	transformID() uint16
	getAttribute() (bool, uint16, uint16, []byte)
	Init() bool
}
