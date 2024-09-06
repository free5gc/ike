package esn

import (
	"github.com/pkg/errors"

	"github.com/free5gc/ike/message"
)

var (
	esnString map[uint16]func(uint16, uint16, []byte) string
	esnTypes  map[string]ESN
)

const (
	string_ESN_ENABLE  string = "ESN_ENABLE"
	string_ESN_DISABLE string = "ESN_DISABLE"
)

func toString_ESN_ENABLE(attrType uint16, intValue uint16, bytesValue []byte) string {
	return string_ESN_ENABLE
}

func toString_ESN_DISABLE(attrType uint16, intValue uint16, bytesValue []byte) string {
	return string_ESN_DISABLE
}

func init() {
	// ESN String
	esnString = make(map[uint16]func(uint16, uint16, []byte) string)
	esnString[message.ESN_ENABLE] = toString_ESN_ENABLE
	esnString[message.ESN_DISABLE] = toString_ESN_DISABLE

	// ESN Types
	esnTypes = make(map[string]ESN)

	esnTypes[string_ESN_ENABLE] = ESN{
		needESN: true,
	}
	esnTypes[string_ESN_DISABLE] = ESN{
		needESN: false,
	}
}

type ESN struct {
	needESN bool
}

func (e *ESN) GetNeedESN() bool {
	return e.needESN
}

func (e *ESN) TransformID() uint16 {
	if e.needESN {
		return message.ESN_ENABLE
	} else {
		return message.ESN_DISABLE
	}
}

func (e *ESN) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func StrToType(algo string) (ESN, error) {
	if t, ok := esnTypes[algo]; ok {
		return t, nil
	} else {
		return ESN{}, errors.Errorf("ESN StrToType get unsupport string")
	}
}

func DecodeTransform(transform *message.Transform) (ESN, error) {
	if f, ok := esnString[transform.TransformID]; ok {
		s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
		if s != "" {
			esn, err := StrToType(s)
			if err != nil {
				return ESN{}, errors.Wrapf(err, "ESN DecodeTransform")
			}
			return esn, nil
		} else {
			return ESN{}, errors.Errorf("ESN DecodeTransform get unsupport string")
		}
	} else {
		return ESN{}, errors.Errorf("ESN DecodeTransform get unsupport transform")
	}
}

func ToTransform(esnType ESN) *message.Transform {
	t := new(message.Transform)
	t.TransformType = message.TypeExtendedSequenceNumbers
	t.TransformID = esnType.TransformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = esnType.getAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = message.AttributeFormatUseTV
	}
	return t
}
