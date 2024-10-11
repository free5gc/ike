package prf

import (
	"hash"

	"github.com/free5gc/ike/message"
)

var (
	prfString map[uint16]func(uint16, uint16, []byte) string
	prfTypes  map[string]PRFType
)

func init() {
	// PRF String
	prfString = make(map[uint16]func(uint16, uint16, []byte) string)
	prfString[message.PRF_HMAC_MD5] = toString_PRF_HMAC_MD5
	prfString[message.PRF_HMAC_SHA1] = toString_PRF_HMAC_SHA1
	prfString[message.PRF_HMAC_SHA2_256] = toString_PRF_HMAC_SHA2_256

	// PRF Types
	prfTypes = make(map[string]PRFType)

	prfTypes[String_PRF_HMAC_MD5] = &PRF_HMAC_MD5{
		keyLength:    16,
		outputLength: 16,
	}
	prfTypes[String_PRF_HMAC_SHA1] = &PRF_HMAC_SHA1{
		keyLength:    20,
		outputLength: 20,
	}
	prfTypes[String_PRF_HMAC_SHA2_256] = &PRF_HMAC_SHA2_256{
		keyLength:    32,
		outputLength: 32,
	}
}

func StrToType(algo string) PRFType {
	if t, ok := prfTypes[algo]; ok {
		return t
	} else {
		return nil
	}
}

func DecodeTransform(transform *message.Transform) PRFType {
	if f, ok := prfString[transform.TransformID]; ok {
		s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
		if s != "" {
			if prfType, ok2 := prfTypes[s]; ok2 {
				return prfType
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

func ToTransform(prfType PRFType) *message.Transform {
	t := new(message.Transform)
	t.TransformType = message.TypePseudorandomFunction
	t.TransformID = prfType.TransformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = prfType.getAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = message.AttributeFormatUseTV
	}
	return t
}

type PRFType interface {
	TransformID() uint16
	getAttribute() (bool, uint16, uint16, []byte)
	GetKeyLength() int
	GetOutputLength() int
	Init(key []byte) hash.Hash
}
