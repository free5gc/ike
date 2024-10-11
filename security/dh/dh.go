package dh

import (
	"math/big"

	"github.com/free5gc/ike/message"
)

const (
	DH_1024_BIT_MODP string = "DH_1024_BIT_MODP"
	DH_2048_BIT_MODP string = "DH_2048_BIT_MODP"
)

var (
	dhString map[uint16]func(uint16, uint16, []byte) string
	dhTypes  map[string]DHType
)

func init() {
	// DH String
	dhString = make(map[uint16]func(uint16, uint16, []byte) string)
	dhString[message.Dh1024BitModp] = toString_DH_1024_BIT_MODP
	dhString[message.DH2048BitModp] = toString_DH_2048_BIT_MODP

	// DH Types
	dhTypes = make(map[string]DHType)

	var factor, generator *big.Int

	// Group 2: Dh1024BitModp
	factor, ok := new(big.Int).SetString(Group2PrimeString, 16)
	if !ok {
		panic("IKE Diffie Hellman Group failed to init.")
	}
	generator = new(big.Int).SetUint64(Group2Generator)
	dhTypes[DH_1024_BIT_MODP] = &Dh1024BitModp{
		factor:            factor,
		generator:         generator,
		factorBytesLength: len(factor.Bytes()),
	}

	// Group 14: DH2048BitModp
	factor, ok = new(big.Int).SetString(Group14PrimeString, 16)
	if !ok {
		panic("IKE Diffie Hellman Group failed to init.")
	}
	generator = new(big.Int).SetUint64(Group14Generator)
	dhTypes[DH_2048_BIT_MODP] = &DH2048BitModp{
		factor:            factor,
		generator:         generator,
		factorBytesLength: len(factor.Bytes()),
	}
}

func StrToType(algo string) DHType {
	if t, ok := dhTypes[algo]; ok {
		return t
	} else {
		return nil
	}
}

func DecodeTransform(transform *message.Transform) DHType {
	if f, ok := dhString[transform.TransformID]; ok {
		s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
		if s != "" {
			if dhType, ok2 := dhTypes[s]; ok2 {
				return dhType
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

func ToTransform(dhType DHType) *message.Transform {
	t := new(message.Transform)
	t.TransformType = message.TypeDiffieHellmanGroup
	t.TransformID = dhType.TransformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = dhType.getAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = message.AttributeFormatUseTV
	}
	return t
}

type DHType interface {
	TransformID() uint16
	getAttribute() (bool, uint16, uint16, []byte)
	GetSharedKey(secret, peerPublicValue *big.Int) []byte
	GetPublicValue(secret *big.Int) []byte
}
