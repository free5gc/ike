package integ

import (
	"hash"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/ike/logger"
	"github.com/free5gc/ike/message"
)

var (
	integLog    *logrus.Entry
	integString map[uint16]func(uint16, uint16, []byte) string
)

var (
	integTypes  map[string]INTEGType
	integKTypes map[string]INTEGKType
)

func init() {
	// Log
	integLog = logger.INTEGLog

	// INTEG String
	integString = make(map[uint16]func(uint16, uint16, []byte) string)
	integString[message.AUTH_HMAC_MD5_96] = toString_AUTH_HMAC_MD5_96
	integString[message.AUTH_HMAC_SHA1_96] = toString_AUTH_HMAC_SHA1_96
	integString[message.AUTH_HMAC_SHA2_256_128] = toString_AUTH_HMAC_SHA2_256_128

	// INTEG Types
	integTypes = make(map[string]INTEGType)

	integTypes[string_AUTH_HMAC_MD5_96] = &AUTH_HMAC_MD5_96{
		keyLength:    16,
		outputLength: 12,
	}
	integTypes[string_AUTH_HMAC_SHA1_96] = &AUTH_HMAC_SHA1_96{
		keyLength:    20,
		outputLength: 12,
	}
	integTypes[string_AUTH_HMAC_SHA2_256_128] = &AUTH_HMAC_SHA2_256_128{
		keyLength:    32,
		outputLength: 16,
	}

	// Default Priority
	priority := []string{
		string_AUTH_HMAC_MD5_96,
		string_AUTH_HMAC_SHA1_96,
		string_AUTH_HMAC_SHA2_256_128,
	}

	// Set Priority
	for i, s := range priority {
		if integType, ok := integTypes[s]; ok {
			integType.setPriority(uint32(i))
		} else {
			integLog.Error("No such INTEG implementation")
			panic("IKE INTEG failed to init.")
		}
	}

	// INTEG Kernel Types
	integKTypes = make(map[string]INTEGKType)

	integKTypes[string_AUTH_HMAC_MD5_96] = &AUTH_HMAC_MD5_96{
		keyLength:    16,
		outputLength: 12,
	}
	integKTypes[string_AUTH_HMAC_SHA1_96] = &AUTH_HMAC_SHA1_96{
		keyLength:    20,
		outputLength: 12,
	}
	integKTypes[string_AUTH_HMAC_SHA2_256_128] = &AUTH_HMAC_SHA2_256_128{
		keyLength:    32,
		outputLength: 16,
	}

	// INTEG Kernel Priority same as above
	// Set Priority
	for i, s := range priority {
		if integKType, ok := integKTypes[s]; ok {
			integKType.setPriority(uint32(i))
		} else {
			integLog.Error("No such INTEG implementation")
			panic("IKE INTEG failed to init.")
		}
	}
}

func SetPriority(algolist map[string]uint32) error {
	// check implemented
	for algo := range algolist {
		if _, ok := integTypes[algo]; !ok {
			return errors.New("No such implementation")
		}
	}
	// set priority
	for algo, priority := range algolist {
		integTypes[algo].setPriority(priority)
	}
	return nil
}

func SetKPriority(algolist []string) error {
	// check implemented
	for _, algo := range algolist {
		if _, ok := integKTypes[algo]; !ok {
			return errors.New("No such implementation")
		}
	}
	// set priority
	for i, algo := range algolist {
		integKTypes[algo].setPriority(uint32(i))
	}
	return nil
}

func StrToType(algo string) INTEGType {
	if t, ok := integTypes[algo]; ok {
		return t
	} else {
		return nil
	}
}

func StrToKType(algo string) INTEGKType {
	if t, ok := integKTypes[algo]; ok {
		return t
	} else {
		return nil
	}
}

func DecodeTransform(transform *message.Transform) INTEGType {
	if f, ok := integString[transform.TransformID]; ok {
		s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
		if s != "" {
			if integType, ok := integTypes[s]; ok {
				return integType
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

func ToTransform(integType INTEGType) *message.Transform {
	t := new(message.Transform)
	t.TransformType = message.TypeIntegrityAlgorithm
	t.TransformID = integType.TransformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = integType.getAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = 1 // TV
	}
	return t
}

func DecodeTransformChildSA(transform *message.Transform) INTEGKType {
	if f, ok := integString[transform.TransformID]; ok {
		s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
		if s != "" {
			if integKType, ok := integKTypes[s]; ok {
				return integKType
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

func ToTransformChildSA(integKType INTEGKType) *message.Transform {
	t := new(message.Transform)
	t.TransformType = message.TypeIntegrityAlgorithm
	t.TransformID = integKType.TransformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = integKType.getAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = message.AttributeFormatUseTV
	}
	return t
}

type INTEGType interface {
	TransformID() uint16
	getAttribute() (bool, uint16, uint16, []byte)
	setPriority(uint32)
	Priority() uint32
	GetKeyLength() int
	GetOutputLength() int
	Init(key []byte) hash.Hash
}

type INTEGKType interface {
	TransformID() uint16
	getAttribute() (bool, uint16, uint16, []byte)
	setPriority(uint32)
	Priority() uint32
	GetKeyLength() int
}