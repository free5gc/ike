package encr

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/ike/internal/logger"
	itypes "github.com/free5gc/ike/internal/types"
	"github.com/free5gc/ike/message"
	types "github.com/free5gc/ike/types"
)

var (
	encrLog    *logrus.Entry
	encrString map[uint16]func(uint16, uint16, []byte) string
)

var (
	encrTypes  map[string]ENCRType
	encrKTypes map[string]ENCRKType
)

func init() {
	// Log
	encrLog = logger.ENCRLog

	// ENCR String
	encrString = make(map[uint16]func(uint16, uint16, []byte) string)
	encrString[types.ENCR_AES_CBC] = toString_ENCR_AES_CBC

	// ENCR Types
	encrTypes = make(map[string]ENCRType)

	encrTypes[string_ENCR_AES_CBC_128] = &ENCR_AES_CBC{
		keyLength: 16,
	}
	encrTypes[string_ENCR_AES_CBC_192] = &ENCR_AES_CBC{
		keyLength: 24,
	}
	encrTypes[string_ENCR_AES_CBC_256] = &ENCR_AES_CBC{
		keyLength: 32,
	}

	// Default Priority
	priority := []string{
		string_ENCR_AES_CBC_128,
		string_ENCR_AES_CBC_192,
		string_ENCR_AES_CBC_256,
	}

	// Set Priority
	for i, s := range priority {
		if encrType, ok := encrTypes[s]; ok {
			encrType.setPriority(uint32(i))
		} else {
			encrLog.Error("No such ENCR implementation")
			panic("IKE ENCR failed to init.")
		}
	}

	// ENCR Kernel Types
	encrKTypes = make(map[string]ENCRKType)

	encrKTypes[string_ENCR_AES_CBC_128] = &ENCR_AES_CBC{
		keyLength: 16,
	}
	encrKTypes[string_ENCR_AES_CBC_192] = &ENCR_AES_CBC{
		keyLength: 24,
	}
	encrKTypes[string_ENCR_AES_CBC_256] = &ENCR_AES_CBC{
		keyLength: 32,
	}

	// ENCR Kernel Priority same as above
	// Set Priority
	for i, s := range priority {
		if encrKType, ok := encrKTypes[s]; ok {
			encrKType.setPriority(uint32(i))
		} else {
			encrLog.Error("No such ENCR implementation")
			panic("IKE ENCR failed to init.")
		}
	}
}

func SetPriority(algolist []string) error {
	// check implemented
	for _, algo := range algolist {
		if _, ok := encrTypes[algo]; !ok {
			return fmt.Errorf("No such implementation: %s", algo)
		}
	}
	// set priority
	for i, algo := range algolist {
		encrTypes[algo].setPriority(uint32(i))
	}
	return nil
}

func SetKPriority(algolist map[string]uint32) error {
	// check implemented
	for algo := range algolist {
		if _, ok := encrKTypes[algo]; !ok {
			return fmt.Errorf("No such implementation: %s", algo)
		}
	}
	// set priority
	for algo, priority := range algolist {
		encrKTypes[algo].setPriority(priority)
	}
	return nil
}

func StrToType(algo string) ENCRType {
	if t, ok := encrTypes[algo]; ok {
		return t
	} else {
		return nil
	}
}

func StrToKType(algo string) ENCRKType {
	if t, ok := encrKTypes[algo]; ok {
		return t
	} else {
		return nil
	}
}

func DecodeTransform(transform *message.Transform) ENCRType {
	if f, ok := encrString[transform.TransformID]; ok {
		s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
		if s != "" {
			if encrType, ok := encrTypes[s]; ok {
				return encrType
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

func ToTransform(encrType ENCRType) *message.Transform {
	t := new(message.Transform)
	t.TransformType = types.TypeEncryptionAlgorithm
	t.TransformID = encrType.transformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = encrType.getAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = types.AttributeFormatUseTV
	}
	return t
}

func DecodeTransformChildSA(transform *message.Transform) ENCRKType {
	if f, ok := encrString[transform.TransformID]; ok {
		s := f(transform.AttributeType, transform.AttributeValue, transform.VariableLengthAttributeValue)
		if s != "" {
			if encrKType, ok := encrKTypes[s]; ok {
				return encrKType
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

func ToTransformChildSA(encrKType ENCRKType) *message.Transform {
	t := new(message.Transform)
	t.TransformType = types.TypeEncryptionAlgorithm
	t.TransformID = encrKType.transformID()
	t.AttributePresent, t.AttributeType, t.AttributeValue, t.VariableLengthAttributeValue = encrKType.getAttribute()
	if t.AttributePresent && t.VariableLengthAttributeValue == nil {
		t.AttributeFormat = 1 // TV
	}
	return t
}

type ENCRType interface {
	transformID() uint16
	getAttribute() (bool, uint16, uint16, []byte)
	setPriority(uint32)
	Priority() uint32
	GetKeyLength() int
	Init(key []byte) itypes.IKECrypto
}

type ENCRKType interface {
	transformID() uint16
	getAttribute() (bool, uint16, uint16, []byte)
	setPriority(uint32)
	Priority() uint32
	GetKeyLength() int
	XFRMString() string
}

/* Archive for future use
type XFRMEncryptionAlgorithmType uint16

func (xfrmEncryptionAlgorithmType XFRMEncryptionAlgorithmType) String() string {
	switch xfrmEncryptionAlgorithmType {
	case message.ENCR_DES:
		return "cbc(des)"
	case message.ENCR_3DES:
		return "cbc(des3_ede)"
	case message.ENCR_CAST:
		return "cbc(cast5)"
	case message.ENCR_BLOWFISH:
		return "cbc(blowfish)"
	case message.ENCR_NULL:
		return "ecb(cipher_null)"
	case message.ENCR_AES_CBC:
		return "cbc(aes)"
	case message.ENCR_AES_CTR:
		return "rfc3686(ctr(aes))"
	default:
		return ""
	}
}
*/
