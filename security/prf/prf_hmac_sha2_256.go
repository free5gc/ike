package prf

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"

	"github.com/free5gc/ike/message"
)

const String_PRF_HMAC_SHA2_256 string = "PRF_HMAC_SHA2_256"

func toString_PRF_HMAC_SHA2_256(attrType uint16, intValue uint16, bytesValue []byte) string {
	return String_PRF_HMAC_SHA2_256
}

var _ PRFType = &PRF_HMAC_SHA2_256{}

type PRF_HMAC_SHA2_256 struct {
	keyLength    int
	outputLength int
}

func (t *PRF_HMAC_SHA2_256) TransformID() uint16 {
	return message.PRF_HMAC_SHA2_256
}

func (t *PRF_HMAC_SHA2_256) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func (t *PRF_HMAC_SHA2_256) GetKeyLength() int {
	return t.keyLength
}

func (t *PRF_HMAC_SHA2_256) GetOutputLength() int {
	return t.outputLength
}

func (t *PRF_HMAC_SHA2_256) Init(key []byte) hash.Hash {
	return hmac.New(sha256.New, key)
}
