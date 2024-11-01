package prf

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"

	ike_types "github.com/free5gc/ike/types"
)

func toString_PRF_HMAC_SHA2_256(attrType uint16, intValue uint16, bytesValue []byte) string {
	return PRF_HMAC_SHA2_256
}

var _ PRFType = &PrfHmacSha2_256{}

type PrfHmacSha2_256 struct {
	keyLength    int
	outputLength int
}

func (t *PrfHmacSha2_256) TransformID() uint16 {
	return ike_types.PRF_HMAC_SHA2_256
}

func (t *PrfHmacSha2_256) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func (t *PrfHmacSha2_256) GetKeyLength() int {
	return t.keyLength
}

func (t *PrfHmacSha2_256) GetOutputLength() int {
	return t.outputLength
}

func (t *PrfHmacSha2_256) Init(key []byte) hash.Hash {
	return hmac.New(sha256.New, key)
}
