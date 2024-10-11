package prf

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505
	"hash"

	"github.com/free5gc/ike/message"
)

func toString_PRF_HMAC_SHA1(attrType uint16, intValue uint16, bytesValue []byte) string {
	return PRF_HMAC_SHA1
}

var _ PRFType = &PrfHmacSha1{}

type PrfHmacSha1 struct {
	keyLength    int
	outputLength int
}

func (t *PrfHmacSha1) TransformID() uint16 {
	return message.PRF_HMAC_SHA1
}

func (t *PrfHmacSha1) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func (t *PrfHmacSha1) GetKeyLength() int {
	return t.keyLength
}

func (t *PrfHmacSha1) GetOutputLength() int {
	return t.outputLength
}

func (t *PrfHmacSha1) Init(key []byte) hash.Hash {
	return hmac.New(sha1.New, key)
}
