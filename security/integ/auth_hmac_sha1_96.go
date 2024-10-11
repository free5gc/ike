package integ

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505
	"hash"

	"github.com/free5gc/ike/message"
)

func toString_AUTH_HMAC_SHA1_96(attrType uint16, intValue uint16, bytesValue []byte) string {
	return AUTH_HMAC_SHA1_96
}

var (
	_ INTEGType  = &AuthHmacSha1_96{}
	_ INTEGKType = &AuthHmacSha1_96{}
)

type AuthHmacSha1_96 struct {
	keyLength    int
	outputLength int
}

func (t *AuthHmacSha1_96) TransformID() uint16 {
	return message.AUTH_HMAC_SHA1_96
}

func (t *AuthHmacSha1_96) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func (t *AuthHmacSha1_96) GetKeyLength() int {
	return t.keyLength
}

func (t *AuthHmacSha1_96) GetOutputLength() int {
	return t.outputLength
}

func (t *AuthHmacSha1_96) Init(key []byte) hash.Hash {
	if len(key) == 20 {
		return hmac.New(sha1.New, key)
	} else {
		return nil
	}
}
