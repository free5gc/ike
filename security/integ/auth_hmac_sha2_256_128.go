package integ

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"

	ike_types "github.com/free5gc/ike/types"
)

func toString_AUTH_HMAC_SHA2_256_128(attrType uint16, intValue uint16, bytesValue []byte) string {
	return AUTH_HMAC_SHA2_256_128
}

var (
	_ INTEGType  = &AuthHmacSha2_256_128{}
	_ INTEGKType = &AuthHmacSha2_256_128{}
)

type AuthHmacSha2_256_128 struct {
	keyLength    int
	outputLength int
}

func (t *AuthHmacSha2_256_128) TransformID() uint16 {
	return ike_types.AUTH_HMAC_SHA2_256_128
}

func (t *AuthHmacSha2_256_128) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func (t *AuthHmacSha2_256_128) GetKeyLength() int {
	return t.keyLength
}

func (t *AuthHmacSha2_256_128) GetOutputLength() int {
	return t.outputLength
}

func (t *AuthHmacSha2_256_128) Init(key []byte) hash.Hash {
	if len(key) == 32 {
		return hmac.New(sha256.New, key)
	} else {
		return nil
	}
}
