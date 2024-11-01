package integ

import (
	"crypto/hmac"
	"crypto/md5" // #nosec G501
	"hash"

	ike_types "github.com/free5gc/ike/types"
)

func toString_AUTH_HMAC_MD5_96(attrType uint16, intValue uint16, bytesValue []byte) string {
	return AUTH_HMAC_MD5_96
}

var (
	_ INTEGType  = &AuthHmacMd5_95{}
	_ INTEGKType = &AuthHmacMd5_95{}
)

type AuthHmacMd5_95 struct {
	keyLength    int
	outputLength int
}

func (t *AuthHmacMd5_95) TransformID() uint16 {
	return ike_types.AUTH_HMAC_MD5_96
}

func (t *AuthHmacMd5_95) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func (t *AuthHmacMd5_95) GetKeyLength() int {
	return t.keyLength
}

func (t *AuthHmacMd5_95) GetOutputLength() int {
	return t.outputLength
}

func (t *AuthHmacMd5_95) Init(key []byte) hash.Hash {
	if len(key) == 16 {
		return hmac.New(md5.New, key)
	} else {
		return nil
	}
}
