package integ

import (
	"crypto/hmac"
	"crypto/md5" // #nosec G501
	"hash"

	"github.com/free5gc/ike/message"
)

const string_AUTH_HMAC_MD5_96 string = "AUTH_HMAC_MD5_96"

func toString_AUTH_HMAC_MD5_96(attrType uint16, intValue uint16, bytesValue []byte) string {
	return string_AUTH_HMAC_MD5_96
}

var (
	_ INTEGType  = &AUTH_HMAC_MD5_96{}
	_ INTEGKType = &AUTH_HMAC_MD5_96{}
)

type AUTH_HMAC_MD5_96 struct {
	keyLength    int
	outputLength int
}

func (t *AUTH_HMAC_MD5_96) TransformID() uint16 {
	return message.AUTH_HMAC_MD5_96
}

func (t *AUTH_HMAC_MD5_96) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func (t *AUTH_HMAC_MD5_96) GetKeyLength() int {
	return t.keyLength
}

func (t *AUTH_HMAC_MD5_96) GetOutputLength() int {
	return t.outputLength
}

func (t *AUTH_HMAC_MD5_96) Init(key []byte) hash.Hash {
	if len(key) == 16 {
		return hmac.New(md5.New, key)
	} else {
		return nil
	}
}
