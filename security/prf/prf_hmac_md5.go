package prf

import (
	"crypto/hmac"
	"crypto/md5" // #nosec G501
	"hash"

	"github.com/free5gc/ike/message"
)

func toString_PRF_HMAC_MD5(attrType uint16, intValue uint16, bytesValue []byte) string {
	return PRF_HMAC_MD5
}

var _ PRFType = &PrfHmacMd5{}

type PrfHmacMd5 struct {
	keyLength    int
	outputLength int
}

func (t *PrfHmacMd5) TransformID() uint16 {
	return message.PRF_HMAC_MD5
}

func (t *PrfHmacMd5) getAttribute() (bool, uint16, uint16, []byte) {
	return false, 0, 0, nil
}

func (t *PrfHmacMd5) GetKeyLength() int {
	return t.keyLength
}

func (t *PrfHmacMd5) GetOutputLength() int {
	return t.outputLength
}

func (t *PrfHmacMd5) Init(key []byte) hash.Hash {
	return hmac.New(md5.New, key)
}
