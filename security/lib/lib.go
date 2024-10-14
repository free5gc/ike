package lib

import (
	"crypto/rand"
	"hash"
	"math"

	"github.com/pkg/errors"
)

func PKCS7Padding(plainText []byte, blockSize int) ([]byte, error) {
	padding := blockSize - (len(plainText) % blockSize)
	if padding == 0 {
		padding = blockSize
	}
	maxNum := math.MaxUint8
	paddingText := make([]byte, padding)
	_, err := rand.Read(paddingText)
	if err != nil {
		return nil, errors.Wrapf(err, "PKCS7Padding()")
	}

	for i := 0; i < padding-1; i++ {
		paddingText[i] = byte(int(paddingText[i]) % (maxNum + 1))
	}

	paddingText[len(paddingText)-1] = byte(padding - 1)
	return append(plainText, paddingText...), nil
}

func PrfPlus(prf hash.Hash, s []byte, streamLen int) []byte {
	var stream, block []byte
	for i := 1; len(stream) < streamLen; i++ {
		prf.Reset()
		if _, err := prf.Write(append(append(block, s...), byte(i))); err != nil {
			return nil
		}
		stream = prf.Sum(stream)
		block = stream[len(stream)-prf.Size():]
	}
	return stream[:streamLen]
}
