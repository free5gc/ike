package util

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/pkg/errors"

	eap_message "github.com/free5gc/ike/message/eap"
	"github.com/free5gc/util/milenage"
)

func DeriveAtRes(opc, k, rand, autn []byte, snName string) ([]byte, error) {
	_, _, _, _, res, err := milenage.GenerateKeysWithAUTN(opc, k, rand, autn) // nolint:dogsled
	if err != nil {
		return nil, errors.Wrap(err, "GenerateKeysWithAUTN error")
	}

	return res, nil
}

func EapAkaPrimePrf(
	ikPrime, ckPrime []byte,
	identity string,
) (k_encr []byte, k_aut []byte, k_re []byte, msk []byte, emsk []byte) {
	key := make([]byte, 0)
	key = append(key, ikPrime...)
	key = append(key, ckPrime...)
	sBase := []byte("EAP-AKA'" + identity)

	MK := []byte("")
	prev := []byte("")
	const prfRounds = 208/32 + 1
	for i := 0; i < prfRounds; i++ {
		// Create a new HMAC by defining the hash type and the key (as byte array)
		h := hmac.New(sha256.New, key)

		hexNum := (byte)(i + 1)
		ap := append(sBase, hexNum)
		s := append(prev, ap...)

		// Write Data to it
		if _, err := h.Write(s); err != nil {
			return nil, nil, nil, nil, nil
		}

		// Get result
		sha := h.Sum(nil)
		MK = append(MK, sha...)
		prev = sha
	}

	k_encr = MK[0:16]  // 0..127
	k_aut = MK[16:48]  // 128..383
	k_re = MK[48:80]   // 384..639
	msk = MK[80:144]   // 640..1151
	emsk = MK[144:208] // 1152..1663

	return k_encr, k_aut, k_re, msk, emsk
}

// TODO: Consider this function if is need
func GenMacInput(eapPkt []byte) ([]byte, error) {
	pktLen := len(eapPkt)
	data := make([]byte, pktLen)
	copy(data, eapPkt)

	hdrLen := eap_message.EapHeaderLen + eap_message.EapAkaHeaderSubtypeLen + eap_message.EapAkaHeaderReservedLen

	// decode attributes
	var attrLen int
	var macExist bool
	for i := hdrLen; i < pktLen; i += attrLen {
		attrType := data[i]
		// Length of this attribute in multiples of 4 bytes.
		// The length includes the Attribute Type and Length bytes.
		attrLen = int(data[i+eap_message.EapAkaAttrTypeLen]) * 4
		if attrLen == 0 {
			return nil, fmt.Errorf("attribute length equal to zero")
		}

		if attrType == eap_message.AT_MAC.Value() {
			macExist = true

			if attrLen != 20 {
				return nil, fmt.Errorf("attribute AT_MAC decode err")
			}

			attrHdrLen := eap_message.EapAkaAttrTypeLen +
				eap_message.EapAkaAttrLengthLen +
				eap_message.EapAkaAttrReservedLen
			macLen := attrLen - attrHdrLen
			zeros := make([]byte, macLen)
			copy(data[i+attrHdrLen:i+attrLen], zeros)
			break
		}
	}

	if !macExist {
		return nil, fmt.Errorf("EAP-AKA' has no AT_MAC field")
	}

	return data, nil
}

/*
key is k_aut;
input is the whole EAP packet;
*/
func CalculateAtMAC(key []byte, input []byte) ([]byte, error) {
	// keyed with k_aut
	h := hmac.New(sha256.New, key)
	if _, err := h.Write(input); err != nil {
		return nil, err
	}
	sum := h.Sum(nil)
	return sum[:16], nil
}
