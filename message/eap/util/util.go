package util

import (
	"crypto/hmac"
	"crypto/sha256"

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

// RFC 9048 - 3.4.1. PRF'
func EapAkaPrimePRF(
	ikPrime, ckPrime []byte,
	identity string,
) (k_encr []byte, k_aut []byte, k_re []byte, msk []byte, emsk []byte) {
	// PRF'(K,S) = T1 | T2 | T3 | T4 | ...
	// where:
	// T1 = HMAC-SHA-256 (K, S | 0x01)
	// T2 = HMAC-SHA-256 (K, T1 | S | 0x02)
	// T3 = HMAC-SHA-256 (K, T2 | S | 0x03)
	// T4 = HMAC-SHA-256 (K, T3 | S | 0x04)
	// ...

	key := make([]byte, 0)
	key = append(key, ikPrime...)
	key = append(key, ckPrime...)
	sBase := []byte("EAP-AKA'" + identity)
	sBaseLen := len(sBase)

	MK := []byte("") // MK = PRF'(IK'|CK',"EAP-AKA'"|Identity)
	prev := []byte("")
	const prfRounds = 208/32 + 1
	for i := 0; i < prfRounds; i++ {
		// Create a new HMAC by defining the hash type and the key (as byte array)
		h := hmac.New(sha256.New, key)
		hexNum := (byte)(i + 1)

		sBaseWithNum := make([]byte, sBaseLen+1)
		copy(sBaseWithNum, sBase)
		sBaseWithNum[sBaseLen] = hexNum

		s := make([]byte, len(prev))
		copy(s, prev)
		s = append(s, sBaseWithNum...)

		// Write Data to it
		if _, err := h.Write(s); err != nil {
			return nil, nil, nil, nil, nil
		}

		// Get result
		sha := h.Sum(nil)
		MK = append(MK, sha...)
		prev = sha
	}

	k_encr = MK[0:16]  // K_encr = MK[0..127]
	k_aut = MK[16:48]  // K_aut  = MK[128..383]
	k_re = MK[48:80]   // K_re   = MK[384..639]
	msk = MK[80:144]   // MSK    = MK[640..1151]
	emsk = MK[144:208] // EMSK   = MK[1152..1663]

	return k_encr, k_aut, k_re, msk, emsk
}

// The EAP packet(eapPkt) includes the EAP header that begins with the Code field,
// the EAP-AKA header that begins with the Subtype field, and all the attributes.
func GenMacInput(eapPkt []byte) ([]byte, error) {
	pktLen := len(eapPkt)
	data := make([]byte, pktLen)
	copy(data, eapPkt)

	hdrLen := eap_message.EapHeaderCodeLen +
		eap_message.EapHeaderIdentifierLen +
		eap_message.EapHeaderLengthLen +
		eap_message.EapHeaderTypeLen +
		eap_message.EapAkaHeaderSubtypeLen +
		eap_message.EapAkaHeaderReservedLen

	// decode attributes
	var attrLen int
	var macExist bool
	for i := hdrLen; i < pktLen; i += attrLen {
		attrType := data[i]
		// Length of this attribute in multiples of 4 bytes.
		// The length includes the Attribute Type and Length bytes.
		attrLen = int(data[i+eap_message.EapAkaAttrTypeLen]) * 4
		if attrLen == 0 {
			return nil, errors.Errorf("attribute length equal to zero")
		}

		if attrType == eap_message.AT_MAC.Value() {
			macExist = true

			if attrLen != 20 {
				return nil, errors.Errorf("attribute AT_MAC decode err")
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
		return nil, errors.Errorf("EAP-AKA' has no AT_MAC field")
	}

	return data, nil
}

// key is k_aut;
// input is the whole EAP packet;
func CalculateAtMAC(key []byte, input []byte) ([]byte, error) {
	// keyed with k_aut
	h := hmac.New(sha256.New, key)
	if _, err := h.Write(input); err != nil {
		return nil, err
	}
	sum := h.Sum(nil)
	return sum[:16], nil
}
