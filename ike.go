package ike

import (
	"crypto/hmac"

	"github.com/pkg/errors"

	"github.com/free5gc/ike/message"
	"github.com/free5gc/ike/security"
)

func EncodeEncrypt(
	ikeMsg *message.IKEMessage,
	ikesaKey *security.IKESAKey,
	role message.Role,
) ([]byte, error) {
	if ikesaKey != nil {
		err := encryptMsg(ikeMsg, ikesaKey, role)
		if err != nil {
			return nil, errors.Wrapf(err, "IKE encode encrypt")
		}
	}

	msg, err := ikeMsg.Encode()
	return msg, errors.Wrapf(err, "IKE encode")
}

// Before use this function, need to use IKEMessage.Encode first
// and get IKESA
func DecodeDecrypt(
	msg []byte,
	ikeHeader *message.IKEHeader,
	ikesaKey *security.IKESAKey,
	role message.Role,
) (*message.IKEMessage, error) {
	ikeMsg := new(message.IKEMessage)
	var err error

	if ikeHeader == nil {
		err = ikeMsg.Decode(msg)
		if err != nil {
			return nil, errors.Wrapf(err, "DecodeDecrypt()")
		}
	} else {
		ikeMsg.IKEHeader = ikeHeader
		err = ikeMsg.DecodePayload(msg[message.IKE_HEADER_LEN:])
		if err != nil {
			return nil, errors.Wrapf(err, "DecodeDecrypt()")
		}
	}

	if ikeMsg.Payloads[0].Type() == message.TypeSK {
		if ikesaKey == nil {
			return nil, errors.Errorf("IKE decode decrypt: need ikesaKey to decrypt")
		}
		ikeMsg, err = decryptMsg(msg, ikeMsg, ikesaKey, role)
		if err != nil {
			return nil, errors.Wrapf(err, "IKE decode decrypt")
		}
	}

	return ikeMsg, nil
}

func verifyIntegrity(
	originData []byte,
	checksum []byte,
	ikesaKey *security.IKESAKey,
	role message.Role,
) error {
	expectChecksum, err := calculateIntegrity(ikesaKey, role, originData)
	if err != nil {
		return errors.Wrapf(err, "verifyIntegrity[%d]", ikesaKey.IntegInfo.TransformID())
	}

	// fmt.Printf("Calculated checksum:\n%s\nReceived checksum:\n%s",
	// 	hex.Dump(expectChecksum), hex.Dump(checksum))
	if !hmac.Equal(checksum, expectChecksum) {
		return errors.Errorf("invalid checksum")
	}
	return nil
}

func calculateIntegrity(
	ikesaKey *security.IKESAKey,
	role message.Role,
	originData []byte,
) ([]byte, error) {
	outputLen := ikesaKey.IntegInfo.GetOutputLength()

	var calculatedChecksum []byte
	if role == message.Role_Initiator {
		if ikesaKey.Integ_i == nil {
			return nil, errors.Errorf("CalcIKEChecksum() : IKE SA have nil Integ_r")
		}
		ikesaKey.Integ_i.Reset()
		if _, err := ikesaKey.Integ_i.Write(originData); err != nil {
			return nil, errors.Wrapf(err, "CalcIKEChecksum()")
		}
		calculatedChecksum = ikesaKey.Integ_i.Sum(nil)
	} else {
		if ikesaKey.Integ_r == nil {
			return nil, errors.Errorf("CalcIKEChecksum() : IKE SA have nil Integ_i")
		}
		ikesaKey.Integ_r.Reset()
		if _, err := ikesaKey.Integ_r.Write(originData); err != nil {
			return nil, errors.Wrapf(err, "CalcIKEChecksum()")
		}
		calculatedChecksum = ikesaKey.Integ_r.Sum(nil)
	}

	return calculatedChecksum[:outputLen], nil
}

func encryptPayload(
	plainText []byte,
	ikesaKey *security.IKESAKey,
	role message.Role,
) ([]byte, error) {
	var cipherText []byte
	if role == message.Role_Initiator {
		var err error
		if cipherText, err = ikesaKey.Encr_i.Encrypt(plainText); err != nil {
			return nil, errors.Wrapf(err, "encryptPayload()")
		}
	} else {
		var err error
		if cipherText, err = ikesaKey.Encr_r.Encrypt(plainText); err != nil {
			return nil, errors.Wrapf(err, "encryptPayload()")
		}
	}

	return cipherText, nil
}

func decryptPayload(
	cipherText []byte,
	ikesaKey *security.IKESAKey,
	role message.Role,
) ([]byte, error) {
	var plainText []byte
	if role == message.Role_Initiator {
		var err error
		if plainText, err = ikesaKey.Encr_r.Decrypt(cipherText); err != nil {
			return nil, errors.Wrapf(err, "decryptPayload()")
		}
	} else {
		var err error
		if plainText, err = ikesaKey.Encr_i.Decrypt(cipherText); err != nil {
			return nil, errors.Wrapf(err, "decryptPayload()")
		}
	}

	return plainText, nil
}

func decryptMsg(
	msg []byte,
	ikeMsg *message.IKEMessage,
	ikesaKey *security.IKESAKey,
	role message.Role,
) (*message.IKEMessage, error) {
	// Check parameters
	if ikesaKey == nil {
		return nil, errors.Errorf("decryptMsg(): IKE SA is nil")
	}
	if msg == nil {
		return nil, errors.Errorf("decryptMsg(): msg is nil")
	}
	if ikeMsg == nil {
		return nil, errors.Errorf("decryptMsg(): IKE encrypted payload is nil")
	}

	// Check if the context contain needed data
	if ikesaKey.IntegInfo == nil {
		return nil, errors.Errorf("decryptMsg(): No integrity algorithm specified")
	}
	if ikesaKey.EncrInfo == nil {
		return nil, errors.Errorf("decryptMsg(): No encryption algorithm specified")
	}

	if ikesaKey.Integ_i == nil {
		return nil, errors.Errorf("decryptMsg(): No initiator's integrity key")
	}
	if ikesaKey.Encr_i == nil {
		return nil, errors.Errorf("decryptMsg(): No initiator's encryption key")
	}

	var encryptedPayload *message.Encrypted
	for _, ikePayload := range ikeMsg.Payloads {
		switch ikePayload.Type() {
		case message.TypeSK:
			encryptedPayload = ikePayload.(*message.Encrypted)
		default:
			return nil, errors.Errorf(
				"Get IKE payload (type %d), this payload will not be decode",
				ikePayload.Type())
		}
	}

	checksumLength := ikesaKey.IntegInfo.GetOutputLength()
	// Checksum
	checksum := encryptedPayload.EncryptedData[len(encryptedPayload.EncryptedData)-checksumLength:]

	err := verifyIntegrity(msg[:len(msg)-checksumLength], checksum, ikesaKey, !role)
	if err != nil {
		return nil, errors.Wrapf(err, "decryptMsg(): verify integrity")
	}

	// Decrypt
	encryptedData := encryptedPayload.EncryptedData[:len(encryptedPayload.EncryptedData)-checksumLength]
	plainText, err := decryptPayload(encryptedData, ikesaKey, role)
	if err != nil {
		return nil, errors.Wrapf(err, "decryptMsg(): Error decrypting message")
	}

	var decryptedPayloads message.IKEPayloadContainer
	err = decryptedPayloads.Decode(encryptedPayload.NextPayload, plainText)
	if err != nil {
		return nil, errors.Wrapf(err, "decryptMsg(): Decoding decrypted payload failed")
	}

	ikeMsg.Payloads.Reset()
	ikeMsg.Payloads = append(ikeMsg.Payloads, decryptedPayloads...)
	return ikeMsg, nil
}

func encryptMsg(
	ikeMsg *message.IKEMessage,
	ikesaKey *security.IKESAKey,
	role message.Role,
) error {
	if ikeMsg == nil {
		return errors.Errorf("encryptMsg(): Response IKE message is nil")
	}
	if ikesaKey == nil {
		return errors.Errorf("encryptMsg(): IKE SA is nil")
	}
	ikePayloads := ikeMsg.Payloads

	// Check if the context contain needed data
	if ikesaKey.IntegInfo == nil {
		return errors.Errorf("encryptMsg(): No integrity algorithm specified")
	}
	if ikesaKey.EncrInfo == nil {
		return errors.Errorf("encryptMsg(): No encryption algorithm specified")
	}

	if ikesaKey.Integ_r == nil {
		return errors.Errorf("encryptMsg(): No responder's integrity key")
	}
	if ikesaKey.Encr_r == nil {
		return errors.Errorf("encryptMsg(): No responder's encryption key")
	}

	checksumLength := ikesaKey.IntegInfo.GetOutputLength()

	plainTextPayload, err := ikePayloads.Encode()
	if err != nil {
		return errors.Wrapf(err, "encryptMsg(): Encoding IKE payload failed.")
	}

	// Encrypting
	encryptedData, err := encryptPayload(plainTextPayload, ikesaKey, role)
	if err != nil {
		return errors.Wrapf(err, "encryptMsg(): Error encrypting message")
	}

	encryptedData = append(encryptedData, make([]byte, checksumLength)...)
	ikeMsg.Payloads.Reset()

	var encrNextPayloadType message.IKEPayloadType
	if len(ikePayloads) == 0 {
		encrNextPayloadType = message.NoNext
	} else {
		encrNextPayloadType = ikePayloads[0].Type()
	}
	sk := ikeMsg.Payloads.BuildEncrypted(encrNextPayloadType, encryptedData)

	// Calculate checksum
	ikeMsgData, err := ikeMsg.Encode()
	if err != nil {
		return errors.Wrapf(err, "encryptMsg(): Encoding IKE message error")
	}
	checksumOfMessage, err := calculateIntegrity(ikesaKey, role,
		ikeMsgData[:len(ikeMsgData)-checksumLength])
	if err != nil {
		return errors.Wrapf(err, "encryptMsg(): Error calculating checksum")
	}
	checksumField := sk.EncryptedData[len(sk.EncryptedData)-checksumLength:]
	copy(checksumField, checksumOfMessage)

	return nil
}
