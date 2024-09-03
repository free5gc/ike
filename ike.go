package ike

import (
	"crypto/hmac"
	"encoding/hex"

	"github.com/free5gc/ike/message"
	"github.com/free5gc/ike/security"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func Encode(log *logrus.Entry,
	ikeMessage *message.IKEMessage,
	role bool, ikesaKey *security.IKESAKey,
) ([]byte, error) {
	if ikesaKey != nil {
		err := EncryptProcedure(log, role, ikesaKey,
			ikeMessage.Payloads, ikeMessage)
		if err != nil {
			return nil, errors.Wrapf(err, "IKE Encode()")
		}

	}

	msg, err := ikeMessage.Encode(log)
	return msg, err
}

func Decode(log *logrus.Entry, msg []byte,
	role bool, ikesaKey *security.IKESAKey,
) (*message.IKEMessage, error) {
	ikeMessage := new(message.IKEMessage)
	err := ikeMessage.Decode(log, msg)
	if err != nil {
		return nil, errors.Wrapf(err, "IKE Decode()")
	}

	if ikesaKey != nil {
		var encryptedPayload *message.Encrypted

		for _, ikePayload := range ikeMessage.Payloads {
			switch ikePayload.Type() {
			case message.TypeSK:
				encryptedPayload = ikePayload.(*message.Encrypted)
			default:
				return nil, errors.Errorf(
					"Get IKE payload (type %d), this payload will not be decode",
					ikePayload.Type())
			}
		}

		decryptPayload, err := DecryptProcedure(log, role, ikesaKey,
			msg, encryptedPayload)
		if err != nil {
			return nil, errors.Wrapf(err, "Decode()")
		}

		ikeMessage.Payloads.Reset()
		ikeMessage.Payloads = append(ikeMessage.Payloads, decryptPayload...)
	}

	return ikeMessage, nil
}

func verifyIntegrity(log *logrus.Entry, ikesaKey *security.IKESAKey,
	role bool, originData []byte,
	checksum []byte,
) (bool, error) {
	expectChecksum, err := calculateIntegrity(ikesaKey, role, originData)
	if err != nil {
		return false, errors.Wrapf(err, "verifyIntegrity[%d]", ikesaKey.IntegInfo.TransformID())
	}

	log.Tracef("Calculated checksum:\n%s\nReceived checksum:\n%s",
		hex.Dump(expectChecksum), hex.Dump(checksum))
	return hmac.Equal(checksum, expectChecksum), nil
}

func calculateIntegrity(ikesaKey *security.IKESAKey, role bool, originData []byte) ([]byte, error) {
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

func EncryptMessage(ikesaKey *security.IKESAKey, role bool, originData []byte) ([]byte, error) {
	var cipherText []byte
	if role == message.Role_Initiator {
		var err error
		if cipherText, err = ikesaKey.Encr_i.Encrypt(originData); err != nil {
			return nil, errors.Errorf("Encrypt() failed to encrypt to SK: %v", err)
		}
	} else {
		var err error
		if cipherText, err = ikesaKey.Encr_r.Encrypt(originData); err != nil {
			return nil, errors.Errorf("Encrypt() failed to encrypt to SK: %v", err)
		}
	}

	return cipherText, nil
}

func DecryptMessage(log *logrus.Entry, role bool, ikesaKey *security.IKESAKey, cipherText []byte) ([]byte, error) {
	var plainText []byte
	if role == message.Role_Initiator {
		var err error
		if plainText, err = ikesaKey.Encr_r.Decrypt(log, cipherText); err != nil {
			return nil, errors.Errorf("Encrypt() Failed to decrypt to SK: %v", err)
		}
	} else {
		var err error
		if plainText, err = ikesaKey.Encr_i.Decrypt(log, cipherText); err != nil {
			return nil, errors.Errorf("Encrypt() Failed to decrypt to SK: %v", err)
		}
	}

	return plainText, nil
}

// Decrypt
func DecryptProcedure(log *logrus.Entry, role bool,
	ikesaKey *security.IKESAKey, ikeMessageRawData []byte,
	encryptedPayload *message.Encrypted,
) (message.IKEPayloadContainer, error) {
	// Check parameters
	if ikesaKey == nil {
		return nil, errors.New("DecryptProcedure(): IKE SA is nil")
	}
	if ikeMessageRawData == nil {
		return nil, errors.New("DecryptProcedure(): ikeMessageRawData is nil")
	}
	if encryptedPayload == nil {
		return nil, errors.New("DecryptProcedure(): IKE encrypted payload is nil")
	}

	// Check if the context contain needed data
	if ikesaKey.IntegInfo == nil {
		return nil, errors.New("DecryptProcedure(): No integrity algorithm specified")
	}
	if ikesaKey.EncrInfo == nil {
		return nil, errors.New("DecryptProcedure(): No encryption algorithm specified")
	}

	if ikesaKey.Integ_i == nil {
		return nil, errors.New("DecryptProcedure(): No initiator's integrity key")
	}
	if ikesaKey.Encr_i == nil {
		return nil, errors.New("DecryptProcedure(): No initiator's encryption key")
	}

	checksumLength := ikesaKey.IntegInfo.GetOutputLength()
	// Checksum
	checksum := encryptedPayload.EncryptedData[len(encryptedPayload.EncryptedData)-checksumLength:]

	ok, err := verifyIntegrity(log, ikesaKey, !role,
		ikeMessageRawData[:len(ikeMessageRawData)-checksumLength], checksum)
	if err != nil {
		return nil, errors.Wrapf(err, "DecryptProcedure(): Error occur when verifying checksum")
	}
	if !ok {
		return nil, errors.New("DecryptProcedure(): Checksum failed, drop the message.")
	}

	// Decrypt
	encryptedData := encryptedPayload.EncryptedData[:len(encryptedPayload.EncryptedData)-checksumLength]
	plainText, err := DecryptMessage(log, role, ikesaKey, encryptedData)
	if err != nil {
		return nil, errors.Wrapf(err, "DecryptProcedure(): Error decrypting message")
	}

	var decryptedIKEPayload message.IKEPayloadContainer
	err = decryptedIKEPayload.Decode(log, encryptedPayload.NextPayload, plainText)
	if err != nil {
		return nil, errors.Wrapf(err, "DecryptProcedure(): Decoding decrypted payload failed")
	}

	return decryptedIKEPayload, nil
}

// Encrypt
func EncryptProcedure(log *logrus.Entry, role bool, ikesaKey *security.IKESAKey,
	ikePayload message.IKEPayloadContainer,
	responseIKEMessage *message.IKEMessage,
) error {
	if ikesaKey == nil {
		return errors.New("EncryptProcedure(): IKE SA is nil")
	}
	// Check parameters
	if len(ikePayload) == 0 {
		return errors.New("EncryptProcedure(): No IKE payload to be encrypted")
	}
	if responseIKEMessage == nil {
		return errors.New("EncryptProcedure(): Response IKE message is nil")
	}

	// Check if the context contain needed data
	if ikesaKey.IntegInfo == nil {
		return errors.New("EncryptProcedure(): No integrity algorithm specified")
	}
	if ikesaKey.EncrInfo == nil {
		return errors.New("EncryptProcedure(): No encryption algorithm specified")
	}

	if ikesaKey.Integ_r == nil {
		return errors.New("EncryptProcedure(): No responder's integrity key")
	}
	if ikesaKey.Encr_r == nil {
		return errors.New("EncryptProcedure(): No responder's encryption key")
	}

	checksumLength := ikesaKey.IntegInfo.GetOutputLength()

	// Encrypting
	ikePayloadData, err := ikePayload.Encode(log)
	if err != nil {
		return errors.Wrapf(err, "EncryptProcedure(): Encoding IKE payload failed.")
	}

	encryptedData, err := EncryptMessage(ikesaKey, role, ikePayloadData)
	if err != nil {
		return errors.Wrapf(err, "EncryptProcedure(): Error encrypting message")
	}

	encryptedData = append(encryptedData, make([]byte, checksumLength)...)
	responseIKEMessage.Payloads.Reset()
	sk := responseIKEMessage.Payloads.BuildEncrypted(ikePayload[0].Type(), encryptedData)

	// Calculate checksum
	responseIKEMessageData, err := responseIKEMessage.Encode(log)
	if err != nil {
		return errors.Wrapf(err, "EncryptProcedure(): Encoding IKE message error")
	}
	checksumOfMessage, err := calculateIntegrity(ikesaKey, role,
		responseIKEMessageData[:len(responseIKEMessageData)-checksumLength])
	if err != nil {
		return errors.Wrapf(err, "EncryptProcedure(): Error calculating checksum")
	}
	checksumField := sk.EncryptedData[len(sk.EncryptedData)-checksumLength:]
	copy(checksumField, checksumOfMessage)

	return nil
}
