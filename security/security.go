package security

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"io"
	"math/big"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/ike/message"
	"github.com/free5gc/ike/security/dh"
	"github.com/free5gc/ike/security/encr"
	"github.com/free5gc/ike/security/esn"
	"github.com/free5gc/ike/security/integ"
	"github.com/free5gc/ike/security/lib"
	"github.com/free5gc/ike/security/prf"
)

// General data
var (
	randomNumberMaximum big.Int
	randomNumberMinimum big.Int
)

func init() {
	// General data
	randomNumberMaximum.SetString(strings.Repeat("F", 512), 16)
	randomNumberMinimum.SetString(strings.Repeat("F", 32), 16)
}

func GenerateRandomNumber() (*big.Int, error) {
	var number *big.Int
	var err error
	for {
		number, err = rand.Int(rand.Reader, &randomNumberMaximum)
		if err != nil {
			return nil, errors.Errorf("GenerateRandomNumber(): Error occurs when generate random number: %+v", err)
		} else {
			if number.Cmp(&randomNumberMinimum) == 1 {
				break
			}
		}
	}
	return number, nil
}

func GenerateRandomUint8() (uint8, error) {
	number := make([]byte, 1)
	_, err := io.ReadFull(rand.Reader, number)
	if err != nil {
		return 0, errors.Errorf("Read random failed: %+v", err)
	}
	return number[0], nil
}

func concatenateNonceAndSPI(nonce []byte, SPI_initiator uint64, SPI_responder uint64) []byte {
	spi := make([]byte, 8)

	binary.BigEndian.PutUint64(spi, SPI_initiator)
	newSlice := append(nonce, spi...)
	binary.BigEndian.PutUint64(spi, SPI_responder)
	newSlice = append(newSlice, spi...)

	return newSlice
}

type IKESAKey struct {
	// SPI
	InitiatorSPI uint64
	ResponderSPI uint64

	// IKE SA transform types
	DhInfo    dh.DHType
	EncrInfo  encr.ENCRType
	IntegInfo integ.INTEGType
	PrfInfo   prf.PRFType

	// Security objects
	Prf_d   hash.Hash      // used to derive key for child sa
	Integ_i hash.Hash      // used by initiator for integrity checking
	Integ_r hash.Hash      // used by responder for integrity checking
	Encr_i  encr.IKECrypto // used by initiator for encrypting
	Encr_r  encr.IKECrypto // used by responder for encrypting
	Prf_i   hash.Hash      // used by initiator for IKE authentication
	Prf_r   hash.Hash      // used by responder for IKE authentication

	// Keys
	SK_d  []byte // used for child SA key deriving
	SK_ai []byte // used by initiator for integrity checking
	SK_ar []byte // used by responder for integrity checking
	SK_ei []byte // used by initiator for encrypting
	SK_er []byte // used by responder for encrypting
	SK_pi []byte // used by initiator for IKE authentication
	SK_pr []byte // used by responder for IKE authentication

	// Used for key generating
	ConcatenatedNonce      []byte
	DiffieHellmanSharedKey []byte

	// Temporary data
	IKEAuthResponseSA *message.SecurityAssociation
}

func (ikesaKey *IKESAKey) ToProposal() *message.Proposal {
	p := new(message.Proposal)
	p.ProtocolID = message.TypeIKE
	p.DiffieHellmanGroup = append(p.DiffieHellmanGroup, dh.ToTransform(ikesaKey.DhInfo))
	p.PseudorandomFunction = append(p.PseudorandomFunction, prf.ToTransform(ikesaKey.PrfInfo))
	p.EncryptionAlgorithm = append(p.EncryptionAlgorithm, encr.ToTransform(ikesaKey.EncrInfo))
	p.IntegrityAlgorithm = append(p.IntegrityAlgorithm, integ.ToTransform(ikesaKey.IntegInfo))
	return p
}

func (ikesaKey *IKESAKey) SetProposal(proposal *message.Proposal) error {
	if proposal == nil {
		return errors.Errorf("SetProposal : proposal is nil")
	}
	if len(proposal.DiffieHellmanGroup) == 0 {
		return errors.Errorf("SetProposal : DiffieHellmanGroup is nil")
	}

	if len(proposal.EncryptionAlgorithm) == 0 {
		return errors.Errorf("SetProposal : EncryptionAlgorithm is nil")
	}

	if len(proposal.IntegrityAlgorithm) == 0 {
		return errors.Errorf("SetProposal : IntegrityAlgorithm is nil")
	}

	if len(proposal.PseudorandomFunction) == 0 {
		return errors.Errorf("SetProposal : PseudorandomFunction is nil")
	}

	if ikesaKey.DhInfo = dh.DecodeTransform(proposal.DiffieHellmanGroup[0]); ikesaKey.DhInfo == nil {
		return errors.Errorf("SetProposal : Get unsupport DiffieHellmanGroup[%v]",
			proposal.DiffieHellmanGroup[0].TransformID)
	}
	if ikesaKey.EncrInfo = encr.DecodeTransform(proposal.EncryptionAlgorithm[0]); ikesaKey.EncrInfo == nil {
		return errors.Errorf("SetProposal : Get unsupport EncryptionAlgorithm[%v]",
			proposal.EncryptionAlgorithm[0].TransformID)
	}
	if ikesaKey.IntegInfo = integ.DecodeTransform(proposal.IntegrityAlgorithm[0]); ikesaKey.EncrInfo == nil {
		return errors.Errorf("SetProposal : Get unsupport IntegrityAlgorithm[%v]",
			proposal.IntegrityAlgorithm[0].TransformID)
	}
	if ikesaKey.PrfInfo = prf.DecodeTransform(proposal.PseudorandomFunction[0]); ikesaKey.PrfInfo == nil {
		return errors.Errorf("SetProposal : Get unsupport PseudorandomFunction[%v]",
			proposal.PseudorandomFunction[0].TransformID)
	}
	return nil
}

// CalculateDiffieHellmanMaterials generates secret and calculate Diffie-Hellman public key
// exchange material.
// Peer public value as parameter, return local public value and shared key.
func CalculateDiffieHellmanMaterials(ikesaKey *IKESAKey, peerPublicValue []byte) ([]byte, []byte, error) {
	secret, err := GenerateRandomNumber()
	if err != nil {
		return nil, nil, errors.Wrapf(err, "CalculateDiffieHellmanMaterials()")
	}

	peerPublicValueBig := new(big.Int).SetBytes(peerPublicValue)
	return ikesaKey.DhInfo.GetPublicValue(secret), ikesaKey.DhInfo.GetSharedKey(secret, peerPublicValueBig), nil
}

func (ikesaKey *IKESAKey) GenerateKeyForIKESA(log *logrus.Entry) error {
	// Check parameters
	if ikesaKey == nil {
		return errors.New("IKE SA is nil")
	}

	// Check if the context contain needed data
	if ikesaKey.EncrInfo == nil {
		return errors.New("No encryption algorithm specified")
	}
	if ikesaKey.IntegInfo == nil {
		return errors.New("No integrity algorithm specified")
	}
	if ikesaKey.PrfInfo == nil {
		return errors.New("No pseudorandom function specified")
	}
	if ikesaKey.DhInfo == nil {
		return errors.New("No Diffie-hellman group algorithm specified")
	}

	if len(ikesaKey.ConcatenatedNonce) == 0 {
		return errors.New("No concatenated nonce data")
	}
	if len(ikesaKey.DiffieHellmanSharedKey) == 0 {
		return errors.New("No Diffie-Hellman shared key")
	}

	// Get key length of SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr
	var length_SK_d, length_SK_ai, length_SK_ar, length_SK_ei, length_SK_er, length_SK_pi, length_SK_pr, totalKeyLength int

	length_SK_d = ikesaKey.PrfInfo.GetKeyLength()
	length_SK_ai = ikesaKey.IntegInfo.GetKeyLength()
	length_SK_ar = length_SK_ai
	length_SK_ei = ikesaKey.EncrInfo.GetKeyLength()
	length_SK_er = length_SK_ei
	length_SK_pi, length_SK_pr = length_SK_d, length_SK_d

	totalKeyLength = length_SK_d + length_SK_ai + length_SK_ar + length_SK_ei + length_SK_er + length_SK_pi + length_SK_pr

	// Generate IKE SA key as defined in RFC7296 Section 1.3 and Section 1.4
	log.Tracef("Concatenated nonce:\n%s", hex.Dump(ikesaKey.ConcatenatedNonce))
	log.Tracef("DH shared key:\n%s", hex.Dump(ikesaKey.DiffieHellmanSharedKey))

	prf := ikesaKey.PrfInfo.Init(ikesaKey.ConcatenatedNonce)
	if _, err := prf.Write(ikesaKey.DiffieHellmanSharedKey); err != nil {
		return err
	}

	skeyseed := prf.Sum(nil)
	seed := concatenateNonceAndSPI(ikesaKey.ConcatenatedNonce, ikesaKey.InitiatorSPI, ikesaKey.ResponderSPI)

	log.Tracef("SKEYSEED:\n%s", hex.Dump(skeyseed))

	keyStream := lib.PrfPlus(ikesaKey.PrfInfo.Init(skeyseed), seed, totalKeyLength)
	if keyStream == nil {
		return errors.New("Error happened in PrfPlus")
	}

	// Assign keys into context
	ikesaKey.SK_d = keyStream[:length_SK_d]
	keyStream = keyStream[length_SK_d:]
	ikesaKey.SK_ai = keyStream[:length_SK_ai]
	keyStream = keyStream[length_SK_ai:]
	ikesaKey.SK_ar = keyStream[:length_SK_ar]
	keyStream = keyStream[length_SK_ar:]
	ikesaKey.SK_ei = keyStream[:length_SK_ei]
	keyStream = keyStream[length_SK_ei:]
	ikesaKey.SK_er = keyStream[:length_SK_er]
	keyStream = keyStream[length_SK_er:]
	ikesaKey.SK_pi = keyStream[:length_SK_pi]
	keyStream = keyStream[length_SK_pi:]
	ikesaKey.SK_pr = keyStream[:length_SK_pr]

	// Set security objects
	ikesaKey.Prf_d = ikesaKey.PrfInfo.Init(ikesaKey.SK_d)
	ikesaKey.Integ_i = ikesaKey.IntegInfo.Init(ikesaKey.SK_ai)
	ikesaKey.Integ_r = ikesaKey.IntegInfo.Init(ikesaKey.SK_ar)

	var err error
	ikesaKey.Encr_i, err = ikesaKey.EncrInfo.Init(ikesaKey.SK_ei)
	if err != nil {
		return err
	}

	ikesaKey.Encr_r, err = ikesaKey.EncrInfo.Init(ikesaKey.SK_er)
	if err != nil {
		return err
	}

	ikesaKey.Prf_i = ikesaKey.PrfInfo.Init(ikesaKey.SK_pi)
	ikesaKey.Prf_r = ikesaKey.PrfInfo.Init(ikesaKey.SK_pr)

	return nil
}

func verifyIntegrity(log *logrus.Entry, ikesaKey *IKESAKey, role int, originData []byte, checksum []byte) (bool, error) {
	expectChecksum, err := calculateIntegrity(ikesaKey, role, originData)
	if err != nil {
		return false, errors.Wrapf(err, "verifyIntegrity[%d]", ikesaKey.IntegInfo.TransformID())
	}

	log.Tracef("Calculated checksum:\n%s\nReceived checksum:\n%s",
		hex.Dump(expectChecksum), hex.Dump(checksum))
	return hmac.Equal(checksum, expectChecksum), nil
}

func calculateIntegrity(ikesaKey *IKESAKey, role int, originData []byte) ([]byte, error) {
	outputLen := ikesaKey.IntegInfo.GetOutputLength()

	var calculatedChecksum []byte
	if role == message.Role_Initiator {
		if ikesaKey.Integ_r == nil {
			return nil, errors.Errorf("CalcIKEChecksum(%d) : IKE SA have nil Integ_r", role)
		}
		ikesaKey.Integ_r.Reset()
		if _, err := ikesaKey.Integ_r.Write(originData); err != nil {
			return nil, errors.Wrapf(err, "CalcIKEChecksum(%d)", role)
		}
		calculatedChecksum = ikesaKey.Integ_r.Sum(nil)
	} else {
		if ikesaKey.Integ_i == nil {
			return nil, errors.Errorf("CalcIKEChecksum(%d) : IKE SA have nil Integ_i", role)
		}
		ikesaKey.Integ_i.Reset()
		if _, err := ikesaKey.Integ_i.Write(originData); err != nil {
			return nil, errors.Wrapf(err, "CalcIKEChecksum(%d)", role)
		}
		calculatedChecksum = ikesaKey.Integ_i.Sum(nil)
	}

	return calculatedChecksum[:outputLen], nil
}

func EncryptMessage(ikesaKey *IKESAKey, role int, originData []byte) ([]byte, error) {
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

	// Append checksum field
	checksumField := make([]byte, ikesaKey.IntegInfo.GetOutputLength())
	cipherText = append(cipherText, checksumField...)

	return cipherText, nil
}

func DecryptMessage(log *logrus.Entry, role int, ikesaKey *IKESAKey, cipherText []byte) ([]byte, error) {
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
func DecryptProcedure(log *logrus.Entry, role int, ikesaKey *IKESAKey,
	ikeMessage *message.IKEMessage,
	encryptedPayload *message.Encrypted,
) (message.IKEPayloadContainer, error) {
	if ikesaKey == nil {
		return nil, errors.New("DecryptProcedure(): IKE SA is nil")
	}

	// Check parameters
	if ikeMessage == nil {
		return nil, errors.New("DecryptProcedure(): IKE message is nil")
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

	ikeMessageData, err := ikeMessage.Encode()
	if err != nil {
		return nil, errors.Wrapf(err, "DecryptProcedure(): Encoding IKE message failed")
	}

	ok, err := verifyIntegrity(log, ikesaKey, role,
		ikeMessageData[:len(ikeMessageData)-checksumLength], checksum)
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
	err = decryptedIKEPayload.Decode(encryptedPayload.NextPayload, plainText)
	if err != nil {
		return nil, errors.Wrapf(err, "DecryptProcedure(): Decoding decrypted payload failed")
	}

	return decryptedIKEPayload, nil
}

// Encrypt
func EncryptProcedure(role int, ikesaKey *IKESAKey,
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
	ikePayloadData, err := ikePayload.Encode()
	if err != nil {
		return errors.Wrapf(err, "EncryptProcedure(): Encoding IKE payload failed.")
	}

	encryptedData, err := EncryptMessage(ikesaKey, role, ikePayloadData)
	if err != nil {
		return errors.Wrapf(err, "EncryptProcedure(): Error encrypting message")
	}

	encryptedData = append(encryptedData, make([]byte, checksumLength)...)
	sk := responseIKEMessage.Payloads.BuildEncrypted(ikePayload[0].Type(), encryptedData)

	// Calculate checksum
	responseIKEMessageData, err := responseIKEMessage.Encode()
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

type ChildSAKey struct {
	// SPI
	SPI uint32

	// Child SA transform types
	DhInfo     dh.DHType
	EncrKInfo  encr.ENCRKType
	IntegKInfo integ.INTEGKType
	EsnInfo    esn.ESNType

	// Security
	InitiatorToResponderEncryptionKey []byte
	ResponderToInitiatorEncryptionKey []byte
	InitiatorToResponderIntegrityKey  []byte
	ResponderToInitiatorIntegrityKey  []byte
}

func (childsaKey *ChildSAKey) ToProposal() *message.Proposal {
	p := new(message.Proposal)
	p.ProtocolID = message.TypeESP
	if childsaKey.DhInfo != nil {
		p.DiffieHellmanGroup = append(p.DiffieHellmanGroup, dh.ToTransform(childsaKey.DhInfo))
	}
	p.EncryptionAlgorithm = append(p.EncryptionAlgorithm, encr.ToTransformChildSA(childsaKey.EncrKInfo))
	if childsaKey.IntegKInfo != nil {
		p.IntegrityAlgorithm = append(p.IntegrityAlgorithm, integ.ToTransformChildSA(childsaKey.IntegKInfo))
	}
	p.ExtendedSequenceNumbers = append(p.ExtendedSequenceNumbers, esn.ToTransform(childsaKey.EsnInfo))
	return p
}

func (childsaKey *ChildSAKey) SetProposal(proposal *message.Proposal) bool {
	if len(proposal.DiffieHellmanGroup) == 1 {
		if childsaKey.DhInfo = dh.DecodeTransform(proposal.DiffieHellmanGroup[0]); childsaKey.DhInfo == nil {
			return false
		}
	}
	if childsaKey.EncrKInfo = encr.DecodeTransformChildSA(proposal.EncryptionAlgorithm[0]); childsaKey.EncrKInfo == nil {
		return false
	}
	if len(proposal.IntegrityAlgorithm) == 1 {
		if childsaKey.IntegKInfo = integ.DecodeTransformChildSA(proposal.IntegrityAlgorithm[0]); childsaKey.EncrKInfo == nil {
			return false
		}
	}
	if childsaKey.EsnInfo = esn.DecodeTransform(proposal.ExtendedSequenceNumbers[0]); childsaKey.EsnInfo == nil {
		return false
	}
	return true
}

// Key Gen for child SA
func (childsaKey *ChildSAKey) GenerateKeyForChildSA(ikeSA *IKESAKey) error {
	// Check parameters
	if ikeSA == nil {
		return errors.New("IKE SA is nil")
	}
	if childsaKey == nil {
		return errors.New("Child SA is nil")
	}

	// Check if the context contain needed data
	if ikeSA.PrfInfo == nil {
		return errors.New("No pseudorandom function specified")
	}
	if childsaKey.EncrKInfo == nil {
		return errors.New("No encryption algorithm specified")
	}
	if ikeSA.Prf_d == nil {
		return errors.New("No key deriving key")
	}

	// Get key length for encryption and integrity key for IPSec
	var lengthEncryptionKeyIPSec, lengthIntegrityKeyIPSec, totalKeyLength int

	lengthEncryptionKeyIPSec = childsaKey.EncrKInfo.GetKeyLength()
	if childsaKey.IntegKInfo != nil {
		lengthIntegrityKeyIPSec = childsaKey.IntegKInfo.GetKeyLength()
	}
	totalKeyLength = (lengthEncryptionKeyIPSec + lengthIntegrityKeyIPSec) * 2

	// Generate key for child security association as specified in RFC 7296 section 2.17
	seed := ikeSA.ConcatenatedNonce

	keyStream := lib.PrfPlus(ikeSA.Prf_d, seed, totalKeyLength)
	if keyStream == nil {
		return errors.New("Error happened in PrfPlus")
	}

	childsaKey.InitiatorToResponderEncryptionKey = append(
		childsaKey.InitiatorToResponderEncryptionKey,
		keyStream[:lengthEncryptionKeyIPSec]...)
	keyStream = keyStream[lengthEncryptionKeyIPSec:]
	childsaKey.InitiatorToResponderIntegrityKey = append(
		childsaKey.InitiatorToResponderIntegrityKey,
		keyStream[:lengthIntegrityKeyIPSec]...)
	keyStream = keyStream[lengthIntegrityKeyIPSec:]
	childsaKey.ResponderToInitiatorEncryptionKey = append(
		childsaKey.ResponderToInitiatorEncryptionKey,
		keyStream[:lengthEncryptionKeyIPSec]...)
	keyStream = keyStream[lengthEncryptionKeyIPSec:]
	childsaKey.ResponderToInitiatorIntegrityKey = append(
		childsaKey.ResponderToInitiatorIntegrityKey,
		keyStream[:lengthIntegrityKeyIPSec]...)

	return nil
}
