package security

import (
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
	ikeCrypto "github.com/free5gc/ike/security/IKECrypto"
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
	// IKE SA transform types
	DhInfo    dh.DHType
	EncrInfo  encr.ENCRType
	IntegInfo integ.INTEGType
	PrfInfo   prf.PRFType

	// Security objects
	Prf_d   hash.Hash           // used to derive key for child sa
	Integ_i hash.Hash           // used by initiator for integrity checking
	Integ_r hash.Hash           // used by responder for integrity checking
	Encr_i  ikeCrypto.IKECrypto // used by initiator for encrypting
	Encr_r  ikeCrypto.IKECrypto // used by responder for encrypting
	Prf_i   hash.Hash           // used by initiator for IKE authentication
	Prf_r   hash.Hash           // used by responder for IKE authentication

	// Keys
	SK_d  []byte // used for child SA key deriving
	SK_ai []byte // used by initiator for integrity checking
	SK_ar []byte // used by responder for integrity checking
	SK_ei []byte // used by initiator for encrypting
	SK_er []byte // used by responder for encrypting
	SK_pi []byte // used by initiator for IKE authentication
	SK_pr []byte // used by responder for IKE authentication

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

// return IKESAKey and local public value
func NewIKESAKey(log *logrus.Entry, proposal *message.Proposal,
	keyExchangeData []byte, concatenatedNonce []byte,
	initiatorSPI uint64, responderSPI uint64,
) (*IKESAKey, []byte, error) {
	if proposal == nil {
		return nil, nil, errors.Errorf("NewIKESAKey : proposal is nil")
	}
	if len(proposal.DiffieHellmanGroup) == 0 {
		return nil, nil, errors.Errorf("NewIKESAKey : DiffieHellmanGroup is nil")
	}

	if len(proposal.EncryptionAlgorithm) == 0 {
		return nil, nil, errors.Errorf("NewIKESAKey : EncryptionAlgorithm is nil")
	}

	if len(proposal.IntegrityAlgorithm) == 0 {
		return nil, nil, errors.Errorf("NewIKESAKey : IntegrityAlgorithm is nil")
	}

	if len(proposal.PseudorandomFunction) == 0 {
		return nil, nil, errors.Errorf("NewIKESAKey : PseudorandomFunction is nil")
	}

	ikesaKey := new(IKESAKey)
	ikesaKey.DhInfo = dh.DecodeTransform(proposal.DiffieHellmanGroup[0])
	if ikesaKey.DhInfo == nil {
		return nil, nil, errors.Errorf("NewIKESAKey : Get unsupport DiffieHellmanGroup[%v]",
			proposal.DiffieHellmanGroup[0].TransformID)
	}

	ikesaKey.EncrInfo = encr.DecodeTransform(proposal.EncryptionAlgorithm[0])
	if ikesaKey.EncrInfo == nil {
		return nil, nil, errors.Errorf("NewIKESAKey : Get unsupport EncryptionAlgorithm[%v]",
			proposal.EncryptionAlgorithm[0].TransformID)
	}

	ikesaKey.IntegInfo = integ.DecodeTransform(proposal.IntegrityAlgorithm[0])
	if ikesaKey.EncrInfo == nil {
		return nil, nil, errors.Errorf("NewIKESAKey : Get unsupport IntegrityAlgorithm[%v]",
			proposal.IntegrityAlgorithm[0].TransformID)
	}

	ikesaKey.PrfInfo = prf.DecodeTransform(proposal.PseudorandomFunction[0])
	if ikesaKey.PrfInfo == nil {
		return nil, nil, errors.Errorf("NewIKESAKey : Get unsupport PseudorandomFunction[%v]",
			proposal.PseudorandomFunction[0].TransformID)
	}

	localPublicValue, sharedKeyData, err := CalculateDiffieHellmanMaterials(
		ikesaKey, keyExchangeData)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "NewIKESAKey")
	}

	err = ikesaKey.GenerateKeyForIKESA(log, concatenatedNonce, sharedKeyData,
		initiatorSPI, responderSPI)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "NewIKESAKey")
	}

	return ikesaKey, localPublicValue, nil
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

func (ikesaKey *IKESAKey) GenerateKeyForIKESA(log *logrus.Entry, concatenatedNonce []byte,
	diffieHellmanSharedKey []byte, initiatorSPI uint64, responderSPI uint64,
) error {
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

	if len(concatenatedNonce) == 0 {
		return errors.New("No concatenated nonce data")
	}
	if len(diffieHellmanSharedKey) == 0 {
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
	log.Tracef("Concatenated nonce:\n%s", hex.Dump(concatenatedNonce))
	log.Tracef("DH shared key:\n%s", hex.Dump(diffieHellmanSharedKey))

	prf := ikesaKey.PrfInfo.Init(concatenatedNonce)
	if _, err := prf.Write(diffieHellmanSharedKey); err != nil {
		return err
	}

	skeyseed := prf.Sum(nil)
	seed := concatenateNonceAndSPI(concatenatedNonce, initiatorSPI, responderSPI)

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
	ikesaKey.Encr_i, err = ikesaKey.EncrInfo.NewCrypto(ikesaKey.SK_ei)
	if err != nil {
		return err
	}

	ikesaKey.Encr_r, err = ikesaKey.EncrInfo.NewCrypto(ikesaKey.SK_er)
	if err != nil {
		return err
	}

	ikesaKey.Prf_i = ikesaKey.PrfInfo.Init(ikesaKey.SK_pi)
	ikesaKey.Prf_r = ikesaKey.PrfInfo.Init(ikesaKey.SK_pr)

	return nil
}

type ChildSAKey struct {
	// SPI
	SPI uint32

	// Child SA transform types
	DhInfo     dh.DHType
	EncrKInfo  encr.ENCRKType
	IntegKInfo integ.INTEGKType
	EsnInfo    esn.ESN

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

func NewChildSAKeyByProposal(proposal *message.Proposal) (*ChildSAKey, error) {
	if proposal == nil {
		return nil, errors.Errorf("NewChildSAKeyByProposal : proposal is nil")
	}
	if len(proposal.DiffieHellmanGroup) == 0 {
		return nil, errors.Errorf("NewChildSAKeyByProposal : DiffieHellmanGroup is nil")
	}

	if len(proposal.EncryptionAlgorithm) == 0 {
		return nil, errors.Errorf("NewChildSAKeyByProposal : EncryptionAlgorithm is nil")
	}

	if len(proposal.IntegrityAlgorithm) == 0 {
		return nil, errors.Errorf("NewChildSAKeyByProposal : IntegrityAlgorithm is nil")
	}

	if len(proposal.ExtendedSequenceNumbers) == 0 {
		return nil, errors.Errorf("NewChildSAKeyByProposal : ExtendedSequenceNumbers is nil")
	}

	childsaKey := new(ChildSAKey)
	if len(proposal.DiffieHellmanGroup) == 1 {
		childsaKey.DhInfo = dh.DecodeTransform(proposal.DiffieHellmanGroup[0])
		if childsaKey.DhInfo == nil {
			return nil, errors.Errorf("NewChildSAKeyByProposal : Get unsupport DiffieHellmanGroup[%v]",
				proposal.DiffieHellmanGroup[0].TransformID)
		}
	}

	childsaKey.EncrKInfo = encr.DecodeTransformChildSA(proposal.EncryptionAlgorithm[0])
	if childsaKey.EncrKInfo == nil {
		return nil, errors.Errorf("NewChildSAKeyByProposal : Get unsupport EncryptionAlgorithm[%v]",
			proposal.EncryptionAlgorithm[0].TransformID)
	}

	if len(proposal.IntegrityAlgorithm) == 1 {
		childsaKey.IntegKInfo = integ.DecodeTransformChildSA(proposal.IntegrityAlgorithm[0])
		if childsaKey.IntegKInfo == nil {
			return nil, errors.Errorf("NewChildSAKeyByProposal : Get unsupport IntegrityAlgorithm[%v]",
				proposal.IntegrityAlgorithm[0].TransformID)
		}
	}

	var err error
	childsaKey.EsnInfo, err = esn.DecodeTransform(proposal.ExtendedSequenceNumbers[0])
	if err != nil {
		return nil, errors.Wrapf(err, "NewChildSAKeyByProposal")
	}

	return childsaKey, nil
}

// Key Gen for child SA
func (childsaKey *ChildSAKey) GenerateKeyForChildSA(ikeSA *IKESAKey, concatenatedNonce []byte) error {
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
	seed := concatenatedNonce

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
