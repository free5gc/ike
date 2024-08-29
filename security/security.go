package security

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"io"
	"math/big"
	"net"
	"strings"

	"github.com/pkg/errors"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/free5gc/ike/internal/dh"
	"github.com/free5gc/ike/internal/encr"
	"github.com/free5gc/ike/internal/esn"
	"github.com/free5gc/ike/internal/integ"
	"github.com/free5gc/ike/internal/lib"
	"github.com/free5gc/ike/internal/logger"
	"github.com/free5gc/ike/internal/prf"
	itypes "github.com/free5gc/ike/internal/types"
	"github.com/free5gc/ike/message"
	types "github.com/free5gc/ike/types"
)

// Log
var secLog *logrus.Entry

// General data
var (
	randomNumberMaximum big.Int
	randomNumberMinimum big.Int
)

func init() {
	// Log
	secLog = logger.SecLog
	// General data
	randomNumberMaximum.SetString(strings.Repeat("F", 512), 16)
	randomNumberMinimum.SetString(strings.Repeat("F", 32), 16)
}

func GenerateRandomNumber() *big.Int {
	var number *big.Int
	var err error
	for {
		number, err = rand.Int(rand.Reader, &randomNumberMaximum)
		if err != nil {
			secLog.Errorf("Error occurs when generate random number: %+v", err)
			return nil
		} else {
			if number.Cmp(&randomNumberMinimum) == 1 {
				break
			}
		}
	}
	return number
}

func GenerateRandomUint8() (uint8, error) {
	number := make([]byte, 1)
	_, err := io.ReadFull(rand.Reader, number)
	if err != nil {
		secLog.Errorf("Read random failed: %+v", err)
		return 0, errors.New("Read failed")
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

type IKESA struct {
	// SPI
	InitiatorSPI uint64
	ResponderSPI uint64

	// IKE SA transform types
	dhInfo    dh.DHType
	encrInfo  encr.ENCRType
	integInfo integ.INTEGType
	prfInfo   prf.PRFType

	// Security objects
	Prf_d   hash.Hash        // used to derive key for child sa
	Integ_i hash.Hash        // used by initiator for integrity checking
	Integ_r hash.Hash        // used by responder for integrity checking
	Encr_i  itypes.IKECrypto // used by initiator for encrypting
	Encr_r  itypes.IKECrypto // used by responder for encrypting
	Prf_i   hash.Hash        // used by initiator for IKE authentication
	Prf_r   hash.Hash        // used by responder for IKE authentication

	// Used for key generating
	ConcatenatedNonce      []byte
	DiffieHellmanSharedKey []byte
}

func SelectProposal(proposals message.ProposalContainer) message.ProposalContainer {
	var chooseProposal message.ProposalContainer

	for _, proposal := range proposals {
		var encryptionAlgorithmTransform, pseudorandomFunctionTransform *message.Transform
		var integrityAlgorithmTransform, diffieHellmanGroupTransform *message.Transform
		var chooseDH dh.DHType
		var chooseEncr encr.ENCRType
		var chooseInte integ.INTEGType
		var choosePrf prf.PRFType

		for _, transform := range proposal.DiffieHellmanGroup {
			dhType := dh.DecodeTransform(transform)
			if dhType != nil {
				if (diffieHellmanGroupTransform == nil) ||
					(dhType.Priority() > chooseDH.Priority()) {
					diffieHellmanGroupTransform = transform
					chooseDH = dhType
				}
			}
		}
		if chooseDH == nil {
			continue // mandatory
		}

		for _, transform := range proposal.EncryptionAlgorithm {
			encrType := encr.DecodeTransform(transform)
			if encrType != nil {
				if (encryptionAlgorithmTransform == nil) ||
					(encrType.Priority() > chooseEncr.Priority()) {
					encryptionAlgorithmTransform = transform
					chooseEncr = encrType
				}
			}
		}
		if chooseEncr == nil {
			continue // mandatory
		}

		for _, transform := range proposal.IntegrityAlgorithm {
			integType := integ.DecodeTransform(transform)
			if integType != nil {
				if (integrityAlgorithmTransform == nil) ||
					(integType.Priority() > chooseInte.Priority()) {
					integrityAlgorithmTransform = transform
					chooseInte = integType
				}
			}
		}
		if chooseInte == nil {
			continue // mandatory
		}

		for _, transform := range proposal.PseudorandomFunction {
			prfType := prf.DecodeTransform(transform)
			if prfType != nil {
				if (pseudorandomFunctionTransform == nil) ||
					(prfType.Priority() > choosePrf.Priority()) {
					pseudorandomFunctionTransform = transform
					choosePrf = prfType
				}
			}
		}
		if choosePrf == nil {
			continue // mandatory
		}
		if len(proposal.ExtendedSequenceNumbers) > 0 {
			continue // No ESN
		}

		// Construct chosen proposal, with ENCR, PRF, INTEG, DH, and each
		// contains one transform expectively
		chosenProposal := chooseProposal.BuildProposal(proposal.ProposalNumber, proposal.ProtocolID, nil)
		chosenProposal.EncryptionAlgorithm = append(chosenProposal.EncryptionAlgorithm, encryptionAlgorithmTransform)
		chosenProposal.IntegrityAlgorithm = append(chosenProposal.IntegrityAlgorithm, integrityAlgorithmTransform)
		chosenProposal.PseudorandomFunction = append(chosenProposal.PseudorandomFunction, pseudorandomFunctionTransform)
		chosenProposal.DiffieHellmanGroup = append(chosenProposal.DiffieHellmanGroup, diffieHellmanGroupTransform)
		break
	}
	return chooseProposal
}

func (ikesa *IKESA) ToProposal() *message.Proposal {
	p := new(message.Proposal)
	p.ProtocolID = types.TypeIKE
	p.DiffieHellmanGroup = append(p.DiffieHellmanGroup, dh.ToTransform(ikesa.dhInfo))
	p.PseudorandomFunction = append(p.PseudorandomFunction, prf.ToTransform(ikesa.prfInfo))
	p.EncryptionAlgorithm = append(p.EncryptionAlgorithm, encr.ToTransform(ikesa.encrInfo))
	p.IntegrityAlgorithm = append(p.IntegrityAlgorithm, integ.ToTransform(ikesa.integInfo))
	return p
}

func (ikesa *IKESA) SetProposal(proposal *message.Proposal) error {
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

	if ikesa.dhInfo = dh.DecodeTransform(proposal.DiffieHellmanGroup[0]); ikesa.dhInfo == nil {
		return errors.Errorf("SetProposal : Get unsupport DiffieHellmanGroup[%v]",
			proposal.DiffieHellmanGroup[0].TransformID)
	}
	if ikesa.encrInfo = encr.DecodeTransform(proposal.EncryptionAlgorithm[0]); ikesa.encrInfo == nil {
		return errors.Errorf("SetProposal : Get unsupport EncryptionAlgorithm[%v]",
			proposal.EncryptionAlgorithm[0].TransformID)
	}
	if ikesa.integInfo = integ.DecodeTransform(proposal.IntegrityAlgorithm[0]); ikesa.encrInfo == nil {
		return errors.Errorf("SetProposal : Get unsupport IntegrityAlgorithm[%v]",
			proposal.IntegrityAlgorithm[0].TransformID)
	}
	if ikesa.prfInfo = prf.DecodeTransform(proposal.PseudorandomFunction[0]); ikesa.prfInfo == nil {
		return errors.Errorf("SetProposal : Get unsupport PseudorandomFunction[%v]",
			proposal.PseudorandomFunction[0].TransformID)
	}
	return nil
}

// CalculateDiffieHellmanMaterials generates secret and calculate Diffie-Hellman public key
// exchange material.
// Peer public value as parameter, return local public value and shared key.
func (ikesa *IKESA) CalculateDiffieHellmanMaterials(peerPublicValue []byte) ([]byte, []byte) {
	secret := GenerateRandomNumber()
	peerPublicValueBig := new(big.Int).SetBytes(peerPublicValue)
	return ikesa.dhInfo.GetPublicValue(secret), ikesa.dhInfo.GetSharedKey(secret, peerPublicValueBig)
}

func (ikesa *IKESA) GenerateKeyForIKESA() error {
	// Check parameters
	if ikesa == nil {
		return errors.New("IKE SA is nil")
	}

	// Check if the context contain needed data
	if ikesa.encrInfo == nil {
		return errors.New("No encryption algorithm specified")
	}
	if ikesa.integInfo == nil {
		return errors.New("No integrity algorithm specified")
	}
	if ikesa.prfInfo == nil {
		return errors.New("No pseudorandom function specified")
	}
	if ikesa.dhInfo == nil {
		return errors.New("No Diffie-hellman group algorithm specified")
	}

	if len(ikesa.ConcatenatedNonce) == 0 {
		return errors.New("No concatenated nonce data")
	}
	if len(ikesa.DiffieHellmanSharedKey) == 0 {
		return errors.New("No Diffie-Hellman shared key")
	}

	// Get key length of SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr
	var length_SK_d, length_SK_ai, length_SK_ar, length_SK_ei, length_SK_er, length_SK_pi, length_SK_pr, totalKeyLength int

	length_SK_d = ikesa.prfInfo.GetKeyLength()
	length_SK_ai = ikesa.integInfo.GetKeyLength()
	length_SK_ar = length_SK_ai
	length_SK_ei = ikesa.encrInfo.GetKeyLength()
	length_SK_er = length_SK_ei
	length_SK_pi, length_SK_pr = length_SK_d, length_SK_d

	totalKeyLength = length_SK_d + length_SK_ai + length_SK_ar + length_SK_ei + length_SK_er + length_SK_pi + length_SK_pr

	// Generate IKE SA key as defined in RFC7296 Section 1.3 and Section 1.4
	secLog.Tracef("Concatenated nonce:\n%s", hex.Dump(ikesa.ConcatenatedNonce))
	secLog.Tracef("DH shared key:\n%s", hex.Dump(ikesa.DiffieHellmanSharedKey))

	prf := ikesa.prfInfo.Init(ikesa.ConcatenatedNonce)
	if _, err := prf.Write(ikesa.DiffieHellmanSharedKey); err != nil {
		return err
	}

	skeyseed := prf.Sum(nil)
	seed := concatenateNonceAndSPI(ikesa.ConcatenatedNonce, ikesa.InitiatorSPI, ikesa.ResponderSPI)

	secLog.Tracef("SKEYSEED:\n%s", hex.Dump(skeyseed))

	keyStream := lib.PrfPlus(ikesa.prfInfo.Init(skeyseed), seed, totalKeyLength)
	if keyStream == nil {
		return errors.New("Error happened in PrfPlus")
	}

	// Assign keys into context
	sk_d := keyStream[:length_SK_d]
	keyStream = keyStream[length_SK_d:]
	sk_ai := keyStream[:length_SK_ai]
	keyStream = keyStream[length_SK_ai:]
	sk_ar := keyStream[:length_SK_ar]
	keyStream = keyStream[length_SK_ar:]
	sk_ei := keyStream[:length_SK_ei]
	keyStream = keyStream[length_SK_ei:]
	sk_er := keyStream[:length_SK_er]
	keyStream = keyStream[length_SK_er:]
	sk_pi := keyStream[:length_SK_pi]
	keyStream = keyStream[length_SK_pi:]
	sk_pr := keyStream[:length_SK_pr]

	secLog.Debugln("====== IKE Security Association Info =====")
	secLog.Debugf("Initiator's SPI: %016x", ikesa.InitiatorSPI)
	secLog.Debugf("Responder's  SPI: %016x", ikesa.ResponderSPI)
	secLog.Debugf("Encryption Algorithm: %d", ikesa.encrInfo.TransformID())
	secLog.Debugf("SK_ei:\n%s", hex.Dump(sk_ei))
	secLog.Debugf("SK_er:\n%s", hex.Dump(sk_er))
	secLog.Debugf("Integrity Algorithm: %d", ikesa.integInfo.TransformID())
	secLog.Debugf("SK_ai:\n%s", hex.Dump(sk_ai))
	secLog.Debugf("SK_ar:\n%s", hex.Dump(sk_ar))
	secLog.Debugf("SK_pi:\n%s", hex.Dump(sk_pi))
	secLog.Debugf("SK_pr:\n%s", hex.Dump(sk_pr))
	secLog.Debugf("SK_d:\n%s", hex.Dump(sk_d))

	// Set security objects
	ikesa.Prf_d = ikesa.prfInfo.Init(sk_d)
	ikesa.Integ_i = ikesa.integInfo.Init(sk_ai)
	ikesa.Integ_r = ikesa.integInfo.Init(sk_ar)

	var err error
	ikesa.Encr_i, err = ikesa.encrInfo.Init(sk_ei)
	if err != nil {
		return err
	}

	ikesa.Encr_r, err = ikesa.encrInfo.Init(sk_er)
	if err != nil {
		return err
	}

	ikesa.Prf_i = ikesa.prfInfo.Init(sk_pi)
	ikesa.Prf_r = ikesa.prfInfo.Init(sk_pr)

	return nil
}

func (ikesa *IKESA) verifyIntegrity(role int, originData []byte, checksum []byte) (bool, error) {
	expectChecksum, err := ikesa.calculateIntegrity(role, originData)
	if err != nil {
		secLog.Errorf("VerifyIKEChecksum(%d): %+v", role, err)
		return false, errors.Wrapf(err, "verifyIntegrity[%d]", ikesa.integInfo.TransformID())
	}

	secLog.Tracef("Calculated checksum:\n%s\nReceived checksum:\n%s",
		hex.Dump(expectChecksum), hex.Dump(checksum))
	return hmac.Equal(checksum, expectChecksum), nil
}

func (ikesa *IKESA) calculateIntegrity(role int, originData []byte) ([]byte, error) {
	outputLen := ikesa.integInfo.GetOutputLength()

	var calculatedChecksum []byte
	if role == types.Role_Initiator {
		if ikesa.Integ_r == nil {
			return nil, errors.Errorf("CalcIKEChecksum(%d) : IKE SA have nil Integ_r", role)
		}
		ikesa.Integ_r.Reset()
		if _, err := ikesa.Integ_r.Write(originData); err != nil {
			return nil, errors.Wrapf(err, "CalcIKEChecksum(%d)", role)
		}
		calculatedChecksum = ikesa.Integ_r.Sum(nil)
	} else {
		if ikesa.Integ_i == nil {
			return nil, errors.Errorf("CalcIKEChecksum(%d) : IKE SA have nil Integ_i", role)
		}
		ikesa.Integ_i.Reset()
		if _, err := ikesa.Integ_i.Write(originData); err != nil {
			return nil, errors.Wrapf(err, "CalcIKEChecksum(%d)", role)
		}
		calculatedChecksum = ikesa.Integ_i.Sum(nil)
	}

	return calculatedChecksum[:outputLen], nil
}

func (ikesa *IKESA) EncryptMessage(role int, originData []byte) ([]byte, error) {
	var cipherText []byte
	if role == types.Role_Initiator {
		var err error
		if cipherText, err = ikesa.Encr_i.Encrypt(originData); err != nil {
			secLog.Errorf("Encrypt() failed: %+v", err)
			return nil, errors.New("Encrypt() Failed to encrypt to SK")
		}
	} else {
		var err error
		if cipherText, err = ikesa.Encr_r.Encrypt(originData); err != nil {
			secLog.Errorf("Encrypt() failed: %+v", err)
			return nil, errors.New("Failed to encrypt to SK")
		}
	}

	// Append checksum field
	checksumField := make([]byte, ikesa.integInfo.GetOutputLength())
	cipherText = append(cipherText, checksumField...)

	return cipherText, nil
}

func (ikesa *IKESA) DecryptMessage(role int, cipherText []byte) ([]byte, error) {
	var plainText []byte
	if role == types.Role_Initiator {
		var err error
		if plainText, err = ikesa.Encr_r.Decrypt(cipherText); err != nil {
			secLog.Errorf("Decrypt() failed: %+v", err)
			return nil, errors.New("Failed to decrypt SK")
		}
	} else {
		var err error
		if plainText, err = ikesa.Encr_i.Decrypt(cipherText); err != nil {
			secLog.Errorf("Decrypt() failed: %+v", err)
			return nil, errors.New("Failed to decrypt SK")
		}
	}

	return plainText, nil
}

// Decrypt
func (ikesa *IKESA) DecryptProcedure(role int, ikeMessage *message.IKEMessage,
	encryptedPayload *message.Encrypted,
) (message.IKEPayloadContainer, error) {
	if ikesa == nil {
		return nil, errors.New("IKE SA is nil")
	}

	// Check parameters
	if ikeMessage == nil {
		return nil, errors.New("IKE message is nil")
	}
	if encryptedPayload == nil {
		return nil, errors.New("IKE encrypted payload is nil")
	}

	// Check if the context contain needed data
	if ikesa.integInfo == nil {
		return nil, errors.New("No integrity algorithm specified")
	}
	if ikesa.encrInfo == nil {
		return nil, errors.New("No encryption algorithm specified")
	}

	if ikesa.Integ_i == nil {
		return nil, errors.New("No initiator's integrity key")
	}
	if ikesa.Encr_i == nil {
		return nil, errors.New("No initiator's encryption key")
	}

	checksumLength := ikesa.integInfo.GetOutputLength()
	// Checksum
	checksum := encryptedPayload.EncryptedData[len(encryptedPayload.EncryptedData)-checksumLength:]

	ikeMessageData, err := ikeMessage.Encode()
	if err != nil {
		secLog.Errorln(err)
		secLog.Error("Error occur when encoding for checksum")
		return nil, errors.New("Encoding IKE message failed")
	}

	ok, err := ikesa.verifyIntegrity(role,
		ikeMessageData[:len(ikeMessageData)-checksumLength], checksum)
	if err != nil {
		secLog.Errorf("Error occur when verifying checksum: %+v", err)
		return nil, errors.New("Error verify checksum")
	}
	if !ok {
		secLog.Warn("Message checksum failed. Drop the message.")
		return nil, errors.New("Checksum failed, drop.")
	}

	// Decrypt
	encryptedData := encryptedPayload.EncryptedData[:len(encryptedPayload.EncryptedData)-checksumLength]
	plainText, err := ikesa.DecryptMessage(role, encryptedData)
	if err != nil {
		secLog.Errorf("Error occur when decrypting message: %+v", err)
		return nil, errors.New("Error decrypting message")
	}

	var decryptedIKEPayload message.IKEPayloadContainer
	err = decryptedIKEPayload.Decode(encryptedPayload.NextPayload, plainText)
	if err != nil {
		secLog.Errorln(err)
		return nil, errors.New("Decoding decrypted payload failed")
	}

	return decryptedIKEPayload, nil
}

// Encrypt
func (ikesa *IKESA) EncryptProcedure(role int,
	ikePayload message.IKEPayloadContainer,
	responseIKEMessage *message.IKEMessage,
) error {
	if ikesa == nil {
		return errors.New("IKE SA is nil")
	}
	// Check parameters
	if len(ikePayload) == 0 {
		return errors.New("No IKE payload to be encrypted")
	}
	if responseIKEMessage == nil {
		return errors.New("Response IKE message is nil")
	}

	// Check if the context contain needed data
	if ikesa.integInfo == nil {
		return errors.New("No integrity algorithm specified")
	}
	if ikesa.encrInfo == nil {
		return errors.New("No encryption algorithm specified")
	}

	if ikesa.Integ_r == nil {
		return errors.New("No responder's integrity key")
	}
	if ikesa.Encr_r == nil {
		return errors.New("No responder's encryption key")
	}

	checksumLength := ikesa.integInfo.GetOutputLength()

	// Encrypting
	ikePayloadData, err := ikePayload.Encode()
	if err != nil {
		secLog.Error(err)
		return errors.New("Encoding IKE payload failed.")
	}

	encryptedData, err := ikesa.EncryptMessage(role, ikePayloadData)
	if err != nil {
		secLog.Errorf("Encrypting data error: %+v", err)
		return errors.New("Error encrypting message")
	}

	encryptedData = append(encryptedData, make([]byte, checksumLength)...)
	sk := responseIKEMessage.Payloads.BuildEncrypted(ikePayload[0].Type(), encryptedData)

	// Calculate checksum
	responseIKEMessageData, err := responseIKEMessage.Encode()
	if err != nil {
		secLog.Error(err)
		return errors.New("Encoding IKE message error")
	}
	checksumOfMessage, err := ikesa.calculateIntegrity(role,
		responseIKEMessageData[:len(responseIKEMessageData)-checksumLength])
	if err != nil {
		secLog.Errorf("Calculating checksum failed: %+v", err)
		return errors.New("Error calculating checksum")
	}
	checksumField := sk.EncryptedData[len(sk.EncryptedData)-checksumLength:]
	copy(checksumField, checksumOfMessage)

	return nil
}

type ChildSA struct {
	// SPI
	SPI uint32

	// Child SA transform types
	dhInfo     dh.DHType
	encrKInfo  encr.ENCRKType
	integKInfo integ.INTEGKType
	esnInfo    esn.ESNType

	// Mark
	Mark uint32

	// IP addresses
	RemotePublicIPAddr net.IP
	LocalPublicIPAddr  net.IP

	// Traffic
	IPProto  uint8
	TSLocal  *net.IPNet
	TSRemote *net.IPNet

	// Security
	InitiatorToResponderEncryptionKey []byte
	ResponderToInitiatorEncryptionKey []byte
	InitiatorToResponderIntegrityKey  []byte
	ResponderToInitiatorIntegrityKey  []byte

	// Encapsulate
	EnableEncap bool
	LocalPort   int
	RemotePort  int

	// XFRM contexts
	initiatorToResponderPolicy *netlink.XfrmPolicy
	initiatorToResponderState  *netlink.XfrmState
	responderToInitiatorPolicy *netlink.XfrmPolicy
	responderToInitiatorState  *netlink.XfrmState
}

func (childsa *ChildSA) SelectProposal(proposal *message.Proposal) bool {
	// DH is optional
	for _, transform := range proposal.DiffieHellmanGroup {
		dhType := dh.DecodeTransform(transform)
		if dhType != nil {
			if childsa.dhInfo == nil {
				childsa.dhInfo = dhType
			} else {
				if dhType.Priority() > childsa.dhInfo.Priority() {
					childsa.dhInfo = dhType
				}
			}
		}
	}
	for _, transform := range proposal.EncryptionAlgorithm {
		encrKType := encr.DecodeTransformChildSA(transform)
		if encrKType != nil {
			if childsa.encrKInfo == nil {
				childsa.encrKInfo = encrKType
			} else {
				if encrKType.Priority() > childsa.encrKInfo.Priority() {
					childsa.encrKInfo = encrKType
				}
			}
		}
	}
	if childsa.encrKInfo == nil {
		return false // mandatory
	}
	// Integ is optional
	for _, transform := range proposal.IntegrityAlgorithm {
		integKType := integ.DecodeTransformChildSA(transform)
		if integKType != nil {
			if childsa.integKInfo == nil {
				childsa.integKInfo = integKType
			} else {
				if integKType.Priority() > childsa.integKInfo.Priority() {
					childsa.integKInfo = integKType
				}
			}
		}
	}
	for _, transform := range proposal.ExtendedSequenceNumbers {
		esnType := esn.DecodeTransform(transform)
		if esnType != nil {
			if childsa.esnInfo == nil {
				childsa.esnInfo = esnType
			} else {
				if esnType.Priority() > childsa.esnInfo.Priority() {
					childsa.esnInfo = esnType
				}
			}
		}
	}
	if childsa.esnInfo == nil {
		return false // mandatory
	}
	if len(proposal.PseudorandomFunction) > 0 {
		return false // No PRF
	}
	return true
}

func (childsa *ChildSA) ToProposal() *message.Proposal {
	p := new(message.Proposal)
	p.ProtocolID = types.TypeESP
	if childsa.dhInfo != nil {
		p.DiffieHellmanGroup = append(p.DiffieHellmanGroup, dh.ToTransform(childsa.dhInfo))
	}
	p.EncryptionAlgorithm = append(p.EncryptionAlgorithm, encr.ToTransformChildSA(childsa.encrKInfo))
	if childsa.integKInfo != nil {
		p.IntegrityAlgorithm = append(p.IntegrityAlgorithm, integ.ToTransformChildSA(childsa.integKInfo))
	}
	p.ExtendedSequenceNumbers = append(p.ExtendedSequenceNumbers, esn.ToTransform(childsa.esnInfo))
	return p
}

func (childsa *ChildSA) SetProposal(proposal *message.Proposal) bool {
	if len(proposal.DiffieHellmanGroup) == 1 {
		if childsa.dhInfo = dh.DecodeTransform(proposal.DiffieHellmanGroup[0]); childsa.dhInfo == nil {
			return false
		}
	}
	if childsa.encrKInfo = encr.DecodeTransformChildSA(proposal.EncryptionAlgorithm[0]); childsa.encrKInfo == nil {
		return false
	}
	if len(proposal.IntegrityAlgorithm) == 1 {
		if childsa.integKInfo = integ.DecodeTransformChildSA(proposal.IntegrityAlgorithm[0]); childsa.encrKInfo == nil {
			return false
		}
	}
	if childsa.esnInfo = esn.DecodeTransform(proposal.ExtendedSequenceNumbers[0]); childsa.esnInfo == nil {
		return false
	}
	return true
}

// CalculateDiffieHellmanMaterials generates secret and calculate Diffie-Hellman public key
// exchange material.
// Peer public value as parameter, return local public value and shared key.
func (childsa *ChildSA) CalculateDiffieHellmanMaterials(peerPublicValue []byte) ([]byte, []byte) {
	secret := GenerateRandomNumber()
	peerPublicValueBig := new(big.Int).SetBytes(peerPublicValue)
	return childsa.dhInfo.GetPublicValue(secret), childsa.dhInfo.GetSharedKey(secret, peerPublicValueBig)
}

// Key Gen for child SA
func (childsa *ChildSA) GenerateKeyForChildSA(ikeSA *IKESA) error {
	// Check parameters
	if ikeSA == nil {
		return errors.New("IKE SA is nil")
	}
	if childsa == nil {
		return errors.New("Child SA is nil")
	}

	// Check if the context contain needed data
	if ikeSA.prfInfo == nil {
		return errors.New("No pseudorandom function specified")
	}
	if childsa.encrKInfo == nil {
		return errors.New("No encryption algorithm specified")
	}
	if ikeSA.Prf_d == nil {
		return errors.New("No key deriving key")
	}

	// Get key length for encryption and integrity key for IPSec
	var lengthEncryptionKeyIPSec, lengthIntegrityKeyIPSec, totalKeyLength int

	lengthEncryptionKeyIPSec = childsa.encrKInfo.GetKeyLength()
	if childsa.integKInfo != nil {
		lengthIntegrityKeyIPSec = childsa.integKInfo.GetKeyLength()
	}
	totalKeyLength = (lengthEncryptionKeyIPSec + lengthIntegrityKeyIPSec) * 2

	// Generate key for child security association as specified in RFC 7296 section 2.17
	seed := ikeSA.ConcatenatedNonce

	keyStream := lib.PrfPlus(ikeSA.Prf_d, seed, totalKeyLength)
	if keyStream == nil {
		return errors.New("Error happened in PrfPlus")
	}

	childsa.InitiatorToResponderEncryptionKey = append(
		childsa.InitiatorToResponderEncryptionKey,
		keyStream[:lengthEncryptionKeyIPSec]...)
	keyStream = keyStream[lengthEncryptionKeyIPSec:]
	childsa.InitiatorToResponderIntegrityKey = append(
		childsa.InitiatorToResponderIntegrityKey,
		keyStream[:lengthIntegrityKeyIPSec]...)
	keyStream = keyStream[lengthIntegrityKeyIPSec:]
	childsa.ResponderToInitiatorEncryptionKey = append(
		childsa.ResponderToInitiatorEncryptionKey,
		keyStream[:lengthEncryptionKeyIPSec]...)
	keyStream = keyStream[lengthEncryptionKeyIPSec:]
	childsa.ResponderToInitiatorIntegrityKey = append(
		childsa.ResponderToInitiatorIntegrityKey,
		keyStream[:lengthIntegrityKeyIPSec]...)

	return nil
}

func (childsa *ChildSA) GenerateXFRMContext(role int) {
	// Mark
	mark := &netlink.XfrmMark{
		Value: childsa.Mark,
	}

	// Initiator to responder state and policy
	// State
	s := new(netlink.XfrmState)
	if role == types.Role_Initiator {
		s.Src = childsa.LocalPublicIPAddr
		s.Dst = childsa.RemotePublicIPAddr
	} else {
		s.Src = childsa.RemotePublicIPAddr
		s.Dst = childsa.LocalPublicIPAddr
	}
	s.Proto = netlink.XFRM_PROTO_ESP
	s.Mode = netlink.XFRM_MODE_TUNNEL
	s.Spi = int(childsa.SPI)
	s.Mark = mark
	if childsa.integKInfo != nil {
		s.Auth = &netlink.XfrmStateAlgo{
			Name: childsa.integKInfo.XFRMString(),
			Key:  childsa.InitiatorToResponderIntegrityKey,
		}
	}
	s.Crypt = &netlink.XfrmStateAlgo{
		Name: childsa.encrKInfo.XFRMString(),
		Key:  childsa.InitiatorToResponderEncryptionKey,
	}
	s.ESN = childsa.esnInfo.Init()
	if childsa.EnableEncap {
		if role == types.Role_Initiator {
			s.Encap = &netlink.XfrmStateEncap{
				Type:    netlink.XFRM_ENCAP_ESPINUDP,
				SrcPort: childsa.LocalPort,
				DstPort: childsa.RemotePort,
			}
		} else {
			s.Encap = &netlink.XfrmStateEncap{
				Type:    netlink.XFRM_ENCAP_ESPINUDP,
				SrcPort: childsa.RemotePort,
				DstPort: childsa.LocalPort,
			}
		}
	}

	// Policy
	p := new(netlink.XfrmPolicy)
	if role == types.Role_Initiator {
		p.Src = childsa.TSLocal
		p.Dst = childsa.TSRemote
		p.Dir = netlink.XFRM_DIR_OUT
	} else {
		p.Src = childsa.TSRemote
		p.Dst = childsa.TSLocal
		p.Dir = netlink.XFRM_DIR_IN
	}
	p.Proto = netlink.Proto(childsa.IPProto)
	p.Mark = mark
	p.Tmpls = []netlink.XfrmPolicyTmpl{
		{
			Src:   s.Src,
			Dst:   s.Dst,
			Proto: s.Proto,
			Mode:  s.Mode,
			Spi:   s.Spi,
		},
	}

	childsa.initiatorToResponderState = s
	childsa.initiatorToResponderPolicy = p

	// Responder to initiator state and policy
	// State
	s = new(netlink.XfrmState)
	if role == types.Role_Initiator {
		s.Src = childsa.RemotePublicIPAddr
		s.Dst = childsa.LocalPublicIPAddr
	} else {
		s.Src = childsa.LocalPublicIPAddr
		s.Dst = childsa.RemotePublicIPAddr
	}
	s.Proto = netlink.XFRM_PROTO_ESP
	s.Mode = netlink.XFRM_MODE_TUNNEL
	s.Spi = int(childsa.SPI)
	s.Mark = mark
	if childsa.integKInfo != nil {
		s.Auth = &netlink.XfrmStateAlgo{
			Name: childsa.integKInfo.XFRMString(),
			Key:  childsa.ResponderToInitiatorIntegrityKey,
		}
	}
	s.Crypt = &netlink.XfrmStateAlgo{
		Name: childsa.encrKInfo.XFRMString(),
		Key:  childsa.ResponderToInitiatorEncryptionKey,
	}
	s.ESN = childsa.esnInfo.Init()
	if childsa.EnableEncap {
		if role == types.Role_Initiator {
			s.Encap = &netlink.XfrmStateEncap{
				Type:    netlink.XFRM_ENCAP_ESPINUDP,
				SrcPort: childsa.RemotePort,
				DstPort: childsa.LocalPort,
			}
		} else {
			s.Encap = &netlink.XfrmStateEncap{
				Type:    netlink.XFRM_ENCAP_ESPINUDP,
				SrcPort: childsa.LocalPort,
				DstPort: childsa.RemotePort,
			}
		}
	}

	// Policy
	p = new(netlink.XfrmPolicy)
	if role == types.Role_Initiator {
		p.Src = childsa.TSRemote
		p.Dst = childsa.TSLocal
		p.Dir = netlink.XFRM_DIR_IN
	} else {
		p.Src = childsa.TSLocal
		p.Dst = childsa.TSRemote
		p.Dir = netlink.XFRM_DIR_OUT
	}
	p.Proto = netlink.Proto(childsa.IPProto)
	p.Mark = mark
	p.Tmpls = []netlink.XfrmPolicyTmpl{
		{
			Src:   s.Src,
			Dst:   s.Dst,
			Proto: s.Proto,
			Mode:  s.Mode,
			Spi:   s.Spi,
		},
	}

	childsa.responderToInitiatorState = s
	childsa.responderToInitiatorPolicy = p
}

func (childsa *ChildSA) XFRMRuleAdd() error {
	if err := netlink.XfrmStateAdd(childsa.initiatorToResponderState); err != nil {
		secLog.Errorf("Add XFRM state failed: %+v", err)
		return errors.New("Add XFRM initiator to responder state failed")
	}
	if err := netlink.XfrmPolicyAdd(childsa.initiatorToResponderPolicy); err != nil {
		secLog.Errorf("Add XFRM policy failed: %+v", err)
		return errors.New("Add XFRM initiator to responder policy failed")
	}
	if err := netlink.XfrmStateAdd(childsa.responderToInitiatorState); err != nil {
		secLog.Errorf("Add XFRM state failed: %+v", err)
		return errors.New("Add XFRM responder to initiator state failed")
	}
	if err := netlink.XfrmPolicyAdd(childsa.responderToInitiatorPolicy); err != nil {
		secLog.Errorf("Add XFRM policy failed: %+v", err)
		return errors.New("Add XFRM responder to initiator policy failed")
	}
	return nil
}

func (childsa *ChildSA) XFRMRuleFlush() error {
	if err := netlink.XfrmStateDel(childsa.initiatorToResponderState); err != nil {
		secLog.Errorf("Delete XFRM state failed: %+v", err)
		return errors.New("Delete XFRM initiator to responder state failed")
	}
	if err := netlink.XfrmPolicyDel(childsa.initiatorToResponderPolicy); err != nil {
		secLog.Errorf("Delete XFRM policy failed: %+v", err)
		return errors.New("Delete XFRM initiator to responder policy failed")
	}
	if err := netlink.XfrmStateDel(childsa.responderToInitiatorState); err != nil {
		secLog.Errorf("Delete XFRM state failed: %+v", err)
		return errors.New("Delete XFRM responder to initiator state failed")
	}
	if err := netlink.XfrmPolicyDel(childsa.responderToInitiatorPolicy); err != nil {
		secLog.Errorf("Delete XFRM policy failed: %+v", err)
		return errors.New("Delete XFRM responder to initiator policy failed")
	}
	return nil
}

/* Archive for future use
// Certificate
func CompareRootCertificate(certificateEncoding uint8, requestedCertificateAuthorityHash []byte) bool {
	if certificateEncoding != types.X509CertificateSignature {
		secLog.Debugf("Not support certificate type: %d. Reject.", certificateEncoding)
		return false
	}

	n3iwfSelf := context.N3IWFSelf()

	if len(n3iwfSelf.CertificateAuthority) == 0 {
		secLog.Error("Certificate authority in context is empty")
		return false
	}

	return bytes.Equal(n3iwfSelf.CertificateAuthority, requestedCertificateAuthorityHash)
}
*/
