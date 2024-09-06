package message

import (
	"encoding/binary"

	"github.com/pkg/errors"
)

type IKEMessage struct {
	InitiatorSPI uint64
	ResponderSPI uint64
	MajorVersion uint8
	MinorVersion uint8
	ExchangeType uint8
	Flags        uint8
	MessageID    uint32
	Payloads     IKEPayloadContainer
}

func GetSPI(b []byte) (uint64, uint64) {
	if len(b) < 16 {
		return 0, 0
	}

	var initiatorSPI, responderSPI uint64
	binary.BigEndian.PutUint64(b[0:8], initiatorSPI)
	binary.BigEndian.PutUint64(b[8:16], responderSPI)
	return initiatorSPI, responderSPI
}

func (ikeMessage *IKEMessage) Encode() ([]byte, error) {
	ikeMessageData := make([]byte, 28)

	binary.BigEndian.PutUint64(ikeMessageData[0:8], ikeMessage.InitiatorSPI)
	binary.BigEndian.PutUint64(ikeMessageData[8:16], ikeMessage.ResponderSPI)
	ikeMessageData[17] = (ikeMessage.MajorVersion << 4) | (ikeMessage.MinorVersion & 0x0F)
	ikeMessageData[18] = ikeMessage.ExchangeType
	ikeMessageData[19] = ikeMessage.Flags
	binary.BigEndian.PutUint32(ikeMessageData[20:24], ikeMessage.MessageID)

	if len(ikeMessage.Payloads) > 0 {
		ikeMessageData[16] = byte(ikeMessage.Payloads[0].Type())
	} else {
		ikeMessageData[16] = byte(NoNext)
	}

	ikeMessagePayloadData, err := ikeMessage.Payloads.Encode()
	if err != nil {
		return nil, errors.Errorf("Encode(): EncodePayload failed: %+v", err)
	}

	ikeMessageData = append(ikeMessageData, ikeMessagePayloadData...)
	binary.BigEndian.PutUint32(ikeMessageData[24:28], uint32(len(ikeMessageData)))
	return ikeMessageData, nil
}

func (ikeMessage *IKEMessage) Decode(b []byte) error {
	// IKE message packet format this implementation referenced is
	// defined in RFC 7296, Section 3.1
	// bounds checking
	if len(b) < 28 {
		return errors.Errorf("Decode(): Received broken IKE header")
	}
	ikeMessageLength := binary.BigEndian.Uint32(b[24:28])
	if ikeMessageLength < 28 {
		return errors.Errorf("Decode(): Illegal IKE message length %d < header length 20", ikeMessageLength)
	}
	// len() return int, which is 64 bit on 64-bit host and 32 bit
	// on 32-bit host, so this implementation may potentially cause
	// problem on 32-bit machine
	if len(b) != int(ikeMessageLength) {
		return errors.Errorf("Decode(): The length of received message not matchs the length specified in header")
	}

	nextPayload := b[16]

	ikeMessage.InitiatorSPI = binary.BigEndian.Uint64(b[:8])
	ikeMessage.ResponderSPI = binary.BigEndian.Uint64(b[8:16])
	ikeMessage.MajorVersion = b[17] >> 4
	ikeMessage.MinorVersion = b[17] & 0x0F
	ikeMessage.ExchangeType = b[18]
	ikeMessage.Flags = b[19]
	ikeMessage.MessageID = binary.BigEndian.Uint32(b[20:24])

	err := ikeMessage.Payloads.Decode(nextPayload, b[28:])
	if err != nil {
		return errors.Errorf("Decode(): DecodePayload failed: %+v", err)
	}

	return nil
}

type IKEPayloadContainer []IKEPayload

func (container *IKEPayloadContainer) Encode() ([]byte, error) {
	ikeMessagePayloadData := make([]byte, 0)

	for index, payload := range *container {
		payloadData := make([]byte, 4)     // IKE payload general header
		if (index + 1) < len(*container) { // if it has next payload
			payloadData[0] = uint8((*container)[index+1].Type())
		} else {
			if payload.Type() == TypeSK {
				payloadData[0] = payload.(*Encrypted).NextPayload
			} else {
				payloadData[0] = byte(NoNext)
			}
		}

		data, err := payload.marshal()
		if err != nil {
			return nil, errors.Errorf("EncodePayload(): Failed to marshal payload: %+v", err)
		}

		payloadData = append(payloadData, data...)
		binary.BigEndian.PutUint16(payloadData[2:4], uint16(len(payloadData)))

		ikeMessagePayloadData = append(ikeMessagePayloadData, payloadData...)
	}

	return ikeMessagePayloadData, nil
}

func (container *IKEPayloadContainer) Decode(nextPayload uint8, b []byte) error {
	for len(b) > 0 {
		// bounds checking
		if len(b) < 4 {
			return errors.Errorf("DecodePayload(): No sufficient bytes to decode next payload")
		}
		payloadLength := binary.BigEndian.Uint16(b[2:4])
		if payloadLength < 4 {
			return errors.Errorf("DecodePayload(): Illegal payload length %d < header length 4", payloadLength)
		}
		if len(b) < int(payloadLength) {
			return errors.Errorf("DecodePayload(): The length of received message not matchs the length specified in header")
		}

		criticalBit := (b[1] & 0x80) >> 7

		var payload IKEPayload

		switch IKEPayloadType(nextPayload) {
		case TypeSA:
			payload = new(SecurityAssociation)
		case TypeKE:
			payload = new(KeyExchange)
		case TypeIDi:
			payload = new(IdentificationInitiator)
		case TypeIDr:
			payload = new(IdentificationResponder)
		case TypeCERT:
			payload = new(Certificate)
		case TypeCERTreq:
			payload = new(CertificateRequest)
		case TypeAUTH:
			payload = new(Authentication)
		case TypeNiNr:
			payload = new(Nonce)
		case TypeN:
			payload = new(Notification)
		case TypeD:
			payload = new(Delete)
		case TypeV:
			payload = new(VendorID)
		case TypeTSi:
			payload = new(TrafficSelectorInitiator)
		case TypeTSr:
			payload = new(TrafficSelectorResponder)
		case TypeSK:
			encryptedPayload := new(Encrypted)
			encryptedPayload.NextPayload = b[0]
			payload = encryptedPayload
		case TypeCP:
			payload = new(Configuration)
		case TypeEAP:
			payload = new(EAP)
		default:
			if criticalBit == 0 {
				// Skip this payload
				nextPayload = b[0]
				b = b[payloadLength:]
				continue
			} else {
				// TODO: Reject this IKE message
				return errors.Errorf("Unknown payload type: %d", nextPayload)
			}
		}

		if err := payload.unmarshal(b[4:payloadLength]); err != nil {
			return errors.Errorf("DecodePayload(): Unmarshal payload failed: %+v", err)
		}

		*container = append(*container, payload)

		nextPayload = b[0]
		b = b[payloadLength:]
	}

	return nil
}

type IKEPayload interface {
	// Type specifies the IKE payload types
	Type() IKEPayloadType

	// Called by Encode() or Decode()
	marshal() ([]byte, error)
	unmarshal(b []byte) error
}

// Definition of Security Association

var _ IKEPayload = &SecurityAssociation{}

type SecurityAssociation struct {
	Proposals ProposalContainer
}

type ProposalContainer []*Proposal

type Proposal struct {
	ProposalNumber          uint8
	ProtocolID              uint8
	SPI                     []byte
	EncryptionAlgorithm     TransformContainer
	PseudorandomFunction    TransformContainer
	IntegrityAlgorithm      TransformContainer
	DiffieHellmanGroup      TransformContainer
	ExtendedSequenceNumbers TransformContainer
}

type TransformContainer []*Transform

type Transform struct {
	TransformType                uint8
	TransformID                  uint16
	AttributePresent             bool
	AttributeFormat              uint8
	AttributeType                uint16
	AttributeValue               uint16
	VariableLengthAttributeValue []byte
}

func (securityAssociation *SecurityAssociation) Type() IKEPayloadType { return TypeSA }

func (securityAssociation *SecurityAssociation) marshal() ([]byte, error) {
	securityAssociationData := make([]byte, 0)

	for proposalIndex, proposal := range securityAssociation.Proposals {
		proposalData := make([]byte, 8)

		if (proposalIndex + 1) < len(securityAssociation.Proposals) {
			proposalData[0] = 2
		} else {
			proposalData[0] = 0
		}

		proposalData[4] = proposal.ProposalNumber
		proposalData[5] = proposal.ProtocolID

		proposalData[6] = uint8(len(proposal.SPI))
		if len(proposal.SPI) > 0 {
			proposalData = append(proposalData, proposal.SPI...)
		}

		// combine all transforms
		var transformList []*Transform
		transformList = append(transformList, proposal.EncryptionAlgorithm...)
		transformList = append(transformList, proposal.PseudorandomFunction...)
		transformList = append(transformList, proposal.IntegrityAlgorithm...)
		transformList = append(transformList, proposal.DiffieHellmanGroup...)
		transformList = append(transformList, proposal.ExtendedSequenceNumbers...)

		if len(transformList) == 0 {
			return nil, errors.Errorf("One proposal has no any transform")
		}
		proposalData[7] = uint8(len(transformList))

		proposalTransformData := make([]byte, 0)

		for transformIndex, transform := range transformList {
			transformData := make([]byte, 8)

			if (transformIndex + 1) < len(transformList) {
				transformData[0] = 3
			} else {
				transformData[0] = 0
			}

			transformData[4] = transform.TransformType
			binary.BigEndian.PutUint16(transformData[6:8], transform.TransformID)

			if transform.AttributePresent {
				attributeData := make([]byte, 4)

				if transform.AttributeFormat == 0 {
					// TLV
					if len(transform.VariableLengthAttributeValue) == 0 {
						return nil, errors.Errorf("Attribute of one transform not specified")
					}
					attributeFormatAndType := ((uint16(transform.AttributeFormat) & 0x1) << 15) | transform.AttributeType
					binary.BigEndian.PutUint16(attributeData[0:2], attributeFormatAndType)
					binary.BigEndian.PutUint16(attributeData[2:4], uint16(len(transform.VariableLengthAttributeValue)))
					attributeData = append(attributeData, transform.VariableLengthAttributeValue...)
				} else {
					// TV
					attributeFormatAndType := ((uint16(transform.AttributeFormat) & 0x1) << 15) | transform.AttributeType
					binary.BigEndian.PutUint16(attributeData[0:2], attributeFormatAndType)
					binary.BigEndian.PutUint16(attributeData[2:4], transform.AttributeValue)
				}

				transformData = append(transformData, attributeData...)
			}

			binary.BigEndian.PutUint16(transformData[2:4], uint16(len(transformData)))

			proposalTransformData = append(proposalTransformData, transformData...)
		}

		proposalData = append(proposalData, proposalTransformData...)
		binary.BigEndian.PutUint16(proposalData[2:4], uint16(len(proposalData)))

		securityAssociationData = append(securityAssociationData, proposalData...)
	}

	return securityAssociationData, nil
}

func (securityAssociation *SecurityAssociation) unmarshal(b []byte) error {
	for len(b) > 0 {
		// bounds checking
		if len(b) < 8 {
			return errors.Errorf("Proposal: No sufficient bytes to decode next proposal")
		}
		proposalLength := binary.BigEndian.Uint16(b[2:4])
		if proposalLength < 8 {
			return errors.Errorf("Proposal: Illegal payload length %d < header length 8", proposalLength)
		}
		if len(b) < int(proposalLength) {
			return errors.Errorf("Proposal: The length of received message not matchs the length specified in header")
		}

		proposal := new(Proposal)
		var transformData []byte

		proposal.ProposalNumber = b[4]
		proposal.ProtocolID = b[5]

		spiSize := b[6]
		if spiSize > 0 {
			// bounds checking
			if len(b) < int(8+spiSize) {
				return errors.Errorf("Proposal: No sufficient bytes for unmarshalling SPI of proposal")
			}
			proposal.SPI = append(proposal.SPI, b[8:8+spiSize]...)
		}

		transformData = b[8+spiSize : proposalLength]

		for len(transformData) > 0 {
			// bounds checking
			if len(transformData) < 8 {
				return errors.Errorf("Transform: No sufficient bytes to decode next transform")
			}
			transformLength := binary.BigEndian.Uint16(transformData[2:4])
			if transformLength < 8 {
				return errors.Errorf("Transform: Illegal payload length %d < header length 8", transformLength)
			}
			if len(transformData) < int(transformLength) {
				return errors.Errorf("Transform: The length of received message not matchs the length specified in header")
			}

			transform := new(Transform)

			transform.TransformType = transformData[4]
			transform.TransformID = binary.BigEndian.Uint16(transformData[6:8])
			if transformLength > 8 {
				transform.AttributePresent = true
				transform.AttributeFormat = ((transformData[8] & 0x80) >> 7)
				transform.AttributeType = binary.BigEndian.Uint16(transformData[8:10]) & 0x7f

				if transform.AttributeFormat == 0 {
					attributeLength := binary.BigEndian.Uint16(transformData[10:12])
					// bounds checking
					if (12 + attributeLength) != transformLength {
						return errors.Errorf("Illegal attribute length %d not satisfies the transform length %d",
							attributeLength, transformLength)
					}
					copy(transform.VariableLengthAttributeValue, transformData[12:12+attributeLength])
				} else {
					transform.AttributeValue = binary.BigEndian.Uint16(transformData[10:12])
				}
			}

			switch transform.TransformType {
			case TypeEncryptionAlgorithm:
				proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, transform)
			case TypePseudorandomFunction:
				proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, transform)
			case TypeIntegrityAlgorithm:
				proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, transform)
			case TypeDiffieHellmanGroup:
				proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, transform)
			case TypeExtendedSequenceNumbers:
				proposal.ExtendedSequenceNumbers = append(proposal.ExtendedSequenceNumbers, transform)
			}

			transformData = transformData[transformLength:]
		}

		securityAssociation.Proposals = append(securityAssociation.Proposals, proposal)

		b = b[proposalLength:]
	}

	return nil
}

// Definition of Key Exchange

var _ IKEPayload = &KeyExchange{}

type KeyExchange struct {
	DiffieHellmanGroup uint16
	KeyExchangeData    []byte
}

func (keyExchange *KeyExchange) Type() IKEPayloadType { return TypeKE }

func (keyExchange *KeyExchange) marshal() ([]byte, error) {
	keyExchangeData := make([]byte, 4)
	binary.BigEndian.PutUint16(keyExchangeData[0:2], keyExchange.DiffieHellmanGroup)
	keyExchangeData = append(keyExchangeData, keyExchange.KeyExchangeData...)
	return keyExchangeData, nil
}

func (keyExchange *KeyExchange) unmarshal(b []byte) error {
	if len(b) > 0 {
		// bounds checking
		if len(b) <= 4 {
			return errors.Errorf("KeyExchange: No sufficient bytes to decode next key exchange data")
		}

		keyExchange.DiffieHellmanGroup = binary.BigEndian.Uint16(b[0:2])
		keyExchange.KeyExchangeData = append(keyExchange.KeyExchangeData, b[4:]...)
	}

	return nil
}

// Definition of Identification - Initiator

var _ IKEPayload = &IdentificationInitiator{}

type IdentificationInitiator struct {
	IDType uint8
	IDData []byte
}

func (identification *IdentificationInitiator) Type() IKEPayloadType { return TypeIDi }

func (identification *IdentificationInitiator) marshal() ([]byte, error) {
	identificationData := make([]byte, 4)
	identificationData[0] = identification.IDType
	identificationData = append(identificationData, identification.IDData...)
	return identificationData, nil
}

func (identification *IdentificationInitiator) unmarshal(b []byte) error {
	if len(b) > 0 {
		// bounds checking
		if len(b) <= 4 {
			return errors.Errorf("Identification: No sufficient bytes to decode next identification")
		}

		identification.IDType = b[0]
		identification.IDData = append(identification.IDData, b[4:]...)
	}

	return nil
}

// Definition of Identification - Responder

var _ IKEPayload = &IdentificationResponder{}

type IdentificationResponder struct {
	IDType uint8
	IDData []byte
}

func (identification *IdentificationResponder) Type() IKEPayloadType { return TypeIDr }

func (identification *IdentificationResponder) marshal() ([]byte, error) {
	identificationData := make([]byte, 4)
	identificationData[0] = identification.IDType
	identificationData = append(identificationData, identification.IDData...)
	return identificationData, nil
}

func (identification *IdentificationResponder) unmarshal(b []byte) error {
	if len(b) > 0 {
		// bounds checking
		if len(b) <= 4 {
			return errors.Errorf("Identification: No sufficient bytes to decode next identification")
		}

		identification.IDType = b[0]
		identification.IDData = append(identification.IDData, b[4:]...)
	}

	return nil
}

// Definition of Certificate

var _ IKEPayload = &Certificate{}

type Certificate struct {
	CertificateEncoding uint8
	CertificateData     []byte
}

func (certificate *Certificate) Type() IKEPayloadType { return TypeCERT }

func (certificate *Certificate) marshal() ([]byte, error) {
	certificateData := make([]byte, 1)
	certificateData[0] = certificate.CertificateEncoding
	certificateData = append(certificateData, certificate.CertificateData...)
	return certificateData, nil
}

func (certificate *Certificate) unmarshal(b []byte) error {
	if len(b) > 0 {
		// bounds checking
		if len(b) <= 1 {
			return errors.Errorf("Certificate: No sufficient bytes to decode next certificate")
		}

		certificate.CertificateEncoding = b[0]
		certificate.CertificateData = append(certificate.CertificateData, b[1:]...)
	}

	return nil
}

// Definition of Certificate Request

var _ IKEPayload = &CertificateRequest{}

type CertificateRequest struct {
	CertificateEncoding    uint8
	CertificationAuthority []byte
}

func (certificateRequest *CertificateRequest) Type() IKEPayloadType { return TypeCERTreq }

func (certificateRequest *CertificateRequest) marshal() ([]byte, error) {
	certificateRequestData := make([]byte, 1)
	certificateRequestData[0] = certificateRequest.CertificateEncoding
	certificateRequestData = append(certificateRequestData, certificateRequest.CertificationAuthority...)
	return certificateRequestData, nil
}

func (certificateRequest *CertificateRequest) unmarshal(b []byte) error {
	if len(b) > 0 {
		// bounds checking
		if len(b) <= 1 {
			return errors.Errorf("CertificateRequest: No sufficient bytes to decode next certificate request")
		}

		certificateRequest.CertificateEncoding = b[0]
		certificateRequest.CertificationAuthority = append(certificateRequest.CertificationAuthority, b[1:]...)
	}

	return nil
}

// Definition of Authentication

var _ IKEPayload = &Authentication{}

type Authentication struct {
	AuthenticationMethod uint8
	AuthenticationData   []byte
}

func (authentication *Authentication) Type() IKEPayloadType { return TypeAUTH }

func (authentication *Authentication) marshal() ([]byte, error) {
	authenticationData := make([]byte, 4)
	authenticationData[0] = authentication.AuthenticationMethod
	authenticationData = append(authenticationData, authentication.AuthenticationData...)
	return authenticationData, nil
}

func (authentication *Authentication) unmarshal(b []byte) error {
	if len(b) > 0 {
		// bounds checking
		if len(b) <= 4 {
			return errors.Errorf("Authentication: No sufficient bytes to decode next authentication")
		}

		authentication.AuthenticationMethod = b[0]
		authentication.AuthenticationData = append(authentication.AuthenticationData, b[4:]...)
	}

	return nil
}

// Definition of Nonce

var _ IKEPayload = &Nonce{}

type Nonce struct {
	NonceData []byte
}

func (nonce *Nonce) Type() IKEPayloadType { return TypeNiNr }

func (nonce *Nonce) marshal() ([]byte, error) {
	nonceData := make([]byte, 0)
	nonceData = append(nonceData, nonce.NonceData...)
	return nonceData, nil
}

func (nonce *Nonce) unmarshal(b []byte) error {
	if len(b) > 0 {
		nonce.NonceData = append(nonce.NonceData, b...)
	}
	return nil
}

// Definition of Notification

var _ IKEPayload = &Notification{}

type Notification struct {
	ProtocolID        uint8
	NotifyMessageType uint16
	SPI               []byte
	NotificationData  []byte
}

func (notification *Notification) Type() IKEPayloadType { return TypeN }

func (notification *Notification) marshal() ([]byte, error) {
	notificationData := make([]byte, 4)

	notificationData[0] = notification.ProtocolID
	notificationData[1] = uint8(len(notification.SPI))
	binary.BigEndian.PutUint16(notificationData[2:4], notification.NotifyMessageType)

	notificationData = append(notificationData, notification.SPI...)
	notificationData = append(notificationData, notification.NotificationData...)
	return notificationData, nil
}

func (notification *Notification) unmarshal(b []byte) error {
	if len(b) > 0 {
		// bounds checking
		if len(b) < 4 {
			return errors.Errorf("Notification: No sufficient bytes to decode next notification")
		}
		spiSize := b[1]
		if len(b) < int(4+spiSize) {
			return errors.Errorf("Notification: No sufficient bytes to get SPI according to the length specified in header")
		}

		notification.ProtocolID = b[0]
		notification.NotifyMessageType = binary.BigEndian.Uint16(b[2:4])

		notification.SPI = append(notification.SPI, b[4:4+spiSize]...)
		notification.NotificationData = append(notification.NotificationData, b[4+spiSize:]...)
	}

	return nil
}

// Definition of Delete

var _ IKEPayload = &Delete{}

type Delete struct {
	ProtocolID  uint8
	SPISize     uint8
	NumberOfSPI uint16
	SPIs        []byte
}

func (d *Delete) Type() IKEPayloadType { return TypeD }

func (d *Delete) marshal() ([]byte, error) {
	if len(d.SPIs) != (int(d.SPISize) * int(d.NumberOfSPI)) {
		return nil, errors.Errorf("Total bytes of all SPIs not correct")
	}

	deleteData := make([]byte, 4)

	deleteData[0] = d.ProtocolID
	deleteData[1] = d.SPISize
	binary.BigEndian.PutUint16(deleteData[2:4], d.NumberOfSPI)

	if int(d.NumberOfSPI) > 0 {
		deleteData = append(deleteData, d.SPIs...)
	}

	return deleteData, nil
}

func (d *Delete) unmarshal(b []byte) error {
	if len(b) > 0 {
		// bounds checking
		if len(b) <= 3 {
			return errors.Errorf("Delete: No sufficient bytes to decode next delete")
		}
		spiSize := b[1]
		numberOfSPI := binary.BigEndian.Uint16(b[2:4])
		if len(b) < (4 + (int(spiSize) * int(numberOfSPI))) {
			return errors.Errorf("Delete: No Sufficient bytes to get SPIs according to the length specified in header")
		}

		d.ProtocolID = b[0]
		d.SPISize = spiSize
		d.NumberOfSPI = numberOfSPI

		d.SPIs = append(d.SPIs, b[4:]...)
	}

	return nil
}

// Definition of Vendor ID

var _ IKEPayload = &VendorID{}

type VendorID struct {
	VendorIDData []byte
}

func (vendorID *VendorID) Type() IKEPayloadType { return TypeV }

func (vendorID *VendorID) marshal() ([]byte, error) {
	return vendorID.VendorIDData, nil
}

func (vendorID *VendorID) unmarshal(b []byte) error {
	if len(b) > 0 {
		vendorID.VendorIDData = append(vendorID.VendorIDData, b...)
	}
	return nil
}

// Definition of Traffic Selector - Initiator

var _ IKEPayload = &TrafficSelectorInitiator{}

type TrafficSelectorInitiator struct {
	TrafficSelectors IndividualTrafficSelectorContainer
}

type IndividualTrafficSelectorContainer []*IndividualTrafficSelector

type IndividualTrafficSelector struct {
	TSType       uint8
	IPProtocolID uint8
	StartPort    uint16
	EndPort      uint16
	StartAddress []byte
	EndAddress   []byte
}

func (trafficSelector *TrafficSelectorInitiator) Type() IKEPayloadType { return TypeTSi }

func (trafficSelector *TrafficSelectorInitiator) marshal() ([]byte, error) {
	if len(trafficSelector.TrafficSelectors) == 0 {
		return nil, errors.Errorf("TrafficSelector: Contains no traffic selector for marshalling message")
	}

	trafficSelectorData := make([]byte, 4)
	trafficSelectorData[0] = uint8(len(trafficSelector.TrafficSelectors))

	for _, individualTrafficSelector := range trafficSelector.TrafficSelectors {
		if individualTrafficSelector.TSType == TS_IPV4_ADDR_RANGE {
			// Address length checking
			if len(individualTrafficSelector.StartAddress) != 4 {
				return nil, errors.Errorf("TrafficSelector: Start IPv4 address length is not correct")
			}
			if len(individualTrafficSelector.EndAddress) != 4 {
				return nil, errors.Errorf("TrafficSelector: End IPv4 address length is not correct")
			}

			individualTrafficSelectorData := make([]byte, 8)

			individualTrafficSelectorData[0] = individualTrafficSelector.TSType
			individualTrafficSelectorData[1] = individualTrafficSelector.IPProtocolID
			binary.BigEndian.PutUint16(individualTrafficSelectorData[4:6], individualTrafficSelector.StartPort)
			binary.BigEndian.PutUint16(individualTrafficSelectorData[6:8], individualTrafficSelector.EndPort)

			individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.StartAddress...)
			individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.EndAddress...)

			binary.BigEndian.PutUint16(individualTrafficSelectorData[2:4], uint16(len(individualTrafficSelectorData)))

			trafficSelectorData = append(trafficSelectorData, individualTrafficSelectorData...)
		} else if individualTrafficSelector.TSType == TS_IPV6_ADDR_RANGE {
			// Address length checking
			if len(individualTrafficSelector.StartAddress) != 16 {
				return nil, errors.Errorf("TrafficSelector: Start IPv6 address length is not correct")
			}
			if len(individualTrafficSelector.EndAddress) != 16 {
				return nil, errors.Errorf("TrafficSelector: End IPv6 address length is not correct")
			}

			individualTrafficSelectorData := make([]byte, 8)

			individualTrafficSelectorData[0] = individualTrafficSelector.TSType
			individualTrafficSelectorData[1] = individualTrafficSelector.IPProtocolID
			binary.BigEndian.PutUint16(individualTrafficSelectorData[4:6], individualTrafficSelector.StartPort)
			binary.BigEndian.PutUint16(individualTrafficSelectorData[6:8], individualTrafficSelector.EndPort)

			individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.StartAddress...)
			individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.EndAddress...)

			binary.BigEndian.PutUint16(individualTrafficSelectorData[2:4], uint16(len(individualTrafficSelectorData)))

			trafficSelectorData = append(trafficSelectorData, individualTrafficSelectorData...)
		} else {
			return nil, errors.Errorf("TrafficSelector: Unsupported traffic selector type")
		}
	}

	return trafficSelectorData, nil
}

func (trafficSelector *TrafficSelectorInitiator) unmarshal(b []byte) error {
	if len(b) > 0 {
		// bounds checking
		if len(b) < 4 {
			return errors.Errorf("TrafficSelector: No sufficient bytes to get number of traffic selector in header")
		}

		numberOfSPI := b[0]

		b = b[4:]

		for ; numberOfSPI > 0; numberOfSPI-- {
			// bounds checking
			if len(b) < 4 {
				return errors.Errorf(
					"TrafficSelector: No sufficient bytes to decode next individual traffic selector length in header")
			}
			trafficSelectorType := b[0]
			if trafficSelectorType == TS_IPV4_ADDR_RANGE {
				selectorLength := binary.BigEndian.Uint16(b[2:4])
				if selectorLength != 16 {
					return errors.Errorf("TrafficSelector: A TS_IPV4_ADDR_RANGE type traffic selector should has length 16 bytes")
				}
				if len(b) < int(selectorLength) {
					return errors.Errorf("TrafficSelector: No sufficient bytes to decode next individual traffic selector")
				}

				individualTrafficSelector := &IndividualTrafficSelector{}

				individualTrafficSelector.TSType = b[0]
				individualTrafficSelector.IPProtocolID = b[1]
				individualTrafficSelector.StartPort = binary.BigEndian.Uint16(b[4:6])
				individualTrafficSelector.EndPort = binary.BigEndian.Uint16(b[6:8])

				individualTrafficSelector.StartAddress = append(individualTrafficSelector.StartAddress, b[8:12]...)
				individualTrafficSelector.EndAddress = append(individualTrafficSelector.EndAddress, b[12:16]...)

				trafficSelector.TrafficSelectors = append(trafficSelector.TrafficSelectors, individualTrafficSelector)

				b = b[16:]
			} else if trafficSelectorType == TS_IPV6_ADDR_RANGE {
				selectorLength := binary.BigEndian.Uint16(b[2:4])
				if selectorLength != 40 {
					return errors.Errorf("TrafficSelector: A TS_IPV6_ADDR_RANGE type traffic selector should has length 40 bytes")
				}
				if len(b) < int(selectorLength) {
					return errors.Errorf("TrafficSelector: No sufficient bytes to decode next individual traffic selector")
				}

				individualTrafficSelector := &IndividualTrafficSelector{}

				individualTrafficSelector.TSType = b[0]
				individualTrafficSelector.IPProtocolID = b[1]
				individualTrafficSelector.StartPort = binary.BigEndian.Uint16(b[4:6])
				individualTrafficSelector.EndPort = binary.BigEndian.Uint16(b[6:8])

				individualTrafficSelector.StartAddress = append(individualTrafficSelector.StartAddress, b[8:24]...)
				individualTrafficSelector.EndAddress = append(individualTrafficSelector.EndAddress, b[24:40]...)

				trafficSelector.TrafficSelectors = append(trafficSelector.TrafficSelectors, individualTrafficSelector)

				b = b[40:]
			} else {
				return errors.Errorf("TrafficSelector: Unsupported traffic selector type")
			}
		}
	}

	return nil
}

// Definition of Traffic Selector - Responder

var _ IKEPayload = &TrafficSelectorResponder{}

type TrafficSelectorResponder struct {
	TrafficSelectors IndividualTrafficSelectorContainer
}

func (trafficSelector *TrafficSelectorResponder) Type() IKEPayloadType { return TypeTSr }

func (trafficSelector *TrafficSelectorResponder) marshal() ([]byte, error) {
	if len(trafficSelector.TrafficSelectors) > 0 {
		trafficSelectorData := make([]byte, 4)
		trafficSelectorData[0] = uint8(len(trafficSelector.TrafficSelectors))

		for _, individualTrafficSelector := range trafficSelector.TrafficSelectors {
			if individualTrafficSelector.TSType == TS_IPV4_ADDR_RANGE {
				// Address length checking
				if len(individualTrafficSelector.StartAddress) != 4 {
					return nil, errors.Errorf("TrafficSelector: Start IPv4 address length is not correct")
				}
				if len(individualTrafficSelector.EndAddress) != 4 {
					return nil, errors.Errorf("TrafficSelector: End IPv4 address length is not correct")
				}

				individualTrafficSelectorData := make([]byte, 8)

				individualTrafficSelectorData[0] = individualTrafficSelector.TSType
				individualTrafficSelectorData[1] = individualTrafficSelector.IPProtocolID
				binary.BigEndian.PutUint16(individualTrafficSelectorData[4:6], individualTrafficSelector.StartPort)
				binary.BigEndian.PutUint16(individualTrafficSelectorData[6:8], individualTrafficSelector.EndPort)

				individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.StartAddress...)
				individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.EndAddress...)

				binary.BigEndian.PutUint16(individualTrafficSelectorData[2:4], uint16(len(individualTrafficSelectorData)))

				trafficSelectorData = append(trafficSelectorData, individualTrafficSelectorData...)
			} else if individualTrafficSelector.TSType == TS_IPV6_ADDR_RANGE {
				// Address length checking
				if len(individualTrafficSelector.StartAddress) != 16 {
					return nil, errors.Errorf("TrafficSelector: Start IPv6 address length is not correct")
				}
				if len(individualTrafficSelector.EndAddress) != 16 {
					return nil, errors.Errorf("TrafficSelector: End IPv6 address length is not correct")
				}

				individualTrafficSelectorData := make([]byte, 8)

				individualTrafficSelectorData[0] = individualTrafficSelector.TSType
				individualTrafficSelectorData[1] = individualTrafficSelector.IPProtocolID
				binary.BigEndian.PutUint16(individualTrafficSelectorData[4:6], individualTrafficSelector.StartPort)
				binary.BigEndian.PutUint16(individualTrafficSelectorData[6:8], individualTrafficSelector.EndPort)

				individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.StartAddress...)
				individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.EndAddress...)

				binary.BigEndian.PutUint16(individualTrafficSelectorData[2:4], uint16(len(individualTrafficSelectorData)))

				trafficSelectorData = append(trafficSelectorData, individualTrafficSelectorData...)
			} else {
				return nil, errors.Errorf("TrafficSelector: Unsupported traffic selector type")
			}
		}

		return trafficSelectorData, nil
	} else {
		return nil, errors.Errorf("TrafficSelector: Contains no traffic selector for marshalling message")
	}
}

func (trafficSelector *TrafficSelectorResponder) unmarshal(b []byte) error {
	if len(b) > 0 {
		// bounds checking
		if len(b) < 4 {
			return errors.Errorf("TrafficSelector: No sufficient bytes to get number of traffic selector in header")
		}

		numberOfSPI := b[0]

		b = b[4:]
		for ; numberOfSPI > 0; numberOfSPI-- {
			// bounds checking
			if len(b) < 4 {
				return errors.Errorf(
					"TrafficSelector: No sufficient bytes to decode next individual traffic selector length in header")
			}
			trafficSelectorType := b[0]
			if trafficSelectorType == TS_IPV4_ADDR_RANGE {
				selectorLength := binary.BigEndian.Uint16(b[2:4])
				if selectorLength != 16 {
					return errors.Errorf("TrafficSelector: A TS_IPV4_ADDR_RANGE type traffic selector should has length 16 bytes")
				}
				if len(b) < int(selectorLength) {
					return errors.Errorf("TrafficSelector: No sufficient bytes to decode next individual traffic selector")
				}

				individualTrafficSelector := &IndividualTrafficSelector{}

				individualTrafficSelector.TSType = b[0]
				individualTrafficSelector.IPProtocolID = b[1]
				individualTrafficSelector.StartPort = binary.BigEndian.Uint16(b[4:6])
				individualTrafficSelector.EndPort = binary.BigEndian.Uint16(b[6:8])

				individualTrafficSelector.StartAddress = append(individualTrafficSelector.StartAddress, b[8:12]...)
				individualTrafficSelector.EndAddress = append(individualTrafficSelector.EndAddress, b[12:16]...)

				trafficSelector.TrafficSelectors = append(trafficSelector.TrafficSelectors, individualTrafficSelector)

				b = b[16:]
			} else if trafficSelectorType == TS_IPV6_ADDR_RANGE {
				selectorLength := binary.BigEndian.Uint16(b[2:4])
				if selectorLength != 40 {
					return errors.Errorf("TrafficSelector: A TS_IPV6_ADDR_RANGE type traffic selector should has length 40 bytes")
				}
				if len(b) < int(selectorLength) {
					return errors.Errorf("TrafficSelector: No sufficient bytes to decode next individual traffic selector")
				}

				individualTrafficSelector := &IndividualTrafficSelector{}

				individualTrafficSelector.TSType = b[0]
				individualTrafficSelector.IPProtocolID = b[1]
				individualTrafficSelector.StartPort = binary.BigEndian.Uint16(b[4:6])
				individualTrafficSelector.EndPort = binary.BigEndian.Uint16(b[6:8])

				individualTrafficSelector.StartAddress = append(individualTrafficSelector.StartAddress, b[8:24]...)
				individualTrafficSelector.EndAddress = append(individualTrafficSelector.EndAddress, b[24:40]...)

				trafficSelector.TrafficSelectors = append(trafficSelector.TrafficSelectors, individualTrafficSelector)

				b = b[40:]
			} else {
				return errors.Errorf("TrafficSelector: Unsupported traffic selector type")
			}
		}
	}

	return nil
}

// Definition of Encrypted Payload

var _ IKEPayload = &Encrypted{}

type Encrypted struct {
	NextPayload   uint8
	EncryptedData []byte
}

func (encrypted *Encrypted) Type() IKEPayloadType { return TypeSK }

func (encrypted *Encrypted) marshal() ([]byte, error) {
	if len(encrypted.EncryptedData) == 0 {
		return nil, errors.Errorf("[Encrypted] The encrypted data is empty")
	}

	return encrypted.EncryptedData, nil
}

func (encrypted *Encrypted) unmarshal(b []byte) error {
	encrypted.EncryptedData = append(encrypted.EncryptedData, b...)
	return nil
}

// Definition of Configuration

var _ IKEPayload = &Configuration{}

type Configuration struct {
	ConfigurationType      uint8
	ConfigurationAttribute ConfigurationAttributeContainer
}

type ConfigurationAttributeContainer []*IndividualConfigurationAttribute

type IndividualConfigurationAttribute struct {
	Type  uint16
	Value []byte
}

func (configuration *Configuration) Type() IKEPayloadType { return TypeCP }

func (configuration *Configuration) marshal() ([]byte, error) {
	configurationData := make([]byte, 4)
	configurationData[0] = configuration.ConfigurationType

	for _, attribute := range configuration.ConfigurationAttribute {
		individualConfigurationAttributeData := make([]byte, 4)

		binary.BigEndian.PutUint16(individualConfigurationAttributeData[0:2], (attribute.Type & 0x7fff))
		binary.BigEndian.PutUint16(individualConfigurationAttributeData[2:4], uint16(len(attribute.Value)))

		individualConfigurationAttributeData = append(individualConfigurationAttributeData, attribute.Value...)

		configurationData = append(configurationData, individualConfigurationAttributeData...)
	}
	return configurationData, nil
}

func (configuration *Configuration) unmarshal(b []byte) error {
	if len(b) > 0 {
		// bounds checking
		if len(b) <= 4 {
			return errors.Errorf("Configuration: No sufficient bytes to decode next configuration")
		}
		configuration.ConfigurationType = b[0]

		configurationAttributeData := b[4:]

		for len(configurationAttributeData) > 0 {
			// bounds checking
			if len(configurationAttributeData) < 4 {
				return errors.Errorf("ConfigurationAttribute: No sufficient bytes to decode next configuration attribute")
			}
			length := binary.BigEndian.Uint16(configurationAttributeData[2:4])
			if len(configurationAttributeData) < int(4+length) {
				return errors.Errorf("ConfigurationAttribute: TLV attribute length error")
			}

			individualConfigurationAttribute := new(IndividualConfigurationAttribute)

			individualConfigurationAttribute.Type = binary.BigEndian.Uint16(configurationAttributeData[0:2])
			configurationAttributeData = configurationAttributeData[4:]
			individualConfigurationAttribute.Value = append(
				individualConfigurationAttribute.Value,
				configurationAttributeData[:length]...)
			configurationAttributeData = configurationAttributeData[length:]

			configuration.ConfigurationAttribute = append(configuration.ConfigurationAttribute, individualConfigurationAttribute)
		}
	}

	return nil
}

// Definition of IKE EAP

var _ IKEPayload = &EAP{}

type EAP struct {
	Code        uint8
	Identifier  uint8
	EAPTypeData EAPTypeDataContainer
}

func (eap *EAP) Type() IKEPayloadType { return TypeEAP }

func (eap *EAP) marshal() ([]byte, error) {
	eapData := make([]byte, 4)

	eapData[0] = eap.Code
	eapData[1] = eap.Identifier

	if len(eap.EAPTypeData) > 0 {
		eapTypeData, err := eap.EAPTypeData[0].marshal()
		if err != nil {
			return nil, errors.Errorf("EAP: EAP type data marshal failed: %+v", err)
		}

		eapData = append(eapData, eapTypeData...)
	}

	binary.BigEndian.PutUint16(eapData[2:4], uint16(len(eapData)))
	return eapData, nil
}

func (eap *EAP) unmarshal(b []byte) error {
	if len(b) > 0 {
		// bounds checking
		if len(b) < 4 {
			return errors.Errorf("EAP: No sufficient bytes to decode next EAP payload")
		}
		eapPayloadLength := binary.BigEndian.Uint16(b[2:4])
		if eapPayloadLength < 4 {
			return errors.Errorf("EAP: Payload length specified in the header is too small for EAP")
		}
		if len(b) != int(eapPayloadLength) {
			return errors.Errorf("EAP: Received payload length not matches the length specified in header")
		}

		eap.Code = b[0]
		eap.Identifier = b[1]

		// EAP Success or Failed
		if eapPayloadLength == 4 {
			return nil
		}

		eapType := b[4]
		var eapTypeData EAPTypeFormat

		switch EAPType(eapType) {
		case EAPTypeIdentity:
			eapTypeData = new(EAPIdentity)
		case EAPTypeNotification:
			eapTypeData = new(EAPNotification)
		case EAPTypeNak:
			eapTypeData = new(EAPNak)
		case EAPTypeExpanded:
			eapTypeData = new(EAPExpanded)
		default:
			// TODO: Create unsupprted type to handle it
			return errors.Errorf("EAP: Not supported EAP type")
		}

		if err := eapTypeData.unmarshal(b[4:]); err != nil {
			return errors.Errorf("EAP: Unamrshal EAP type data failed: %+v", err)
		}

		eap.EAPTypeData = append(eap.EAPTypeData, eapTypeData)
	}

	return nil
}

type EAPTypeDataContainer []EAPTypeFormat

type EAPTypeFormat interface {
	// Type specifies EAP types
	Type() EAPType

	// Called by EAP.marshal() or EAP.unmarshal()
	marshal() ([]byte, error)
	unmarshal(b []byte) error
}

// Definition of EAP Identity

var _ EAPTypeFormat = &EAPIdentity{}

type EAPIdentity struct {
	IdentityData []byte
}

func (eapIdentity *EAPIdentity) Type() EAPType { return EAPTypeIdentity }

func (eapIdentity *EAPIdentity) marshal() ([]byte, error) {
	if len(eapIdentity.IdentityData) == 0 {
		return nil, errors.Errorf("EAPIdentity: EAP identity is empty")
	}

	eapIdentityData := []byte{byte(EAPTypeIdentity)}
	eapIdentityData = append(eapIdentityData, eapIdentity.IdentityData...)
	return eapIdentityData, nil
}

func (eapIdentity *EAPIdentity) unmarshal(b []byte) error {
	if len(b) > 1 {
		eapIdentity.IdentityData = append(eapIdentity.IdentityData, b[1:]...)
	}
	return nil
}

// Definition of EAP Notification

var _ EAPTypeFormat = &EAPNotification{}

type EAPNotification struct {
	NotificationData []byte
}

func (eapNotification *EAPNotification) Type() EAPType { return EAPTypeNotification }

func (eapNotification *EAPNotification) marshal() ([]byte, error) {
	if len(eapNotification.NotificationData) == 0 {
		return nil, errors.Errorf("EAPNotification: EAP notification is empty")
	}

	eapNotificationData := []byte{byte(EAPTypeNotification)}
	eapNotificationData = append(eapNotificationData, eapNotification.NotificationData...)
	return eapNotificationData, nil
}

func (eapNotification *EAPNotification) unmarshal(b []byte) error {
	if len(b) > 1 {
		eapNotification.NotificationData = append(eapNotification.NotificationData, b[1:]...)
	}
	return nil
}

// Definition of EAP Nak

var _ EAPTypeFormat = &EAPNak{}

type EAPNak struct {
	NakData []byte
}

func (eapNak *EAPNak) Type() EAPType { return EAPTypeNak }

func (eapNak *EAPNak) marshal() ([]byte, error) {
	if len(eapNak.NakData) == 0 {
		return nil, errors.Errorf("EAPNak: EAP nak is empty")
	}

	eapNakData := []byte{byte(EAPTypeNak)}
	eapNakData = append(eapNakData, eapNak.NakData...)
	return eapNakData, nil
}

func (eapNak *EAPNak) unmarshal(b []byte) error {
	if len(b) > 1 {
		eapNak.NakData = append(eapNak.NakData, b[1:]...)
	}
	return nil
}

// Definition of EAP expanded

var _ EAPTypeFormat = &EAPExpanded{}

type EAPExpanded struct {
	VendorID   uint32
	VendorType uint32
	VendorData []byte
}

func (eapExpanded *EAPExpanded) Type() EAPType { return EAPTypeExpanded }

func (eapExpanded *EAPExpanded) marshal() ([]byte, error) {
	eapExpandedData := make([]byte, 8)

	vendorID := eapExpanded.VendorID & 0x00ffffff
	typeAndVendorID := (uint32(EAPTypeExpanded)<<24 | vendorID)

	binary.BigEndian.PutUint32(eapExpandedData[0:4], typeAndVendorID)
	binary.BigEndian.PutUint32(eapExpandedData[4:8], eapExpanded.VendorType)

	if len(eapExpanded.VendorData) == 0 {
		return eapExpandedData, nil
	}

	eapExpandedData = append(eapExpandedData, eapExpanded.VendorData...)
	return eapExpandedData, nil
}

func (eapExpanded *EAPExpanded) unmarshal(b []byte) error {
	if len(b) > 0 {
		if len(b) < 8 {
			return errors.Errorf("EAPExpanded: No sufficient bytes to decode the EAP expanded type")
		}

		typeAndVendorID := binary.BigEndian.Uint32(b[0:4])
		eapExpanded.VendorID = typeAndVendorID & 0x00ffffff

		eapExpanded.VendorType = binary.BigEndian.Uint32(b[4:8])

		if len(b) > 8 {
			eapExpanded.VendorData = append(eapExpanded.VendorData, b[8:]...)
		}
	}
	return nil
}
