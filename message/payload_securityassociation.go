package message

import (
	"encoding/binary"

	"github.com/pkg/errors"

	ike_types "github.com/free5gc/ike/types"
)

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

func (securityAssociation *SecurityAssociation) Type() ike_types.IkePayloadType {
	return ike_types.TypeSA
}

func (securityAssociation *SecurityAssociation) Marshal() ([]byte, error) {
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

		numberofSPI := len(proposal.SPI)
		if numberofSPI > 0xFF {
			return nil, errors.Errorf("Proposal: Too many SPI: %d", numberofSPI)
		}
		proposalData[6] = uint8(numberofSPI)
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

		transformListCount := len(transformList)
		if transformListCount > 0xFF {
			return nil, errors.Errorf("Transform: Too many transform: %d", transformListCount)
		}
		proposalData[7] = uint8(transformListCount)

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
					variableLen := len(transform.VariableLengthAttributeValue)
					if variableLen > 0xFFFF {
						return nil, errors.Errorf("VariableLengthAttributeValue length exceeds uint16 limit: %d", variableLen)
					}
					binary.BigEndian.PutUint16(attributeData[2:4], uint16(variableLen))
					attributeData = append(attributeData, transform.VariableLengthAttributeValue...)
				} else {
					// TV
					attributeFormatAndType := ((uint16(transform.AttributeFormat) & 0x1) << 15) | transform.AttributeType
					binary.BigEndian.PutUint16(attributeData[0:2], attributeFormatAndType)
					binary.BigEndian.PutUint16(attributeData[2:4], transform.AttributeValue)
				}

				transformData = append(transformData, attributeData...)
			}
			transformDataLen := len(transformData)
			if transformDataLen > 0xFFFF {
				return nil, errors.Errorf("Transform: transformData length exceeds uint16 limit: %d", transformDataLen)
			}
			binary.BigEndian.PutUint16(transformData[2:4], uint16(transformDataLen))

			proposalTransformData = append(proposalTransformData, transformData...)
		}

		proposalData = append(proposalData, proposalTransformData...)
		proposalDataLen := len(proposalData)
		if proposalDataLen > 0xFFFF {
			return nil, errors.Errorf("Proposal: proposalData length exceeds uint16 limit: %d", proposalDataLen)
		}
		binary.BigEndian.PutUint16(proposalData[2:4], uint16(proposalDataLen))

		securityAssociationData = append(securityAssociationData, proposalData...)
	}

	return securityAssociationData, nil
}

func (securityAssociation *SecurityAssociation) Unmarshal(b []byte) error {
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
			case ike_types.TypeEncryptionAlgorithm:
				proposal.EncryptionAlgorithm = append(proposal.EncryptionAlgorithm, transform)
			case ike_types.TypePseudorandomFunction:
				proposal.PseudorandomFunction = append(proposal.PseudorandomFunction, transform)
			case ike_types.TypeIntegrityAlgorithm:
				proposal.IntegrityAlgorithm = append(proposal.IntegrityAlgorithm, transform)
			case ike_types.TypeDiffieHellmanGroup:
				proposal.DiffieHellmanGroup = append(proposal.DiffieHellmanGroup, transform)
			case ike_types.TypeExtendedSequenceNumbers:
				proposal.ExtendedSequenceNumbers = append(proposal.ExtendedSequenceNumbers, transform)
			}

			transformData = transformData[transformLength:]
		}

		securityAssociation.Proposals = append(securityAssociation.Proposals, proposal)

		b = b[proposalLength:]
	}

	return nil
}
