package message

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	validSecurityAssociation = &SecurityAssociation{
		ProposalContainer{
			&Proposal{
				ProposalNumber: 1,
				ProtocolID:     1,
				SPI:            []byte{1, 2, 3},
				EncryptionAlgorithm: TransformContainer{
					&Transform{
						TransformType:    TypeEncryptionAlgorithm,
						TransformID:      ENCR_AES_CBC,
						AttributePresent: true,
						AttributeFormat:  AttributeFormatUseTV,
						AttributeType:    AttributeTypeKeyLength,
						AttributeValue:   256,
					},
					&Transform{
						TransformType:    TypeEncryptionAlgorithm,
						TransformID:      ENCR_AES_CBC,
						AttributePresent: true,
						AttributeFormat:  AttributeFormatUseTV,
						AttributeType:    AttributeTypeKeyLength,
						AttributeValue:   192,
					},
				},
				IntegrityAlgorithm: TransformContainer{
					&Transform{
						TransformType:    TypeIntegrityAlgorithm,
						TransformID:      AUTH_HMAC_MD5_96,
						AttributePresent: false,
						AttributeType:    0,
						AttributeValue:   0,
					},
					&Transform{
						TransformType:    TypeIntegrityAlgorithm,
						TransformID:      AUTH_HMAC_SHA1_96,
						AttributePresent: false,
						AttributeType:    0,
						AttributeValue:   0,
					},
				},
				DiffieHellmanGroup: TransformContainer{
					&Transform{
						TransformType:    TypeDiffieHellmanGroup,
						TransformID:      DH_1024_BIT_MODP,
						AttributePresent: false,
						AttributeType:    0,
						AttributeValue:   0,
					},
					&Transform{
						TransformType:    TypeDiffieHellmanGroup,
						TransformID:      DH_2048_BIT_MODP,
						AttributePresent: false,
						AttributeType:    0,
						AttributeValue:   0,
					},
				},
				PseudorandomFunction: TransformContainer{
					&Transform{
						TransformType:    TypePseudorandomFunction,
						TransformID:      PRF_HMAC_MD5,
						AttributePresent: false,
						AttributeType:    0,
						AttributeValue:   0,
					},
					&Transform{
						TransformType:    TypePseudorandomFunction,
						TransformID:      PRF_HMAC_SHA1,
						AttributePresent: false,
						AttributeType:    0,
						AttributeValue:   0,
					},
				},
				ExtendedSequenceNumbers: TransformContainer{
					&Transform{
						TransformType:    TypeExtendedSequenceNumbers,
						TransformID:      ESN_DISABLE,
						AttributePresent: false,
						AttributeType:    0,
						AttributeValue:   0,
					},
				},
			},
			&Proposal{
				ProposalNumber: 2,
				ProtocolID:     1,
				SPI:            []byte{1, 2, 3},
				EncryptionAlgorithm: TransformContainer{
					&Transform{
						TransformType:    TypeEncryptionAlgorithm,
						TransformID:      ENCR_AES_CBC,
						AttributePresent: true,
						AttributeFormat:  AttributeFormatUseTV,
						AttributeType:    AttributeTypeKeyLength,
						AttributeValue:   128,
					},
				},
				IntegrityAlgorithm: TransformContainer{
					&Transform{
						TransformType:    TypeIntegrityAlgorithm,
						TransformID:      AUTH_HMAC_SHA2_256_128,
						AttributePresent: false,
						AttributeType:    0,
						AttributeValue:   0,
					},
				},
				DiffieHellmanGroup: TransformContainer{
					&Transform{
						TransformType:    TypeDiffieHellmanGroup,
						TransformID:      DH_1024_BIT_MODP,
						AttributePresent: false,
						AttributeType:    0,
						AttributeValue:   0,
					},
				},
				PseudorandomFunction: TransformContainer{
					&Transform{
						TransformType:    TypePseudorandomFunction,
						TransformID:      PRF_HMAC_SHA2_256,
						AttributePresent: false,
						AttributeType:    0,
						AttributeValue:   0,
					},
				},
				ExtendedSequenceNumbers: TransformContainer{
					&Transform{
						TransformType:    TypeExtendedSequenceNumbers,
						TransformID:      ESN_DISABLE,
						AttributePresent: false,
						AttributeType:    0,
						AttributeValue:   0,
					},
				},
			},
		},
	}

	validSecurityAssociationByte = []byte{
		0x02, 0x00, 0x00, 0x5b, 0x01, 0x01, 0x03, 0x09,
		0x01, 0x02, 0x03, 0x03, 0x00, 0x00, 0x0c, 0x01,
		0x00, 0x00, 0x0c, 0x80, 0x0e, 0x01, 0x00, 0x03,
		0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x0c, 0x80,
		0x0e, 0x00, 0xc0, 0x03, 0x00, 0x00, 0x08, 0x02,
		0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x08, 0x02,
		0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x08, 0x03,
		0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x08, 0x03,
		0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x08, 0x04,
		0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x08, 0x04,
		0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x08, 0x05,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x37, 0x02,
		0x01, 0x03, 0x05, 0x01, 0x02, 0x03, 0x03, 0x00,
		0x00, 0x0c, 0x01, 0x00, 0x00, 0x0c, 0x80, 0x0e,
		0x00, 0x80, 0x03, 0x00, 0x00, 0x08, 0x02, 0x00,
		0x00, 0x05, 0x03, 0x00, 0x00, 0x08, 0x03, 0x00,
		0x00, 0x0c, 0x03, 0x00, 0x00, 0x08, 0x04, 0x00,
		0x00, 0x02, 0x00, 0x00, 0x00, 0x08, 0x05, 0x00,
		0x00, 0x00,
	}
)

func TestSecurityAssociationMarshal(t *testing.T) {
	testcases := []struct {
		description         string
		securityAssociation *SecurityAssociation
		expErr              bool
		expMarshal          []byte
	}{
		{
			description: "One proposal doesn't have any transform",
			securityAssociation: &SecurityAssociation{
				ProposalContainer{
					&Proposal{
						ProposalNumber: 1,
						ProtocolID:     1,
						SPI:            []byte{1, 2, 3},
					},
				},
			},
			expErr: true,
		},
		{
			description: "Attribute of one transform not specified",
			securityAssociation: &SecurityAssociation{
				ProposalContainer{
					&Proposal{
						ProposalNumber: 1,
						ProtocolID:     1,
						SPI:            []byte{1, 2, 3},
						EncryptionAlgorithm: TransformContainer{
							&Transform{
								TransformType:    TypeEncryptionAlgorithm,
								TransformID:      ENCR_AES_CBC,
								AttributePresent: true,
								AttributeFormat:  0,
								AttributeType:    AttributeTypeKeyLength,
							},
						},
					},
				},
			},
			expErr: true,
		},
		{
			description:         "SecurityAssociation Marshal",
			securityAssociation: validSecurityAssociation,
			expMarshal:          validSecurityAssociationByte,
			expErr:              false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.securityAssociation.Marshal()
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, result)
			}
		})
	}
}

func TestSecurityAssociationUnmarshal(t *testing.T) {
	testcases := []struct {
		description string
		b           []byte
		expErr      bool
		expSA       *SecurityAssociation
	}{
		{
			description: "No sufficient bytes to decode next proposal",
			b:           []byte{0x01, 0x02, 0x03, 0x04},
			expErr:      true,
		},
		{
			description: "Illegal payload length",
			b:           []byte{0x01, 0x02, 0x00, 0x04, 0x05, 0x06, 0x07, 0x08},
			expErr:      true,
		},
		{
			description: "The length of received message not matchs the length specified in header",
			b:           []byte{0x01, 0x02, 0x00, 0x09, 0x05, 0x06, 0x07, 0x08},
			expErr:      true,
		},
		{
			description: "No sufficient bytes for unmarshalling SPI of proposal",
			b: []byte{
				0x01, 0x02, 0x00, 0x09, 0x05, 0x06, 0x07, 0x08,
				0x01, 0x02,
			},
			expErr: true,
		},
		{
			description: "Illegal attribute length",
			b: []byte{
				0x00, 0x00, 0x00, 0x18, 0x02, 0x01, 0x03, 0x01,
				0x01, 0x01, 0x05, 0x00, 0x00, 0x00, 0x0d, 0x03,
				0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x05, 0x01,
			},
			expErr: true,
		},
		{
			description: "SecurityAssociation Unmarshal",
			b:           validSecurityAssociationByte,
			expSA:       validSecurityAssociation,
			expErr:      false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var sa SecurityAssociation
			err := sa.Unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, *tc.expSA, sa)
			}
		})
	}
}
