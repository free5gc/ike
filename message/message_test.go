package message

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	Crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	Mrand "math/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestEncodeDecode tests the Encode() and Decode() function using the data
// build manually.
// First, build each payload with correct value, then the IKE message for
// IKE_SA_INIT type.
// Second, encode/decode the IKE message using Encode/Decode function, and then
// re-encode the decoded message again.
// Third, send the encoded data to the UDP connection for verification with Wireshark.
// Compare the dataFirstEncode and dataSecondEncode and return the result.
func TestEncodeDecode(t *testing.T) {
	conn, err := net.Dial("udp", "127.0.0.1:500")
	if err != nil {
		t.Fatalf("udp Dial failed: %+v", err)
	}
	testPacket := &IKEMessage{}

	// random an SPI
	src := Mrand.NewSource(63579)
	localRand := Mrand.New(src)
	ispi := localRand.Uint64()

	testPacket.InitiatorSPI = ispi
	testPacket.MajorVersion = 2
	testPacket.MinorVersion = 0
	testPacket.ExchangeType = 34 // IKE_SA_INIT
	testPacket.Flags = 16        // flagI is set
	testPacket.MessageID = 0     // for IKE_SA_INIT

	testSA := &SecurityAssociation{}

	testProposal1 := &Proposal{}
	testProposal1.ProposalNumber = 1 // first
	testProposal1.ProtocolID = 1     // IKE

	testtransform1 := &Transform{}
	testtransform1.TransformType = 1 // ENCR
	testtransform1.TransformID = 12  // ENCR_AES_CBC
	testtransform1.AttributePresent = true
	testtransform1.AttributeFormat = 1
	testtransform1.AttributeType = 14
	testtransform1.AttributeValue = 128

	testProposal1.EncryptionAlgorithm = append(testProposal1.EncryptionAlgorithm, testtransform1)

	testtransform2 := &Transform{}
	testtransform2.TransformType = 1 // ENCR
	testtransform2.TransformID = 12  // ENCR_AES_CBC
	testtransform2.AttributePresent = true
	testtransform2.AttributeFormat = 1
	testtransform2.AttributeType = 14
	testtransform2.AttributeValue = 192

	testProposal1.EncryptionAlgorithm = append(testProposal1.EncryptionAlgorithm, testtransform2)

	testtransform3 := &Transform{}
	testtransform3.TransformType = 3 // INTEG
	testtransform3.TransformID = 5   // AUTH_AES_XCBC_96
	testtransform3.AttributePresent = false

	testProposal1.IntegrityAlgorithm = append(testProposal1.IntegrityAlgorithm, testtransform3)

	testtransform4 := &Transform{}
	testtransform4.TransformType = 3 // INTEG
	testtransform4.TransformID = 2   // AUTH_HMAC_SHA1_96
	testtransform4.AttributePresent = false

	testProposal1.IntegrityAlgorithm = append(testProposal1.IntegrityAlgorithm, testtransform4)

	testSA.Proposals = append(testSA.Proposals, testProposal1)

	testProposal2 := &Proposal{}
	testProposal2.ProposalNumber = 2 // second
	testProposal2.ProtocolID = 1     // IKE

	testtransform1 = &Transform{}
	testtransform1.TransformType = 1 // ENCR
	testtransform1.TransformID = 12  // ENCR_AES_CBC
	testtransform1.AttributePresent = true
	testtransform1.AttributeFormat = 1
	testtransform1.AttributeType = 14
	testtransform1.AttributeValue = 128

	testProposal2.EncryptionAlgorithm = append(testProposal2.EncryptionAlgorithm, testtransform1)

	testtransform2 = &Transform{}
	testtransform2.TransformType = 1 // ENCR
	testtransform2.TransformID = 12  // ENCR_AES_CBC
	testtransform2.AttributePresent = true
	testtransform2.AttributeFormat = 1
	testtransform2.AttributeType = 14
	testtransform2.AttributeValue = 192

	testProposal2.EncryptionAlgorithm = append(testProposal2.EncryptionAlgorithm, testtransform2)

	testtransform3 = &Transform{}
	testtransform3.TransformType = 3 // INTEG
	testtransform3.TransformID = 1   // AUTH_HMAC_MD5_96
	testtransform3.AttributePresent = false

	testProposal2.IntegrityAlgorithm = append(testProposal2.IntegrityAlgorithm, testtransform3)

	testtransform4 = &Transform{}
	testtransform4.TransformType = 3 // INTEG
	testtransform4.TransformID = 2   // AUTH_HMAC_SHA1_96
	testtransform4.AttributePresent = false

	testProposal2.IntegrityAlgorithm = append(testProposal2.IntegrityAlgorithm, testtransform4)

	testSA.Proposals = append(testSA.Proposals, testProposal2)

	testPacket.Payloads = append(testPacket.Payloads, testSA)

	testKE := &KeyExchange{}

	testKE.DiffieHellmanGroup = 1
	for i := 0; i < 8; i++ {
		partKeyExchangeData := make([]byte, 8)
		binary.BigEndian.PutUint64(partKeyExchangeData, 7482105748278537214)
		testKE.KeyExchangeData = append(testKE.KeyExchangeData, partKeyExchangeData...)
	}

	testPacket.Payloads = append(testPacket.Payloads, testKE)

	testIDr := &IdentificationResponder{}

	testIDr.IDType = 3
	for i := 0; i < 8; i++ {
		partIdentification := make([]byte, 8)
		binary.BigEndian.PutUint64(partIdentification, 4378215321473912643)
		testIDr.IDData = append(testIDr.IDData, partIdentification...)
	}

	testPacket.Payloads = append(testPacket.Payloads, testIDr)

	testCert := &Certificate{}

	testCert.CertificateEncoding = 1
	for i := 0; i < 8; i++ {
		partCertificate := make([]byte, 8)
		binary.BigEndian.PutUint64(partCertificate, 4378217432157543265)
		testCert.CertificateData = append(testCert.CertificateData, partCertificate...)
	}

	testPacket.Payloads = append(testPacket.Payloads, testCert)

	testCertReq := &CertificateRequest{}

	testCertReq.CertificateEncoding = 1
	for i := 0; i < 8; i++ {
		partCertificateRquest := make([]byte, 8)
		binary.BigEndian.PutUint64(partCertificateRquest, 7438274381754372584)
		testCertReq.CertificationAuthority = append(testCertReq.CertificationAuthority, partCertificateRquest...)
	}

	testPacket.Payloads = append(testPacket.Payloads, testCertReq)

	testAuth := &Authentication{}

	testAuth.AuthenticationMethod = 1
	for i := 0; i < 8; i++ {
		partAuthentication := make([]byte, 8)
		binary.BigEndian.PutUint64(partAuthentication, 4632714362816473824)
		testAuth.AuthenticationData = append(testAuth.AuthenticationData, partAuthentication...)
	}

	testPacket.Payloads = append(testPacket.Payloads, testAuth)

	testNonce := &Nonce{}

	for i := 0; i < 8; i++ {
		partNonce := make([]byte, 8)
		binary.BigEndian.PutUint64(partNonce, 8984327463782167381)
		testNonce.NonceData = append(testNonce.NonceData, partNonce...)
	}

	testPacket.Payloads = append(testPacket.Payloads, testNonce)

	testNotification := &Notification{}

	testNotification.ProtocolID = 1
	testNotification.NotifyMessageType = 2

	for i := 0; i < 5; i++ {
		partSPI := make([]byte, 8)
		binary.BigEndian.PutUint64(partSPI, 4372847328749832794)
		testNotification.SPI = append(testNotification.SPI, partSPI...)
	}

	for i := 0; i < 19; i++ {
		partNotification := make([]byte, 8)
		binary.BigEndian.PutUint64(partNotification, 9721437148392747354)
		testNotification.NotificationData = append(testNotification.NotificationData, partNotification...)
	}

	testPacket.Payloads = append(testPacket.Payloads, testNotification)

	testDelete := &Delete{}

	testDelete.ProtocolID = 1
	testDelete.SPISize = 9
	testDelete.NumberOfSPI = 4

	for i := 0; i < 36; i++ {
		testDelete.SPIs = append(testDelete.SPIs, 87)
	}

	testPacket.Payloads = append(testPacket.Payloads, testDelete)

	testVendor := &VendorID{}

	for i := 0; i < 5; i++ {
		partVendorData := make([]byte, 8)
		binary.BigEndian.PutUint64(partVendorData, 5421487329873941748)
		testVendor.VendorIDData = append(testVendor.VendorIDData, partVendorData...)
	}

	testPacket.Payloads = append(testPacket.Payloads, testVendor)

	testTSi := &TrafficSelectorResponder{}

	testIndividualTS := &IndividualTrafficSelector{}

	testIndividualTS.TSType = 7
	testIndividualTS.IPProtocolID = 6
	testIndividualTS.StartPort = 1989
	testIndividualTS.EndPort = 2020

	testIndividualTS.StartAddress = []byte{192, 168, 0, 15}
	testIndividualTS.EndAddress = []byte{192, 168, 0, 192}

	testTSi.TrafficSelectors = append(testTSi.TrafficSelectors, testIndividualTS)

	testIndividualTS = &IndividualTrafficSelector{}

	testIndividualTS.TSType = 8
	testIndividualTS.IPProtocolID = 6
	testIndividualTS.StartPort = 2010
	testIndividualTS.EndPort = 2050

	testIndividualTS.StartAddress = net.ParseIP("2001:db8::68")
	testIndividualTS.EndAddress = net.ParseIP("2001:db8::72")

	testTSi.TrafficSelectors = append(testTSi.TrafficSelectors, testIndividualTS)

	testPacket.Payloads = append(testPacket.Payloads, testTSi)

	testCP := new(Configuration)

	testCP.ConfigurationType = 1

	testIndividualConfigurationAttribute := new(IndividualConfigurationAttribute)

	testIndividualConfigurationAttribute.Type = 1
	testIndividualConfigurationAttribute.Value = []byte{10, 1, 14, 1}

	testCP.ConfigurationAttribute = append(testCP.ConfigurationAttribute, testIndividualConfigurationAttribute)

	testPacket.Payloads = append(testPacket.Payloads, testCP)

	testEAP := new(EAP)

	testEAP.Code = 1
	testEAP.Identifier = 123

	// testEAPExpanded := &EAPExpanded{
	// 	VendorID:   26838,
	// 	VendorType: 1,
	// 	VendorData: []byte{9, 4, 8, 7},
	// }

	testEAPNotification := new(EAPNotification)

	rawstr := "I'm tired"
	testEAPNotification.NotificationData = []byte(rawstr)

	testEAP.EAPTypeData = append(testEAP.EAPTypeData, testEAPNotification)

	testPacket.Payloads = append(testPacket.Payloads, testEAP)

	testSK := new(Encrypted)

	testSK.NextPayload = uint8(TypeSA)

	ikePayload := IKEPayloadContainer{
		testSA,
		testAuth,
	}

	ikePayloadDataForSK, retErr := ikePayload.Encode()
	if retErr != nil {
		t.Fatalf("EncodePayload failed: %+v", retErr)
	}

	// aes 128 key
	key, retErr := hex.DecodeString("6368616e676520746869732070617373")
	if retErr != nil {
		t.Fatalf("HexDecoding failed: %+v", retErr)
	}
	block, retErr := aes.NewCipher(key)
	if retErr != nil {
		t.Fatalf("AES NewCipher failed: %+v", retErr)
	}

	// padding plaintext
	padNum := len(ikePayloadDataForSK) % aes.BlockSize
	for i := 0; i < (aes.BlockSize - padNum); i++ {
		ikePayloadDataForSK = append(ikePayloadDataForSK, byte(padNum))
	}

	// ciphertext
	cipherText := make([]byte, aes.BlockSize+len(ikePayloadDataForSK))
	iv := cipherText[:aes.BlockSize]
	_, err = io.ReadFull(Crand.Reader, iv)
	if err != nil {
		t.Fatalf("IO ReadFull failed: %+v", err)
	}

	// CBC mode
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], ikePayloadDataForSK)

	testSK.EncryptedData = cipherText

	testPacket.Payloads = append(testPacket.Payloads, testSK)

	var dataFirstEncode, dataSecondEncode []byte
	decodedPacket := new(IKEMessage)

	if dataFirstEncode, err = testPacket.Encode(); err != nil {
		t.Fatalf("Encode failed: %+v", err)
	}

	t.Logf("%+v", dataFirstEncode)

	if err = decodedPacket.Decode(dataFirstEncode); err != nil {
		t.Fatalf("Decode failed: %+v", err)
	}

	if dataSecondEncode, err = decodedPacket.Encode(); err != nil {
		t.Fatalf("Encode failed: %+v", err)
	}

	t.Logf("Original IKE Message: %+v", dataFirstEncode)
	t.Logf("Result IKE Message:   %+v", dataSecondEncode)

	_, err = conn.Write(dataFirstEncode)
	if err != nil {
		t.Fatalf("Error: %+v", err)
	}

	if !bytes.Equal(dataFirstEncode, dataSecondEncode) {
		t.FailNow()
	}
}

// TestEncodeDecodeUsingPublicData tests the Encode() and Decode() function
// using the public data.
// Decode and encode the data, and compare the verifyData and the origin
// data and return the result.
func TestEncodeDecodeUsingPublicData(t *testing.T) {
	data := []byte{
		0x86, 0x43, 0x30, 0xac, 0x30, 0xe6, 0x56, 0x4d, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x20, 0x22, 0x08, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc9, 0x22, 0x00, 0x00,
		0x30, 0x00, 0x00, 0x00, 0x2c, 0x01, 0x01, 0x00, 0x04, 0x03, 0x00,
		0x00, 0x0c, 0x01, 0x00, 0x00, 0x0c, 0x80, 0x0e, 0x00, 0x80,
		0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00,
		0x08, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08, 0x04,
		0x00, 0x00, 0x02, 0x28, 0x00, 0x00, 0x88, 0x00, 0x02, 0x00, 0x00,
		0x03, 0xdc, 0xf5, 0x9a, 0x29, 0x05, 0x7b, 0x5a, 0x49, 0xbd,
		0x55, 0x8c, 0x9b, 0x14, 0x7a, 0x11, 0x0e, 0xed, 0xff, 0xe5, 0xea,
		0x2d, 0x12, 0xc2, 0x1e, 0x5c, 0x7a, 0x5f, 0x5e, 0x9c, 0x99,
		0xe3, 0xd1, 0xd3, 0x00, 0x24, 0x3c, 0x89, 0x73, 0x1e, 0x6c, 0x6d,
		0x63, 0x41, 0x7b, 0x33, 0xfa, 0xaf, 0x5a, 0xc7, 0x26, 0xe8,
		0xb6, 0xf8, 0xc3, 0xb5, 0x2a, 0x14, 0xeb, 0xec, 0xd5, 0x6f, 0x1b,
		0xd9, 0x5b, 0x28, 0x32, 0x84, 0x9e, 0x26, 0xfc, 0x59, 0xee,
		0xf1, 0x4e, 0x38, 0x5f, 0x55, 0xc2, 0x1b, 0xe8, 0xf6, 0xa3, 0xfb,
		0xc5, 0x55, 0xd7, 0x35, 0x92, 0x86, 0x24, 0x00, 0x62, 0x8b,
		0xea, 0xce, 0x23, 0xf0, 0x47, 0xaf, 0xaa, 0xf8, 0x61, 0xe4, 0x5c,
		0x42, 0xba, 0x5c, 0xa1, 0x4a, 0x52, 0x6e, 0xd8, 0xe8, 0xf1,
		0xb9, 0x74, 0xae, 0xe4, 0xd1, 0x9c, 0x9f, 0xa5, 0x9b, 0xf0, 0xd7,
		0xdb, 0x55, 0x2b, 0x00, 0x00, 0x44, 0x4c, 0xa7, 0xf3, 0x9b,
		0xcd, 0x1d, 0xc2, 0x01, 0x79, 0xfa, 0xa2, 0xe4, 0x72, 0xe0, 0x61,
		0xc4, 0x45, 0x61, 0xe6, 0x49, 0x2d, 0xb3, 0x96, 0xae, 0xc9,
		0x2c, 0xdb, 0x54, 0x21, 0xf4, 0x98, 0x4f, 0x72, 0xd2, 0x43, 0x78,
		0xab, 0x80, 0xe4, 0x6c, 0x01, 0x78, 0x6a, 0xc4, 0x64, 0x45,
		0xbc, 0xa8, 0x1f, 0x56, 0xbc, 0xed, 0xf9, 0xb5, 0xd8, 0x21, 0x95,
		0x41, 0x71, 0xe9, 0x0e, 0xb4, 0x3c, 0x4e, 0x2b, 0x00, 0x00,
		0x17, 0x43, 0x49, 0x53, 0x43, 0x4f, 0x2d, 0x44, 0x45, 0x4c, 0x45,
		0x54, 0x45, 0x2d, 0x52, 0x45, 0x41, 0x53, 0x4f, 0x4e, 0x2b,
		0x00, 0x00, 0x3b, 0x43, 0x49, 0x53, 0x43, 0x4f, 0x28, 0x43, 0x4f,
		0x50, 0x59, 0x52, 0x49, 0x47, 0x48, 0x54, 0x29, 0x26, 0x43,
		0x6f, 0x70, 0x79, 0x72, 0x69, 0x67, 0x68, 0x74, 0x20, 0x28, 0x63,
		0x29, 0x20, 0x32, 0x30, 0x30, 0x39, 0x20, 0x43, 0x69, 0x73,
		0x63, 0x6f, 0x20, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x73, 0x2c,
		0x20, 0x49, 0x6e, 0x63, 0x2e, 0x29, 0x00, 0x00, 0x13, 0x43,
		0x49, 0x53, 0x43, 0x4f, 0x2d, 0x47, 0x52, 0x45, 0x2d, 0x4d, 0x4f,
		0x44, 0x45, 0x02, 0x29, 0x00, 0x00, 0x1c, 0x01, 0x00, 0x40,
		0x04, 0x7e, 0x57, 0x6c, 0xc0, 0x13, 0xd4, 0x05, 0x43, 0xa2, 0xe8,
		0x77, 0x7d, 0x00, 0x34, 0x68, 0xa5, 0xb1, 0x89, 0x0c, 0x58,
		0x2b, 0x00, 0x00, 0x1c, 0x01, 0x00, 0x40, 0x05, 0x52, 0x64, 0x4d,
		0x87, 0xd4, 0x7c, 0x2d, 0x44, 0x23, 0xbd, 0x37, 0xe4, 0x48,
		0xa9, 0xf5, 0x17, 0x01, 0x81, 0xcb, 0x8a, 0x00, 0x00, 0x00, 0x14,
		0x40, 0x48, 0xb7, 0xd5, 0x6e, 0xbc, 0xe8, 0x85, 0x25, 0xe7,
		0xde, 0x7f, 0x00, 0xd6, 0xc2, 0xd3,
	}

	ikeMsg := new(IKEMessage)
	err := ikeMsg.Decode(data)
	if err != nil {
		t.Fatalf("Decode failed: %+v", err)
	}

	verifyData, err := ikeMsg.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %+v", err)
	}

	if !bytes.Equal(data, verifyData) {
		t.FailNow()
	}
}

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
			description: "Valid SecurityAssociation",
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
			},
			expErr: false,
			expMarshal: []byte{
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
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.securityAssociation.marshal()
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
			description: "Vaild SecurityAssociation",
			b: []byte{
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
			},
			expErr: false,
			expSA: &SecurityAssociation{
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
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var sa SecurityAssociation
			err := sa.unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, *tc.expSA, sa)
			}
		})
	}
}

func TestKeyExchangeMarshal(t *testing.T) {
	testcases := []struct {
		description string
		keyExchange KeyExchange
		expMarshal  []byte
	}{
		{
			description: "1024 bit MODP group",
			keyExchange: KeyExchange{
				DiffieHellmanGroup: DH_1024_BIT_MODP,
				KeyExchangeData: []byte{
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				},
			},
			expMarshal: []byte{
				0x00, 0x02, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
				0x05, 0x06, 0x07, 0x08,
			},
		},
		{
			description: "2048 bit MODP group",
			keyExchange: KeyExchange{
				DiffieHellmanGroup: DH_2048_BIT_MODP,
				KeyExchangeData: []byte{
					0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
				},
			},
			expMarshal: []byte{
				0x00, 0x0e, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44,
				0x55, 0x66, 0x77, 0x88,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.keyExchange.marshal()
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, result)
		})
	}
}

func TestKeyExchangeUnmarshal(t *testing.T) {
	testcases := []struct {
		description string
		b           []byte
		expErr      bool
		expKE       KeyExchange
	}{
		{
			description: "No sufficient bytes to decode next key exchange data",
			b: []byte{
				0x01, 0x02, 0x03,
			},
			expErr: true,
		},
		{
			description: "Valid Data1",
			b: []byte{
				0x00, 0x02, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
				0x05, 0x06, 0x07, 0x08,
			},
			expErr: false,
			expKE: KeyExchange{
				DiffieHellmanGroup: DH_1024_BIT_MODP,
				KeyExchangeData: []byte{
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				},
			},
		},
		{
			description: "Valid Data2",
			b: []byte{
				0x00, 0x0e, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44,
				0x55, 0x66, 0x77, 0x88,
			},
			expErr: false,
			expKE: KeyExchange{
				DiffieHellmanGroup: DH_2048_BIT_MODP,
				KeyExchangeData: []byte{
					0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var ke KeyExchange
			err := ke.unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expKE, ke)
			}
		})
	}
}

func TestIdentificationInitiator(t *testing.T) {
	testcasesMarshal := []struct {
		description string
		id          IdentificationInitiator
		expMarshal  []byte
	}{
		{
			description: "Identification marshal",
			id: IdentificationInitiator{
				IDType: ID_KEY_ID,
				IDData: []byte{
					0x55, 0x45,
				},
			},
			expMarshal: []byte{
				0xb, 0x0, 0x0, 0x0, 0x55, 0x45,
			},
		},
	}

	for _, tc := range testcasesMarshal {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.id.marshal()
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, result)
		})
	}

	testcasesUnmarshal := []struct {
		description string
		b           []byte
		expErr      bool
		expMarshal  IdentificationInitiator
	}{
		{
			description: "No sufficient bytes to decode next identification",
			b: []byte{
				0x01, 0x02, 0x03,
			},
			expErr: true,
		},
		{
			description: "Identification Unmarshal",
			b: []byte{
				0xb, 0x0, 0x0, 0x0, 0x55, 0x45,
			},
			expMarshal: IdentificationInitiator{
				IDType: ID_KEY_ID,
				IDData: []byte{
					0x55, 0x45,
				},
			},
		},
	}

	for _, tc := range testcasesUnmarshal {
		t.Run(tc.description, func(t *testing.T) {
			var id IdentificationInitiator
			err := id.unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, id)
			}
		})
	}
}

func TestIdentificationResponder(t *testing.T) {
	testcasesMarshal := []struct {
		description string
		id          IdentificationResponder
		expMarshal  []byte
	}{
		{
			description: "Identification marshal",
			id: IdentificationResponder{
				IDType: ID_KEY_ID,
				IDData: []byte{
					0x55, 0x45,
				},
			},
			expMarshal: []byte{
				0xb, 0x0, 0x0, 0x0, 0x55, 0x45,
			},
		},
	}

	for _, tc := range testcasesMarshal {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.id.marshal()
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, result)
		})
	}

	testcasesUnmarshal := []struct {
		description string
		b           []byte
		expErr      bool
		expMarshal  IdentificationResponder
	}{
		{
			description: "No sufficient bytes to decode next identification",
			b: []byte{
				0x01, 0x02, 0x03,
			},
			expErr: true,
		},
		{
			description: "Identification Unmarshal",
			b: []byte{
				0xb, 0x0, 0x0, 0x0, 0x55, 0x45,
			},
			expMarshal: IdentificationResponder{
				IDType: ID_KEY_ID,
				IDData: []byte{
					0x55, 0x45,
				},
			},
		},
	}

	for _, tc := range testcasesUnmarshal {
		t.Run(tc.description, func(t *testing.T) {
			var id IdentificationResponder
			err := id.unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, id)
			}
		})
	}
}

func TestCertificate(t *testing.T) {
	testcasesMarshal := []struct {
		description string
		crt         Certificate
		expMarshal  []byte
	}{
		{
			description: "Certificate marshal",
			crt: Certificate{
				CertificateEncoding: ID_FQDN,
				CertificateData: []byte{
					0x6e, 0x33, 0x69, 0x77, 0x66, 0x2e, 0x73, 0x61,
					0x76, 0x69, 0x61, 0x68, 0x35, 0x67, 0x63, 0x2e,
					0x6f, 0x72, 0x67,
				},
			},
			expMarshal: []byte{
				0x02, 0x6e, 0x33, 0x69, 0x77, 0x66, 0x2e, 0x73,
				0x61, 0x76, 0x69, 0x61, 0x68, 0x35, 0x67, 0x63,
				0x2e, 0x6f, 0x72, 0x67,
			},
		},
	}

	for _, tc := range testcasesMarshal {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.crt.marshal()
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, result)
		})
	}

	testcasesUnmarshal := []struct {
		description string
		b           []byte
		expErr      bool
		expMarshal  Certificate
	}{
		{
			description: "No sufficient bytes to decode next certificate",
			b: []byte{
				0x01,
			},
			expErr: true,
		},
		{
			description: "Certificate Unmarshal",
			b: []byte{
				0x02, 0x6e, 0x33, 0x69, 0x77, 0x66, 0x2e, 0x73,
				0x61, 0x76, 0x69, 0x61, 0x68, 0x35, 0x67, 0x63,
				0x2e, 0x6f, 0x72, 0x67,
			},
			expMarshal: Certificate{
				CertificateEncoding: ID_FQDN,
				CertificateData: []byte{
					0x6e, 0x33, 0x69, 0x77, 0x66, 0x2e, 0x73, 0x61,
					0x76, 0x69, 0x61, 0x68, 0x35, 0x67, 0x63, 0x2e,
					0x6f, 0x72, 0x67,
				},
			},
		},
	}

	for _, tc := range testcasesUnmarshal {
		t.Run(tc.description, func(t *testing.T) {
			var crt Certificate
			err := crt.unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, crt)
			}
		})
	}
}

func TestCertificateRequest(t *testing.T) {
	testcasesMarshal := []struct {
		description string
		crt         CertificateRequest
		expMarshal  []byte
	}{
		{
			description: "CertificateRequest marshal",
			crt: CertificateRequest{
				CertificateEncoding: ID_FQDN,
				CertificationAuthority: []byte{
					0x6e, 0x33, 0x69, 0x77, 0x66, 0x2e, 0x73, 0x61,
					0x76, 0x69, 0x61, 0x68, 0x35, 0x67, 0x63, 0x2e,
					0x6f, 0x72, 0x67,
				},
			},
			expMarshal: []byte{
				0x02, 0x6e, 0x33, 0x69, 0x77, 0x66, 0x2e, 0x73,
				0x61, 0x76, 0x69, 0x61, 0x68, 0x35, 0x67, 0x63,
				0x2e, 0x6f, 0x72, 0x67,
			},
		},
	}

	for _, tc := range testcasesMarshal {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.crt.marshal()
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, result)
		})
	}

	testcasesUnmarshal := []struct {
		description string
		b           []byte
		expErr      bool
		expMarshal  CertificateRequest
	}{
		{
			description: "No sufficient bytes to decode next certificate request",
			b: []byte{
				0x01,
			},
			expErr: true,
		},
		{
			description: "CertificateRequest Unmarshal",
			b: []byte{
				0x02, 0x6e, 0x33, 0x69, 0x77, 0x66, 0x2e, 0x73,
				0x61, 0x76, 0x69, 0x61, 0x68, 0x35, 0x67, 0x63,
				0x2e, 0x6f, 0x72, 0x67,
			},
			expMarshal: CertificateRequest{
				CertificateEncoding: ID_FQDN,
				CertificationAuthority: []byte{
					0x6e, 0x33, 0x69, 0x77, 0x66, 0x2e, 0x73, 0x61,
					0x76, 0x69, 0x61, 0x68, 0x35, 0x67, 0x63, 0x2e,
					0x6f, 0x72, 0x67,
				},
			},
		},
	}

	for _, tc := range testcasesUnmarshal {
		t.Run(tc.description, func(t *testing.T) {
			var crt CertificateRequest
			err := crt.unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, crt)
			}
		})
	}
}

func TestAuthentication(t *testing.T) {
	testcasesMarshal := []struct {
		description    string
		authentication Authentication
		expMarshal     []byte
	}{
		{
			description: "Authentication marshal",
			authentication: Authentication{
				AuthenticationMethod: SharedKeyMesageIntegrityCode,
				AuthenticationData: []byte{
					0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
					0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
					0xb8, 0x56, 0x81, 0x8a,
				},
			},
			expMarshal: []byte{
				0x02, 0x00, 0x00, 0x00, 0x7d, 0x09, 0x18, 0x42,
				0x60, 0x9c, 0x9e, 0x20, 0x56, 0x9f, 0xc0, 0x39,
				0xda, 0x3f, 0x22, 0x2a, 0xb8, 0x56, 0x81, 0x8a,
			},
		},
	}

	for _, tc := range testcasesMarshal {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.authentication.marshal()
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, result)
		})
	}

	testcasesUnmarshal := []struct {
		description string
		b           []byte
		expErr      bool
		expMarshal  Authentication
	}{
		{
			description: "No sufficient bytes to decode next Authentication",
			b: []byte{
				0x01, 0x02, 0x03,
			},
			expErr: true,
		},
		{
			description: "Authentication Unmarshal",
			b: []byte{
				0x02, 0x00, 0x00, 0x00, 0x7d, 0x09, 0x18, 0x42,
				0x60, 0x9c, 0x9e, 0x20, 0x56, 0x9f, 0xc0, 0x39,
				0xda, 0x3f, 0x22, 0x2a, 0xb8, 0x56, 0x81, 0x8a,
			},
			expMarshal: Authentication{
				AuthenticationMethod: SharedKeyMesageIntegrityCode,
				AuthenticationData: []byte{
					0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
					0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
					0xb8, 0x56, 0x81, 0x8a,
				},
			},
		},
	}

	for _, tc := range testcasesUnmarshal {
		t.Run(tc.description, func(t *testing.T) {
			var authentication Authentication
			err := authentication.unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, authentication)
			}
		})
	}
}

func TestNonce(t *testing.T) {
	testcasesMarshal := []struct {
		description string
		nonce       Nonce
		expMarshal  []byte
	}{
		{
			description: "Nonce marshal",
			nonce: Nonce{
				NonceData: []byte{
					0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
					0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
					0xb8, 0x56, 0x81, 0x8a,
				},
			},
			expMarshal: []byte{
				0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
				0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
				0xb8, 0x56, 0x81, 0x8a,
			},
		},
	}

	for _, tc := range testcasesMarshal {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.nonce.marshal()
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, result)
		})
	}

	testcasesUnmarshal := []struct {
		description string
		b           []byte
		expErr      bool
		expMarshal  Nonce
	}{
		{
			description: "Nonce Unmarshal",
			b: []byte{
				0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
				0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
				0xb8, 0x56, 0x81, 0x8a,
			},
			expMarshal: Nonce{
				NonceData: []byte{
					0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
					0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
					0xb8, 0x56, 0x81, 0x8a,
				},
			},
		},
	}

	for _, tc := range testcasesUnmarshal {
		t.Run(tc.description, func(t *testing.T) {
			var nonce Nonce
			err := nonce.unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, nonce)
			}
		})
	}
}

func TestNotification(t *testing.T) {
	testcasesMarshal := []struct {
		description  string
		notification Notification
		expMarshal   []byte
	}{
		{
			description: "Notification marshal",
			notification: Notification{
				ProtocolID:        TypeNone,
				NotifyMessageType: NAT_DETECTION_SOURCE_IP,
				SPI:               []byte{0x01, 0x02, 0x03},
				NotificationData: []byte{
					0x50, 0xc4, 0xc2, 0xbe, 0x8e, 0x3f, 0xd9, 0x16,
					0x19, 0x24, 0x65, 0x0d, 0x14, 0x5d, 0x4f, 0xf6,
					0x46, 0xd8, 0x9d, 0x75,
				},
			},
			expMarshal: []byte{
				0x00, 0x03, 0x40, 0x04, 0x01, 0x02, 0x03, 0x50,
				0xc4, 0xc2, 0xbe, 0x8e, 0x3f, 0xd9, 0x16, 0x19,
				0x24, 0x65, 0x0d, 0x14, 0x5d, 0x4f, 0xf6, 0x46,
				0xd8, 0x9d, 0x75,
			},
		},
	}

	for _, tc := range testcasesMarshal {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.notification.marshal()
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, result)
		})
	}

	testcasesUnmarshal := []struct {
		description string
		b           []byte
		expErr      bool
		expMarshal  Notification
	}{
		{
			description: "No sufficient bytes to decode next notification",
			b:           []byte{0x01, 0x02, 0x03},
			expErr:      true,
		},
		{
			description: "No sufficient bytes to get SPI according to the length specified in header",
			b:           []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expErr:      true,
		},
		{
			description: "Notification Unmarshal",
			b: []byte{
				0x00, 0x03, 0x40, 0x04, 0x01, 0x02, 0x03, 0x50,
				0xc4, 0xc2, 0xbe, 0x8e, 0x3f, 0xd9, 0x16, 0x19,
				0x24, 0x65, 0x0d, 0x14, 0x5d, 0x4f, 0xf6, 0x46,
				0xd8, 0x9d, 0x75,
			},
			expMarshal: Notification{
				ProtocolID:        TypeNone,
				NotifyMessageType: NAT_DETECTION_SOURCE_IP,
				SPI:               []byte{0x01, 0x02, 0x03},
				NotificationData: []byte{
					0x50, 0xc4, 0xc2, 0xbe, 0x8e, 0x3f, 0xd9, 0x16,
					0x19, 0x24, 0x65, 0x0d, 0x14, 0x5d, 0x4f, 0xf6,
					0x46, 0xd8, 0x9d, 0x75,
				},
			},
			expErr: false,
		},
	}

	for _, tc := range testcasesUnmarshal {
		t.Run(tc.description, func(t *testing.T) {
			var notification Notification
			err := notification.unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, notification)
			}
		})
	}
}

func TestDelete(t *testing.T) {
	testcasesMarshal := []struct {
		description string
		delete      Delete
		expMarshal  []byte
		expErr      bool
	}{
		{
			description: "Total bytes of all SPIs not correct",
			delete: Delete{
				ProtocolID:  TypeESP,
				SPISize:     4,
				NumberOfSPI: 1,
				SPIs:        []byte{0x01, 0x02, 0x03},
			},
			expErr: true,
		},
		{
			description: "Delete marshal TypeIKE",
			delete: Delete{
				ProtocolID:  TypeIKE,
				SPISize:     0,
				NumberOfSPI: 0,
				SPIs:        nil,
			},
			expMarshal: []byte{
				0x01, 0x00, 0x00, 0x00,
			},
			expErr: false,
		},
		{
			description: "Delete marshal TypeESP",
			delete: Delete{
				ProtocolID:  TypeESP,
				SPISize:     4,
				NumberOfSPI: 1,
				SPIs:        []byte{0x01, 0x02, 0x03, 0x04},
			},
			expMarshal: []byte{
				0x03, 0x04, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04,
			},
			expErr: false,
		},
	}

	for _, tc := range testcasesMarshal {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.delete.marshal()
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, result)
			}
		})
	}

	testcasesUnmarshal := []struct {
		description string
		b           []byte
		expErr      bool
		expMarshal  Delete
	}{
		{
			description: "No sufficient bytes to decode next delete",
			b:           []byte{0x01, 0x02, 0x03},
			expErr:      true,
		},
		{
			description: "No Sufficient bytes to get SPIs according to the length specified in header",
			b:           []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expErr:      true,
		},
		{
			description: "Delete Unmarshal",
			b: []byte{
				0x03, 0x04, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04,
			},
			expMarshal: Delete{
				ProtocolID:  TypeESP,
				SPISize:     4,
				NumberOfSPI: 1,
				SPIs:        []byte{0x01, 0x02, 0x03, 0x04},
			},
			expErr: false,
		},
	}

	for _, tc := range testcasesUnmarshal {
		t.Run(tc.description, func(t *testing.T) {
			var d Delete
			err := d.unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, d)
			}
		})
	}
}

func TestVendorID(t *testing.T) {
	testcasesMarshal := []struct {
		description string
		vendorID    VendorID
		expMarshal  []byte
	}{
		{
			description: "VendorID marshal",
			vendorID: VendorID{
				VendorIDData: []byte{
					0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
					0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
					0xb8, 0x56, 0x81, 0x8a,
				},
			},
			expMarshal: []byte{
				0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
				0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
				0xb8, 0x56, 0x81, 0x8a,
			},
		},
	}

	for _, tc := range testcasesMarshal {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.vendorID.marshal()
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, result)
		})
	}

	testcasesUnmarshal := []struct {
		description string
		b           []byte
		expMarshal  VendorID
	}{
		{
			description: "VendorID Unmarshal",
			b: []byte{
				0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
				0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
				0xb8, 0x56, 0x81, 0x8a,
			},
			expMarshal: VendorID{
				VendorIDData: []byte{
					0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
					0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
					0xb8, 0x56, 0x81, 0x8a,
				},
			},
		},
	}

	for _, tc := range testcasesUnmarshal {
		t.Run(tc.description, func(t *testing.T) {
			var vendorID VendorID
			err := vendorID.unmarshal(tc.b)
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, vendorID)
		})
	}
}

func TestTrafficSelectorInitiator(t *testing.T) {
	testcasesMarshal := []struct {
		description string
		tsi         TrafficSelectorInitiator
		expMarshal  []byte
		expErr      bool
	}{
		{
			description: "Contains no traffic selector for marshalling message",
			tsi:         TrafficSelectorInitiator{},
			expErr:      true,
		},
		{
			description: "Unsupported traffic selector type",
			tsi: TrafficSelectorInitiator{
				IndividualTrafficSelectorContainer{
					&IndividualTrafficSelector{
						StartAddress: []byte{0x01, 0x02, 0x03},
					},
				},
			},
			expErr: true,
		},
		{
			description: "Start IPv4 address length is not correct",
			tsi: TrafficSelectorInitiator{
				IndividualTrafficSelectorContainer{
					&IndividualTrafficSelector{
						TSType:       TS_IPV4_ADDR_RANGE,
						StartAddress: []byte{0x01, 0x02, 0x03},
					},
				},
			},
			expErr: true,
		},
		{
			description: "End IPv4 address length is not correct",
			tsi: TrafficSelectorInitiator{
				IndividualTrafficSelectorContainer{
					&IndividualTrafficSelector{
						TSType:       TS_IPV4_ADDR_RANGE,
						StartAddress: []byte{0x01, 0x02, 0x03, 0x04},
						EndAddress:   []byte{0x01, 0x02, 0x03},
					},
				},
			},
			expErr: true,
		},
		{
			description: "TrafficSelectorInitiator Marshal IPv4",
			tsi: TrafficSelectorInitiator{
				IndividualTrafficSelectorContainer{
					&IndividualTrafficSelector{
						TSType:       TS_IPV4_ADDR_RANGE,
						IPProtocolID: IPProtocolAll,
						StartPort:    0,
						EndPort:      65535,
						StartAddress: []byte{0x0a, 0x00, 0x00, 0x01},
						EndAddress:   []byte{0x0a, 0x00, 0x00, 0x01},
					},
				},
			},
			expMarshal: []byte{
				0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x10,
				0x00, 0x00, 0xff, 0xff, 0x0a, 0x00, 0x00, 0x01,
				0x0a, 0x00, 0x00, 0x01,
			},
			expErr: false,
		},
		{
			description: "TrafficSelectorInitiator Marshal IPv6",
			tsi: TrafficSelectorInitiator{
				IndividualTrafficSelectorContainer{
					&IndividualTrafficSelector{
						TSType:       TS_IPV6_ADDR_RANGE,
						IPProtocolID: IPProtocolAll,
						StartPort:    0,
						EndPort:      65535,
						StartAddress: []byte{
							0xb8, 0x46, 0xd2, 0x47, 0xcf, 0x84, 0xf2, 0x89,
							0xcf, 0x7e, 0xce, 0xe6, 0x6d, 0xb2, 0x1f, 0xc4,
						},
						EndAddress: []byte{
							0xb8, 0x46, 0xd2, 0x47, 0xcf, 0x84, 0xf2, 0x89,
							0xcf, 0x7e, 0xce, 0xe6, 0x6d, 0xb2, 0x1f, 0xc4,
						},
					},
				},
			},
			expMarshal: []byte{
				0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x28,
				0x00, 0x00, 0xff, 0xff, 0xb8, 0x46, 0xd2, 0x47,
				0xcf, 0x84, 0xf2, 0x89, 0xcf, 0x7e, 0xce, 0xe6,
				0x6d, 0xb2, 0x1f, 0xc4, 0xb8, 0x46, 0xd2, 0x47,
				0xcf, 0x84, 0xf2, 0x89, 0xcf, 0x7e, 0xce, 0xe6,
				0x6d, 0xb2, 0x1f, 0xc4,
			},
			expErr: false,
		},
	}

	for _, tc := range testcasesMarshal {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.tsi.marshal()
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, result)
			}
		})
	}

	testcasesUnmarshal := []struct {
		description string
		b           []byte
		expMarshal  TrafficSelectorInitiator
		expErr      bool
	}{
		{
			description: "No sufficient bytes to get number of traffic selector in header",
			b:           []byte{0x01, 0x02, 0x03},
			expErr:      true,
		},
		{
			description: "No sufficient bytes to decode next individual traffic selector length in header",
			b:           []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expErr:      true,
		},
		{
			description: "A TS_IPV4_ADDR_RANGE type traffic selector should has length 16 bytes",
			b: []byte{
				0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x05,
				0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
				0xff, 0xff, 0xff, 0xff,
			},
			expErr: true,
		},
		{
			description: "TS_IPV4_ADDR_RANGE No sufficient bytes to decode next individual traffic selector",
			b: []byte{
				0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x10,
				0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
				0xff, 0xff, 0xff,
			},
			expErr: true,
		},
		{
			description: "A TS_IPV6_ADDR_RANGE type traffic selector should has length 40 bytes",
			b: []byte{
				0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x27,
				0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
				0xff, 0xff, 0xff, 0xff,
			},
			expErr: true,
		},
		{
			description: "TS_IPV6_ADDR_RANGE No sufficient bytes to decode next individual traffic selector",
			b: []byte{
				0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x28,
				0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
				0xff, 0xff, 0xff, 0xff, 0x07, 0x00, 0x00, 0x10,
				0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
				0xff, 0xff, 0xff, 0xff,
			},
			expErr: true,
		},
		{
			description: "Unsupported traffic selector type",
			b: []byte{
				0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x27,
				0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
				0xff, 0xff, 0xff, 0xff,
			},
			expErr: true,
		},
		{
			description: "TrafficSelectorInitiator Unmarshal IPv4",
			b: []byte{
				0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x10,
				0x00, 0x00, 0xff, 0xff, 0x0a, 0x00, 0x00, 0x01,
				0x0a, 0x00, 0x00, 0x01,
			},
			expMarshal: TrafficSelectorInitiator{
				IndividualTrafficSelectorContainer{
					&IndividualTrafficSelector{
						TSType:       TS_IPV4_ADDR_RANGE,
						IPProtocolID: IPProtocolAll,
						StartPort:    0,
						EndPort:      65535,
						StartAddress: []byte{0x0a, 0x00, 0x00, 0x01},
						EndAddress:   []byte{0x0a, 0x00, 0x00, 0x01},
					},
				},
			},
			expErr: false,
		},
		{
			description: "TrafficSelectorInitiator Unmarshal IPv6",
			b: []byte{
				0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x28,
				0x00, 0x00, 0xff, 0xff, 0xb8, 0x46, 0xd2, 0x47,
				0xcf, 0x84, 0xf2, 0x89, 0xcf, 0x7e, 0xce, 0xe6,
				0x6d, 0xb2, 0x1f, 0xc4, 0xb8, 0x46, 0xd2, 0x47,
				0xcf, 0x84, 0xf2, 0x89, 0xcf, 0x7e, 0xce, 0xe6,
				0x6d, 0xb2, 0x1f, 0xc4,
			},
			expMarshal: TrafficSelectorInitiator{
				IndividualTrafficSelectorContainer{
					&IndividualTrafficSelector{
						TSType:       TS_IPV6_ADDR_RANGE,
						IPProtocolID: IPProtocolAll,
						StartPort:    0,
						EndPort:      65535,
						StartAddress: []byte{
							0xb8, 0x46, 0xd2, 0x47, 0xcf, 0x84, 0xf2, 0x89,
							0xcf, 0x7e, 0xce, 0xe6, 0x6d, 0xb2, 0x1f, 0xc4,
						},
						EndAddress: []byte{
							0xb8, 0x46, 0xd2, 0x47, 0xcf, 0x84, 0xf2, 0x89,
							0xcf, 0x7e, 0xce, 0xe6, 0x6d, 0xb2, 0x1f, 0xc4,
						},
					},
				},
			},
			expErr: false,
		},
	}

	for _, tc := range testcasesUnmarshal {
		t.Run(tc.description, func(t *testing.T) {
			var tsi TrafficSelectorInitiator
			err := tsi.unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, tsi)
			}
		})
	}
}

func TestTrafficSelectorResponder(t *testing.T) {
	testcasesMarshal := []struct {
		description string
		tsr         TrafficSelectorResponder
		expMarshal  []byte
		expErr      bool
	}{
		{
			description: "Contains no traffic selector for marshalling message",
			tsr:         TrafficSelectorResponder{},
			expErr:      true,
		},
		{
			description: "Unsupported traffic selector type",
			tsr: TrafficSelectorResponder{
				IndividualTrafficSelectorContainer{
					&IndividualTrafficSelector{
						StartAddress: []byte{0x01, 0x02, 0x03},
					},
				},
			},
			expErr: true,
		},
		{
			description: "Start IPv4 address length is not correct",
			tsr: TrafficSelectorResponder{
				IndividualTrafficSelectorContainer{
					&IndividualTrafficSelector{
						TSType:       TS_IPV4_ADDR_RANGE,
						StartAddress: []byte{0x01, 0x02, 0x03},
					},
				},
			},
			expErr: true,
		},
		{
			description: "End IPv4 address length is not correct",
			tsr: TrafficSelectorResponder{
				IndividualTrafficSelectorContainer{
					&IndividualTrafficSelector{
						TSType:       TS_IPV4_ADDR_RANGE,
						StartAddress: []byte{0x01, 0x02, 0x03, 0x04},
						EndAddress:   []byte{0x01, 0x02, 0x03},
					},
				},
			},
			expErr: true,
		},
		{
			description: "TrafficSelectorResponder Marshal IPv4",
			tsr: TrafficSelectorResponder{
				IndividualTrafficSelectorContainer{
					&IndividualTrafficSelector{
						TSType:       TS_IPV4_ADDR_RANGE,
						IPProtocolID: IPProtocolAll,
						StartPort:    0,
						EndPort:      65535,
						StartAddress: []byte{0x0a, 0x00, 0x00, 0x01},
						EndAddress:   []byte{0x0a, 0x00, 0x00, 0x01},
					},
				},
			},
			expMarshal: []byte{
				0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x10,
				0x00, 0x00, 0xff, 0xff, 0x0a, 0x00, 0x00, 0x01,
				0x0a, 0x00, 0x00, 0x01,
			},
			expErr: false,
		},
		{
			description: "TrafficSelectorInitiator Marshal IPv6",
			tsr: TrafficSelectorResponder{
				IndividualTrafficSelectorContainer{
					&IndividualTrafficSelector{
						TSType:       TS_IPV6_ADDR_RANGE,
						IPProtocolID: IPProtocolAll,
						StartPort:    0,
						EndPort:      65535,
						StartAddress: []byte{
							0xb8, 0x46, 0xd2, 0x47, 0xcf, 0x84, 0xf2, 0x89,
							0xcf, 0x7e, 0xce, 0xe6, 0x6d, 0xb2, 0x1f, 0xc4,
						},
						EndAddress: []byte{
							0xb8, 0x46, 0xd2, 0x47, 0xcf, 0x84, 0xf2, 0x89,
							0xcf, 0x7e, 0xce, 0xe6, 0x6d, 0xb2, 0x1f, 0xc4,
						},
					},
				},
			},
			expMarshal: []byte{
				0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x28,
				0x00, 0x00, 0xff, 0xff, 0xb8, 0x46, 0xd2, 0x47,
				0xcf, 0x84, 0xf2, 0x89, 0xcf, 0x7e, 0xce, 0xe6,
				0x6d, 0xb2, 0x1f, 0xc4, 0xb8, 0x46, 0xd2, 0x47,
				0xcf, 0x84, 0xf2, 0x89, 0xcf, 0x7e, 0xce, 0xe6,
				0x6d, 0xb2, 0x1f, 0xc4,
			},
			expErr: false,
		},
	}

	for _, tc := range testcasesMarshal {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.tsr.marshal()
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, result)
			}
		})
	}

	testcasesUnmarshal := []struct {
		description string
		b           []byte
		expMarshal  TrafficSelectorResponder
		expErr      bool
	}{
		{
			description: "No sufficient bytes to get number of traffic selector in header",
			b:           []byte{0x01, 0x02, 0x03},
			expErr:      true,
		},
		{
			description: "No sufficient bytes to decode next individual traffic selector length in header",
			b:           []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expErr:      true,
		},
		{
			description: "A TS_IPV4_ADDR_RANGE type traffic selector should has length 16 bytes",
			b: []byte{
				0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x05,
				0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
				0xff, 0xff, 0xff, 0xff,
			},
			expErr: true,
		},
		{
			description: "TS_IPV4_ADDR_RANGE No sufficient bytes to decode next individual traffic selector",
			b: []byte{
				0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x10,
				0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
				0xff, 0xff, 0xff,
			},
			expErr: true,
		},
		{
			description: "A TS_IPV6_ADDR_RANGE type traffic selector should has length 40 bytes",
			b: []byte{
				0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x27,
				0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
				0xff, 0xff, 0xff, 0xff,
			},
			expErr: true,
		},
		{
			description: "TS_IPV6_ADDR_RANGE No sufficient bytes to decode next individual traffic selector",
			b: []byte{
				0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x28,
				0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
				0xff, 0xff, 0xff, 0xff, 0x07, 0x00, 0x00, 0x10,
				0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
				0xff, 0xff, 0xff, 0xff,
			},
			expErr: true,
		},
		{
			description: "Unsupported traffic selector type",
			b: []byte{
				0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x27,
				0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
				0xff, 0xff, 0xff, 0xff,
			},
			expErr: true,
		},
		{
			description: "TrafficSelectorInitiator Unmarshal IPv4",
			b: []byte{
				0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x10,
				0x00, 0x00, 0xff, 0xff, 0x0a, 0x00, 0x00, 0x01,
				0x0a, 0x00, 0x00, 0x01,
			},
			expMarshal: TrafficSelectorResponder{
				IndividualTrafficSelectorContainer{
					&IndividualTrafficSelector{
						TSType:       TS_IPV4_ADDR_RANGE,
						IPProtocolID: IPProtocolAll,
						StartPort:    0,
						EndPort:      65535,
						StartAddress: []byte{0x0a, 0x00, 0x00, 0x01},
						EndAddress:   []byte{0x0a, 0x00, 0x00, 0x01},
					},
				},
			},
			expErr: false,
		},
		{
			description: "TrafficSelectorInitiator Unmarshal IPv6",
			b: []byte{
				0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x28,
				0x00, 0x00, 0xff, 0xff, 0xb8, 0x46, 0xd2, 0x47,
				0xcf, 0x84, 0xf2, 0x89, 0xcf, 0x7e, 0xce, 0xe6,
				0x6d, 0xb2, 0x1f, 0xc4, 0xb8, 0x46, 0xd2, 0x47,
				0xcf, 0x84, 0xf2, 0x89, 0xcf, 0x7e, 0xce, 0xe6,
				0x6d, 0xb2, 0x1f, 0xc4,
			},
			expMarshal: TrafficSelectorResponder{
				IndividualTrafficSelectorContainer{
					&IndividualTrafficSelector{
						TSType:       TS_IPV6_ADDR_RANGE,
						IPProtocolID: IPProtocolAll,
						StartPort:    0,
						EndPort:      65535,
						StartAddress: []byte{
							0xb8, 0x46, 0xd2, 0x47, 0xcf, 0x84, 0xf2, 0x89,
							0xcf, 0x7e, 0xce, 0xe6, 0x6d, 0xb2, 0x1f, 0xc4,
						},
						EndAddress: []byte{
							0xb8, 0x46, 0xd2, 0x47, 0xcf, 0x84, 0xf2, 0x89,
							0xcf, 0x7e, 0xce, 0xe6, 0x6d, 0xb2, 0x1f, 0xc4,
						},
					},
				},
			},
			expErr: false,
		},
	}

	for _, tc := range testcasesUnmarshal {
		t.Run(tc.description, func(t *testing.T) {
			var tsr TrafficSelectorResponder
			err := tsr.unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, tsr)
			}
		})
	}
}

func TestEncrypted(t *testing.T) {
	testcasesMarshal := []struct {
		description string
		encrypted   Encrypted
		expMarshal  []byte
	}{
		{
			description: "Encrypted marshal",
			encrypted: Encrypted{
				EncryptedData: []byte{
					0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
					0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
					0xb8, 0x56, 0x81, 0x8a,
				},
			},
			expMarshal: []byte{
				0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
				0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
				0xb8, 0x56, 0x81, 0x8a,
			},
		},
	}

	for _, tc := range testcasesMarshal {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.encrypted.marshal()
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, result)
		})
	}

	testcasesUnmarshal := []struct {
		description string
		b           []byte
		expMarshal  Encrypted
	}{
		{
			description: "Encrypted Unmarshal",
			b: []byte{
				0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
				0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
				0xb8, 0x56, 0x81, 0x8a,
			},
			expMarshal: Encrypted{
				EncryptedData: []byte{
					0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
					0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
					0xb8, 0x56, 0x81, 0x8a,
				},
			},
		},
	}

	for _, tc := range testcasesUnmarshal {
		t.Run(tc.description, func(t *testing.T) {
			var encrypted Encrypted
			err := encrypted.unmarshal(tc.b)
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, encrypted)
		})
	}
}

func TestEAPIdentity(t *testing.T) {
	testcasesMarshal := []struct {
		description string
		eap         EAPIdentity
		expMarshal  []byte
		expErr      bool
	}{
		{
			description: "EAP identity is empty",
			eap: EAPIdentity{
				IdentityData: nil,
			},
			expErr: true,
		},
		{
			description: "EAPIdentity marshal",
			eap: EAPIdentity{
				IdentityData: []byte{
					0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
					0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
					0xb8, 0x56, 0x81, 0x8a,
				},
			},
			expMarshal: []byte{
				0x01, 0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e,
				0x20, 0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22,
				0x2a, 0xb8, 0x56, 0x81, 0x8a,
			},
			expErr: false,
		},
	}

	for _, tc := range testcasesMarshal {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.eap.marshal()
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, result)
			}
		})
	}

	testcasesUnmarshal := []struct {
		description string
		b           []byte
		expMarshal  EAPIdentity
	}{
		{
			description: "EAPIdentity Unmarshal",
			b: []byte{
				0x01, 0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e,
				0x20, 0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22,
				0x2a, 0xb8, 0x56, 0x81, 0x8a,
			},
			expMarshal: EAPIdentity{
				IdentityData: []byte{
					0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
					0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
					0xb8, 0x56, 0x81, 0x8a,
				},
			},
		},
	}

	for _, tc := range testcasesUnmarshal {
		t.Run(tc.description, func(t *testing.T) {
			var eap EAPIdentity
			err := eap.unmarshal(tc.b)
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, eap)
		})
	}
}

func TestEAPNotification(t *testing.T) {
	testcasesMarshal := []struct {
		description string
		eap         EAPNotification
		expMarshal  []byte
		expErr      bool
	}{
		{
			description: "EAP notification is empty",
			eap: EAPNotification{
				NotificationData: nil,
			},
			expErr: true,
		},
		{
			description: "EAPNotification marshal",
			eap: EAPNotification{
				NotificationData: []byte{
					0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
					0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
					0xb8, 0x56, 0x81, 0x8a,
				},
			},
			expMarshal: []byte{
				0x02, 0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e,
				0x20, 0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22,
				0x2a, 0xb8, 0x56, 0x81, 0x8a,
			},
			expErr: false,
		},
	}

	for _, tc := range testcasesMarshal {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.eap.marshal()
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, result)
			}
		})
	}

	testcasesUnmarshal := []struct {
		description string
		b           []byte
		expMarshal  EAPNotification
	}{
		{
			description: "EAPNotification Unmarshal",
			b: []byte{
				0x02, 0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e,
				0x20, 0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22,
				0x2a, 0xb8, 0x56, 0x81, 0x8a,
			},
			expMarshal: EAPNotification{
				NotificationData: []byte{
					0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
					0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
					0xb8, 0x56, 0x81, 0x8a,
				},
			},
		},
	}

	for _, tc := range testcasesUnmarshal {
		t.Run(tc.description, func(t *testing.T) {
			var eap EAPNotification
			err := eap.unmarshal(tc.b)
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, eap)
		})
	}
}

func TestEAPNak(t *testing.T) {
	testcasesMarshal := []struct {
		description string
		eap         EAPNak
		expMarshal  []byte
		expErr      bool
	}{
		{
			description: "EAP nak is empty",
			eap: EAPNak{
				NakData: nil,
			},
			expErr: true,
		},
		{
			description: "EAPNak marshal",
			eap: EAPNak{
				NakData: []byte{
					0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
					0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
					0xb8, 0x56, 0x81, 0x8a,
				},
			},
			expMarshal: []byte{
				0x03, 0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e,
				0x20, 0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22,
				0x2a, 0xb8, 0x56, 0x81, 0x8a,
			},
			expErr: false,
		},
	}

	for _, tc := range testcasesMarshal {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.eap.marshal()
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, result)
			}
		})
	}

	testcasesUnmarshal := []struct {
		description string
		b           []byte
		expMarshal  EAPNak
	}{
		{
			description: "EAPNak Unmarshal",
			b: []byte{
				0x03, 0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e,
				0x20, 0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22,
				0x2a, 0xb8, 0x56, 0x81, 0x8a,
			},
			expMarshal: EAPNak{
				NakData: []byte{
					0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
					0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
					0xb8, 0x56, 0x81, 0x8a,
				},
			},
		},
	}

	for _, tc := range testcasesUnmarshal {
		t.Run(tc.description, func(t *testing.T) {
			var eap EAPNak
			err := eap.unmarshal(tc.b)
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, eap)
		})
	}
}

func TestEAPExpanded(t *testing.T) {
	testcasesMarshal := []struct {
		description string
		eap         EAPExpanded
		expMarshal  []byte
		expErr      bool
	}{
		{
			description: "EAPExpanded marshal",
			eap: EAPExpanded{
				VendorID:   VendorID3GPP,
				VendorType: VendorTypeEAP5G,
				VendorData: []byte{
					0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
					0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
					0xb8, 0x56, 0x81, 0x8a,
				},
			},
			expMarshal: []byte{
				0xfe, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x00, 0x03,
				0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
				0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
				0xb8, 0x56, 0x81, 0x8a,
			},
			expErr: false,
		},
	}

	for _, tc := range testcasesMarshal {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.eap.marshal()
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, result)
			}
		})
	}

	testcasesUnmarshal := []struct {
		description string
		b           []byte
		expMarshal  EAPExpanded
	}{
		{
			description: "EAPExpanded Unmarshal",
			b: []byte{
				0xfe, 0x00, 0x28, 0xaf, 0x00, 0x00, 0x00, 0x03,
				0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
				0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
				0xb8, 0x56, 0x81, 0x8a,
			},
			expMarshal: EAPExpanded{
				VendorID:   VendorID3GPP,
				VendorType: VendorTypeEAP5G,
				VendorData: []byte{
					0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
					0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
					0xb8, 0x56, 0x81, 0x8a,
				},
			},
		},
	}

	for _, tc := range testcasesUnmarshal {
		t.Run(tc.description, func(t *testing.T) {
			var eap EAPExpanded
			err := eap.unmarshal(tc.b)
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, eap)
		})
	}
}

func TestConfiguration(t *testing.T) {
	testcasesMarshal := []struct {
		description string
		cfg         Configuration
		expMarshal  []byte
	}{
		{
			description: "Configuration marshal",
			cfg: Configuration{
				ConfigurationType: CFG_REQUEST,
				ConfigurationAttribute: ConfigurationAttributeContainer{
					&IndividualConfigurationAttribute{
						Type: INTERNAL_IP4_ADDRESS,
						Value: []byte{
							0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
							0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
							0xb8, 0x56, 0x81, 0x8a,
						},
					},
				},
			},
			expMarshal: []byte{
				0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x14,
				0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
				0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
				0xb8, 0x56, 0x81, 0x8a,
			},
		},
	}

	for _, tc := range testcasesMarshal {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.cfg.marshal()
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, result)
		})
	}

	testcasesUnmarshal := []struct {
		description string
		b           []byte
		expErr      bool
		expMarshal  Configuration
	}{
		{
			description: "No sufficient bytes to decode next configuration",
			b:           []byte{0x01, 0x02, 0x03, 0x04},
			expErr:      true,
		},
		{
			description: "No sufficient bytes to decode next configuration attribute",
			b:           []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expErr:      true,
		},
		{
			description: "TLV attribute length error",
			b:           []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x05, 0x05, 0x05},
			expErr:      true,
		},
		{
			description: "Configuration Unmarshal",
			b: []byte{
				0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x14,
				0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
				0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
				0xb8, 0x56, 0x81, 0x8a,
			},
			expMarshal: Configuration{
				ConfigurationType: CFG_REQUEST,
				ConfigurationAttribute: ConfigurationAttributeContainer{
					&IndividualConfigurationAttribute{
						Type: INTERNAL_IP4_ADDRESS,
						Value: []byte{
							0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
							0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
							0xb8, 0x56, 0x81, 0x8a,
						},
					},
				},
			},
			expErr: false,
		},
	}

	for _, tc := range testcasesUnmarshal {
		t.Run(tc.description, func(t *testing.T) {
			var cfg Configuration
			err := cfg.unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, cfg)
			}
		})
	}
}

func TestEAP(t *testing.T) {
	testcasesMarshal := []struct {
		description string
		eap         EAP
		expMarshal  []byte
		expErr      bool
	}{
		{
			description: "EAP identity is empty",
			eap: EAP{
				Code:       EAPCodeRequest,
				Identifier: 9,
				EAPTypeData: EAPTypeDataContainer{
					&EAPIdentity{
						IdentityData: nil,
					},
				},
			},
			expErr: true,
		},
		{
			description: "EAPIdentity marshal",
			eap: EAP{
				Code:       EAPCodeRequest,
				Identifier: 9,
				EAPTypeData: EAPTypeDataContainer{
					&EAPIdentity{
						IdentityData: []byte{
							0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
							0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
							0xb8, 0x56, 0x81, 0x8a,
						},
					},
				},
			},
			expMarshal: []byte{
				0x01, 0x09, 0x00, 0x19, 0x01, 0x7d, 0x09,
				0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20, 0x56,
				0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
				0xb8, 0x56, 0x81, 0x8a,
			},
			expErr: false,
		},
		{
			description: "EAP notification is empty",
			eap: EAP{
				Code:       EAPCodeRequest,
				Identifier: 9,
				EAPTypeData: EAPTypeDataContainer{
					&EAPNotification{
						NotificationData: nil,
					},
				},
			},
			expErr: true,
		},
		{
			description: "EAPNotification marshal",
			eap: EAP{
				Code:       EAPCodeRequest,
				Identifier: 9,
				EAPTypeData: EAPTypeDataContainer{
					&EAPNotification{
						NotificationData: []byte{
							0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
							0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
							0xb8, 0x56, 0x81, 0x8a,
						},
					},
				},
			},
			expMarshal: []byte{
				0x01, 0x09, 0x00, 0x19, 0x02, 0x7d, 0x09, 0x18,
				0x42, 0x60, 0x9c, 0x9e, 0x20, 0x56, 0x9f, 0xc0,
				0x39, 0xda, 0x3f, 0x22, 0x2a, 0xb8, 0x56, 0x81,
				0x8a,
			},
			expErr: false,
		},
		{
			description: "EAP nak is empty",
			eap: EAP{
				Code:       EAPCodeRequest,
				Identifier: 9,
				EAPTypeData: EAPTypeDataContainer{
					&EAPNak{
						NakData: nil,
					},
				},
			},
			expErr: true,
		},
		{
			description: "EAPNak marshal",
			eap: EAP{
				Code:       EAPCodeRequest,
				Identifier: 9,
				EAPTypeData: EAPTypeDataContainer{
					&EAPNak{
						NakData: []byte{
							0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
							0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
							0xb8, 0x56, 0x81, 0x8a,
						},
					},
				},
			},
			expMarshal: []byte{
				0x01, 0x09, 0x00, 0x19, 0x03, 0x7d, 0x09, 0x18,
				0x42, 0x60, 0x9c, 0x9e, 0x20, 0x56, 0x9f, 0xc0,
				0x39, 0xda, 0x3f, 0x22, 0x2a, 0xb8, 0x56, 0x81,
				0x8a,
			},
			expErr: false,
		},
		{
			description: "EAPExpanded marshal",
			eap: EAP{
				Code:       EAPCodeRequest,
				Identifier: 9,
				EAPTypeData: EAPTypeDataContainer{
					&EAPExpanded{
						VendorID:   VendorID3GPP,
						VendorType: VendorTypeEAP5G,
						VendorData: []byte{
							0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
							0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
							0xb8, 0x56, 0x81, 0x8a,
						},
					},
				},
			},
			expMarshal: []byte{
				0x01, 0x09, 0x00, 0x20, 0xfe, 0x00, 0x28, 0xaf,
				0x00, 0x00, 0x00, 0x03, 0x7d, 0x09, 0x18, 0x42,
				0x60, 0x9c, 0x9e, 0x20, 0x56, 0x9f, 0xc0, 0x39,
				0xda, 0x3f, 0x22, 0x2a, 0xb8, 0x56, 0x81, 0x8a,
			},
			expErr: false,
		},
	}

	for _, tc := range testcasesMarshal {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.eap.marshal()
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, result)
			}
		})
	}

	testcasesUnmarshal := []struct {
		description string
		b           []byte
		expMarshal  EAP
		expErr      bool
	}{
		{
			description: "No sufficient bytes to decode next EAP payload",
			b:           []byte{0x01, 0x02, 0x03},
			expErr:      true,
		},
		{
			description: "Payload length specified in the header is too small for EAP",
			b:           []byte{0x01, 0x02, 0x00, 0x03},
			expErr:      true,
		},
		{
			description: "Received payload length not matches the length specified in header",
			b:           []byte{0x01, 0x02, 0x00, 0x07, 0x01},
			expErr:      true,
		},
		{
			description: "EAPIdentity unmarshal",
			b: []byte{
				0x01, 0x09, 0x00, 0x19, 0x01, 0x7d, 0x09,
				0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20, 0x56,
				0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
				0xb8, 0x56, 0x81, 0x8a,
			},
			expMarshal: EAP{
				Code:       EAPCodeRequest,
				Identifier: 9,
				EAPTypeData: EAPTypeDataContainer{
					&EAPIdentity{
						IdentityData: []byte{
							0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
							0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
							0xb8, 0x56, 0x81, 0x8a,
						},
					},
				},
			},
			expErr: false,
		},
		{
			description: "EAPNotification unmarshal",
			b: []byte{
				0x01, 0x09, 0x00, 0x19, 0x02, 0x7d, 0x09, 0x18,
				0x42, 0x60, 0x9c, 0x9e, 0x20, 0x56, 0x9f, 0xc0,
				0x39, 0xda, 0x3f, 0x22, 0x2a, 0xb8, 0x56, 0x81,
				0x8a,
			},
			expMarshal: EAP{
				Code:       EAPCodeRequest,
				Identifier: 9,
				EAPTypeData: EAPTypeDataContainer{
					&EAPNotification{
						NotificationData: []byte{
							0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
							0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
							0xb8, 0x56, 0x81, 0x8a,
						},
					},
				},
			},
			expErr: false,
		},
		{
			description: "EAPNak unmarshal",
			b: []byte{
				0x01, 0x09, 0x00, 0x19, 0x03, 0x7d, 0x09, 0x18,
				0x42, 0x60, 0x9c, 0x9e, 0x20, 0x56, 0x9f, 0xc0,
				0x39, 0xda, 0x3f, 0x22, 0x2a, 0xb8, 0x56, 0x81,
				0x8a,
			},
			expMarshal: EAP{
				Code:       EAPCodeRequest,
				Identifier: 9,
				EAPTypeData: EAPTypeDataContainer{
					&EAPNak{
						NakData: []byte{
							0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
							0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
							0xb8, 0x56, 0x81, 0x8a,
						},
					},
				},
			},
			expErr: false,
		},
		{
			description: "EAPExpanded: No sufficient bytes to decode the EAP expanded type",
			b: []byte{
				0x01, 0x09, 0x00, 0x20, 0xfe, 0x00, 0x28,
			},
			expErr: true,
		},
		{
			description: "EAPExpanded unmarshal",
			b: []byte{
				0x01, 0x09, 0x00, 0x20, 0xfe, 0x00, 0x28, 0xaf,
				0x00, 0x00, 0x00, 0x03, 0x7d, 0x09, 0x18, 0x42,
				0x60, 0x9c, 0x9e, 0x20, 0x56, 0x9f, 0xc0, 0x39,
				0xda, 0x3f, 0x22, 0x2a, 0xb8, 0x56, 0x81, 0x8a,
			},
			expMarshal: EAP{
				Code:       EAPCodeRequest,
				Identifier: 9,
				EAPTypeData: EAPTypeDataContainer{
					&EAPExpanded{
						VendorID:   VendorID3GPP,
						VendorType: VendorTypeEAP5G,
						VendorData: []byte{
							0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
							0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
							0xb8, 0x56, 0x81, 0x8a,
						},
					},
				},
			},
			expErr: false,
		},
	}

	for _, tc := range testcasesUnmarshal {
		t.Run(tc.description, func(t *testing.T) {
			var eap EAP
			err := eap.unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, eap)
			}
		})
	}
}

func TestDecode(t *testing.T) {
	testcases := []struct {
		description string
		b           []byte
		expErr      bool
		expIkeMsg   *IKEMessage
	}{
		{
			description: "decode IKE_AUTH",
			b: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0xf7, 0x08,
				0xc9, 0xe2, 0xe3, 0x1f, 0x8b, 0x64, 0x05, 0x3d,
				0x2e, 0x20, 0x23, 0x08, 0x00, 0x00, 0x00, 0x03,
				0x00, 0x00, 0x00, 0x6c, 0x30, 0x00, 0x00, 0x50,
				0xec, 0x50, 0x31, 0x16, 0x2c, 0x69, 0x2f, 0xbb,
				0xfc, 0x4d, 0x20, 0x64, 0x0c, 0x91, 0x21, 0xeb,
				0xe9, 0x47, 0x5e, 0xf9, 0x4f, 0x9b, 0x02, 0x95,
				0x9d, 0x31, 0x24, 0x2e, 0x53, 0x5e, 0x9c, 0x3c,
				0x4d, 0xca, 0xec, 0xd1, 0xbf, 0xd6, 0xdd, 0x80,
				0xaa, 0x81, 0x2b, 0x07, 0xde, 0x36, 0xde, 0xe9,
				0xb7, 0x50, 0x94, 0x35, 0xf6, 0x35, 0xe1, 0xaa,
				0xae, 0x1c, 0x38, 0x25, 0xf4, 0xea, 0xe3, 0x38,
				0x49, 0x03, 0xf7, 0x24, 0xf4, 0x44, 0x17, 0x0c,
				0x68, 0x45, 0xca, 0x80,
			},
			expErr: false,
			expIkeMsg: &IKEMessage{
				IKEHeader: &IKEHeader{
					InitiatorSPI: 0x000000000006f708,
					ResponderSPI: 0xc9e2e31f8b64053d,
					MajorVersion: 2,
					MinorVersion: 0,
					ExchangeType: IKE_AUTH,
					Flags:        0x08,
					MessageID:    0x03,
					NextPayload:  uint8(TypeSK),
				},
				Payloads: IKEPayloadContainer{
					&Encrypted{
						NextPayload: uint8(TypeEAP),
						EncryptedData: []byte{
							0xec, 0x50, 0x31, 0x16, 0x2c, 0x69, 0x2f, 0xbb,
							0xfc, 0x4d, 0x20, 0x64, 0x0c, 0x91, 0x21, 0xeb,
							0xe9, 0x47, 0x5e, 0xf9, 0x4f, 0x9b, 0x02, 0x95,
							0x9d, 0x31, 0x24, 0x2e, 0x53, 0x5e, 0x9c, 0x3c,
							0x4d, 0xca, 0xec, 0xd1, 0xbf, 0xd6, 0xdd, 0x80,
							0xaa, 0x81, 0x2b, 0x07, 0xde, 0x36, 0xde, 0xe9,
							0xb7, 0x50, 0x94, 0x35, 0xf6, 0x35, 0xe1, 0xaa,
							0xae, 0x1c, 0x38, 0x25, 0xf4, 0xea, 0xe3, 0x38,
							0x49, 0x03, 0xf7, 0x24, 0xf4, 0x44, 0x17, 0x0c,
							0x68, 0x45, 0xca, 0x80,
						},
					},
				},
			},
		},
		{
			description: "decode with short length message",
			b: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05,
			},
			expErr: true,
		},
		{
			description: "decode with IKE_SA_INIT message",
			b: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05,
			},
			expErr: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			ikeMsg := new(IKEMessage)

			err := ikeMsg.Decode(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expIkeMsg, ikeMsg)
			}
		})
	}
}
