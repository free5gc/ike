package eap

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEapAkaPrimePrf(t *testing.T) {
	tcs := []struct {
		name           string
		ikPrime        string
		ckPrime        string
		identity       string
		expectedResult []string
	}{
		{
			name:     "correct",
			ikPrime:  "4bf4f64b21b59444277f2c60c417d4c7",
			ckPrime:  "403075840723643618b6fae83236c86d",
			identity: "208930123456789",
			expectedResult: []string{
				"d2e0e54aa01d48959e38ca1aff6c38fb",
				"a56e1733adf3747cfe045dacebedeb33dd53e0f5200f6697c0855e2f856c4e40",
				"c362f256003483d0766bf877191741254446986158e66d57fcdc251d531fdec4",
				"e6ad162cd2fbcf3b6df5765b51e8983f5fb3204d16930c9bbbef5a971cf1de7c" +
					"1c60f79516b4efe1b937ce510a3e52c161d6c6db3f03a62a93e33a53cc15bb70",
				"f74892a2343d64de4528bd0cbbf12edf03b47adbc72e7839175af598d87cc7d3" +
					"3cf0671517eb051345946b978e7afc9b48327e90f816e67efddc5949adab08ad",
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			ikPrime, err := hex.DecodeString(tc.ikPrime)
			require.NoError(t, err)
			ckPrime, err := hex.DecodeString(tc.ckPrime)
			require.NoError(t, err)

			k_encr, k_aut, k_re, msk, emsk, err := EapAkaPrimePRF(ikPrime, ckPrime, tc.identity)
			require.NoError(t, err)
			actualResult := [][]byte{k_encr, k_aut, k_re, msk, emsk}

			for i := 0; i < len(actualResult); i++ {
				expectedResult, innerErr := hex.DecodeString(tc.expectedResult[i])
				require.NoError(t, innerErr)
				require.Equal(t, expectedResult, actualResult[i])
			}
		})
	}
}

func TestEapAkaPrimeSetGetAttr(t *testing.T) {
	tcs := []struct {
		name      string
		attrType  EapAkaPrimeAttrType
		value     []byte
		expectErr bool
	}{
		{
			name:     "Set AT_RAND",
			attrType: AT_RAND,
			value: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			},
			expectErr: false,
		},
		{
			name:     "Set AT_MAC",
			attrType: AT_MAC,
			value: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			},
			expectErr: false,
		},
		{
			name:      "Set AT_KDF with invalid length",
			attrType:  AT_KDF,
			value:     []byte{0x01},
			expectErr: true,
		},
		{
			name:      "Set AT_KDF",
			attrType:  AT_KDF,
			value:     []byte{0x00, 0x01},
			expectErr: false,
		},
		{
			name:      "Set AT_RAND with invalid length",
			attrType:  AT_RAND,
			value:     []byte{0x01, 0x02, 0x03},
			expectErr: true,
		},
		{
			name:      "Set AT_AUTN",
			attrType:  AT_AUTN,
			value:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			expectErr: false,
		},
		{
			name:      "Set AT_AUTN with invalid length",
			attrType:  AT_AUTN,
			value:     []byte{0x01, 0x02, 0x03},
			expectErr: true,
		},
		{
			name:      "Set AT_RES valid (32 bits)",
			attrType:  AT_RES,
			value:     []byte{0x01, 0x02, 0x03, 0x04},
			expectErr: false,
		},
		{
			name:     "Set AT_RES valid (128 bits)",
			attrType: AT_RES,
			value: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			},
			expectErr: false,
		},
		{
			name:      "Set AT_RES too short",
			attrType:  AT_RES,
			value:     []byte{0x01, 0x02, 0x03}, // 24 bits
			expectErr: true,
		},
		{
			name:      "Set AT_RES too long",
			attrType:  AT_RES,
			value:     make([]byte, 17), // 136 bits
			expectErr: true,
		},
		{
			name:      "Set AT_KDF_INPUT",
			attrType:  AT_KDF_INPUT,
			value:     []byte("test.free5gc.org"),
			expectErr: false,
		},
		{
			name:      "Set AT_CHECKCODE empty",
			attrType:  AT_CHECKCODE,
			value:     []byte{},
			expectErr: false,
		},
		{
			name:      "Set AT_CHECKCODE with 20 bytes",
			attrType:  AT_CHECKCODE,
			value:     make([]byte, 20),
			expectErr: false,
		},
		{
			name:      "Set unsupported attribute type",
			attrType:  255, // Use undefined attribute type
			value:     []byte{0x01},
			expectErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			eapAka := NewEapAkaPrime(SubtypeAkaChallenge)

			// Test SetAttr
			err := eapAka.SetAttr(tc.attrType, tc.value)
			if tc.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Test GetAttr
			attr, err := eapAka.GetAttr(tc.attrType)
			require.NoError(t, err)
			require.Equal(t, tc.attrType, attr.GetAttrType())
			require.Equal(t, tc.value, attr.GetValue())

			// Additional check for length field
			switch tc.attrType {
			case AT_KDF:
				require.Equal(t, uint8(1), attr.length)
			case AT_MAC, AT_RAND, AT_AUTN:
				require.Equal(t, uint8(5), attr.length)
			}
		})
	}
}

func TestEapAkaPrimeGetNonExistentAttr(t *testing.T) {
	eapAka := NewEapAkaPrime(SubtypeAkaChallenge)

	// Try to get an attribute that hasn't been set
	_, err := eapAka.GetAttr(AT_MAC)
	require.Error(t, err)
	require.Contains(t, err.Error(), "is not found")
}

func TestEapAkaPrimeMultipleAttributes(t *testing.T) {
	eapAka := NewEapAkaPrime(SubtypeAkaChallenge)

	// Set multiple attributes
	attrs := map[EapAkaPrimeAttrType][]byte{
		AT_RAND: {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		AT_MAC:  {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		AT_KDF:  {0x00, 0x01},
	}

	for attrType, value := range attrs {
		err := eapAka.SetAttr(attrType, value)
		require.NoError(t, err)
	}

	// Verify all attributes
	for attrType, expectedValue := range attrs {
		attr, err := eapAka.GetAttr(attrType)
		require.NoError(t, err)
		require.Equal(t, attrType, attr.GetAttrType())
		require.Equal(t, expectedValue, attr.GetValue())
	}
}

func TestEapAkaPrimeOverwriteAttribute(t *testing.T) {
	eapAka := NewEapAkaPrime(SubtypeAkaChallenge)

	// Set initial value
	initialValue := []byte{0x01, 0x02}
	err := eapAka.SetAttr(AT_KDF, initialValue)
	require.NoError(t, err)

	// Overwrite with new value
	newValue := []byte{0x03, 0x04}
	err = eapAka.SetAttr(AT_KDF, newValue)
	require.NoError(t, err)

	// Verify new value
	attr, err := eapAka.GetAttr(AT_KDF)
	require.NoError(t, err)
	require.Equal(t, newValue, attr.GetValue())
}

func TestEapAkaPrimeAttrLength(t *testing.T) {
	testCases := []struct {
		name             string
		attrType         EapAkaPrimeAttrType
		value            []byte
		expectedLen      uint8
		expectedReserved uint16
	}{
		{
			name:             "AT_MAC length",
			attrType:         AT_MAC,
			value:            make([]byte, 16),
			expectedLen:      5,
			expectedReserved: 0,
		},
		{
			name:             "AT_RES length (32 bits)",
			attrType:         AT_RES,
			value:            make([]byte, 4),
			expectedLen:      2,
			expectedReserved: 32, // bits
		},
		{
			name:             "AT_KDF_INPUT length",
			attrType:         AT_KDF_INPUT,
			value:            []byte("test.free5gc.org"),
			expectedLen:      5,
			expectedReserved: uint16(len("test.free5gc.org") * 8),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			attr := new(EapAkaPrimeAttr)
			err := attr.setAttr(tc.attrType, tc.value)
			require.NoError(t, err)
			require.Equal(t, tc.expectedLen, attr.length)
			require.Equal(t, tc.expectedReserved, attr.reserved)
		})
	}
}

func TestEapAkaPrimeMarshal(t *testing.T) {
	testCases := []struct {
		name           string
		subType        EapAkaSubtype
		attrs          map[EapAkaPrimeAttrType][]byte
		expectedResult []byte
		expectErr      bool
	}{
		{
			name:    "Basic Challenge with AT_RAND and AT_MAC",
			subType: SubtypeAkaChallenge,
			attrs: map[EapAkaPrimeAttrType][]byte{
				AT_RAND: {
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
				},
				AT_MAC: {
					0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
					0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
				},
			},
			expectedResult: []byte{
				byte(EapTypeAkaPrime),     // EAP-AKA' type
				byte(SubtypeAkaChallenge), // Subtype
				0x00, 0x00,                // Reserved
				0x01, 0x05, 0x00, 0x00, // AT_RAND header (type=1, length=5)
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // AT_RAND value
				0x0b, 0x05, 0x00, 0x00, // AT_MAC header (type=11, length=5)
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, // AT_MAC value
			},
			expectErr: false,
		},
		{
			name:    "AT_RES with padding",
			subType: SubtypeAkaChallenge,
			attrs: map[EapAkaPrimeAttrType][]byte{
				AT_RES: {0x01, 0x02, 0x03, 0x04, 0x05}, // 5 bytes = 40 bits
			},
			expectedResult: []byte{
				byte(EapTypeAkaPrime),     // EAP-AKA' type
				byte(SubtypeAkaChallenge), // Subtype
				0x00, 0x00,                // Reserved
				0x03, 0x03, // AT_RES type and length
				0x00, 0x28, // RES Length (40 bits)
				0x01, 0x02, 0x03, 0x04, 0x05, // RES value
				0x00, 0x00, 0x00, // Padding to make multiple of 4 bytes
			},
			expectErr: false,
		},
		{
			name:    "Identity with AT_KDF and AT_KDF_INPUT",
			subType: SubtypeAkaIdentity,
			attrs: map[EapAkaPrimeAttrType][]byte{
				AT_KDF:       {0x00, 0x01},
				AT_KDF_INPUT: []byte("free5gc.org"),
			},
			expectedResult: []byte{
				byte(EapTypeAkaPrime),    // EAP-AKA' type
				byte(SubtypeAkaIdentity), // Subtype
				0x00, 0x00,               // Reserved
				0x17, 0x04, // AT_KDF_INPUT header (type=23, length=4)
				0x00, 0x58, // AT_KDF_INPUT reserved (88 bits)
				'f', 'r', 'e', 'e', '5', 'g', 'c', '.', 'o', 'r', 'g', // AT_KDF_INPUT value
				0x00,                   // Padding
				0x18, 0x01, 0x00, 0x01, // AT_KDF (type=24, length=1)
			},
			expectErr: false,
		},
		{
			name:    "Empty attributes",
			subType: SubtypeAkaChallenge,
			attrs:   map[EapAkaPrimeAttrType][]byte{},
			expectedResult: []byte{
				byte(EapTypeAkaPrime),     // EAP-AKA' type
				byte(SubtypeAkaChallenge), // Subtype
				0x00, 0x00,                // Reserved
			},
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create and initialize EapAkaPrime
			original := NewEapAkaPrime(tc.subType)

			// Set attributes
			for attrType, value := range tc.attrs {
				err := original.SetAttr(attrType, value)
				require.NoError(t, err)
			}

			// Marshal
			data, err := original.Marshal()
			if tc.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expectedResult, data)
		})
	}
}

func TestEapAkaPrimeUnmarshalErrors(t *testing.T) {
	testCases := []struct {
		name        string
		rawData     []byte
		errContains string
	}{
		{
			name:        "Empty data",
			rawData:     []byte{},
			errContains: "no sufficient bytes to decode the EAP-AKA' type",
		},
		{
			name:        "Invalid EAP type",
			rawData:     []byte{0x00, 0x01, 0x00, 0x00},
			errContains: "expect EAP type",
		},
		{
			name:        "Truncated data after type",
			rawData:     []byte{byte(EapTypeAkaPrime)},
			errContains: "no sufficient bytes to decode the EAP-AKA' type",
		},
		{
			name:        "Truncated data after subtype",
			rawData:     []byte{byte(EapTypeAkaPrime), 0x01},
			errContains: "no sufficient bytes to decode the EAP-AKA' type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			eapAka := new(EapAkaPrime)
			err := eapAka.Unmarshal(tc.rawData)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.errContains)
		})
	}
}

func TestEapAkaPrimeUnmarshal(t *testing.T) {
	testCases := []struct {
		name          string
		rawData       []byte
		expectedEap   *EapAkaPrime
		expectErr     bool
		expectedAttrs map[EapAkaPrimeAttrType][]byte
	}{
		{
			name: "Basic Challenge with AT_RAND and AT_MAC",
			rawData: []byte{
				byte(EapTypeAkaPrime),     // EAP-AKA' type
				byte(SubtypeAkaChallenge), // Subtype
				0x00, 0x00,                // Reserved
				0x01, 0x05, 0x00, 0x00, // AT_RAND header (type=1, length=5)
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // AT_RAND value
				0x0b, 0x05, 0x00, 0x00, // AT_MAC header (type=11, length=5)
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, // AT_MAC value
			},
			expectedAttrs: map[EapAkaPrimeAttrType][]byte{
				AT_RAND: {
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
				},
				AT_MAC: {
					0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
					0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
				},
			},
			expectErr: false,
		},
		{
			name: "Identity with AT_KDF and AT_KDF_INPUT",
			rawData: []byte{
				byte(EapTypeAkaPrime),    // EAP-AKA' type
				byte(SubtypeAkaIdentity), // Subtype
				0x00, 0x00,               // Reserved
				0x17, 0x04, // AT_KDF_INPUT header (type=23, length=4)
				0x00, 0x58, // AT_KDF_INPUT reserved (88 bits)
				'f', 'r', 'e', 'e', '5', 'g', 'c', '.', 'o', 'r', 'g', // AT_KDF_INPUT value
				0x00,                   // Padding
				0x18, 0x01, 0x00, 0x01, // AT_KDF (type=24, length=1, value=1)
			},
			expectedAttrs: map[EapAkaPrimeAttrType][]byte{
				AT_KDF:       {0x00, 0x01},
				AT_KDF_INPUT: []byte("free5gc.org"),
			},
			expectErr: false,
		},
		{
			name: "AT_RES with padding",
			rawData: []byte{
				byte(EapTypeAkaPrime),     // EAP-AKA' type
				byte(SubtypeAkaChallenge), // Subtype
				0x00, 0x00,                // Reserved
				0x03, 0x03, // AT_RES type and length
				0x00, 0x28, // RES Length (40 bits)
				0x01, 0x02, 0x03, 0x04, 0x05, // RES value
				0x00, 0x00, 0x00, // Padding
			},
			expectedAttrs: map[EapAkaPrimeAttrType][]byte{
				AT_RES: {0x01, 0x02, 0x03, 0x04, 0x05},
			},
			expectErr: false,
		},
		{
			name: "Invalid attribute length",
			rawData: []byte{
				byte(EapTypeAkaPrime),     // EAP-AKA' type
				byte(SubtypeAkaChallenge), // Subtype
				0x00, 0x00,                // Reserved
				0x01, 0x02, 0x00, 0x00, // AT_RAND with invalid length
			},
			expectErr: true,
		},
		{
			name: "Invalid attribute value",
			rawData: []byte{
				byte(EapTypeAkaPrime),     // EAP-AKA' type
				byte(SubtypeAkaChallenge), // Subtype
				0x00, 0x00,                // Reserved
				0x01, 0x05, 0x00, 0x00, // AT_RAND header (type=1, length=5)
				// Missing AT_RAND value
			},
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			eapAka := new(EapAkaPrime)
			err := eapAka.Unmarshal(tc.rawData)

			if tc.expectErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			// Verify all expected attributes
			for attrType, expectedValue := range tc.expectedAttrs {
				attr, attrErr := eapAka.GetAttr(attrType)
				require.NoError(t, attrErr)
				require.Equal(t, expectedValue, attr.GetValue())
			}

			// Verify no extra attributes exist
			for _, attr := range eapAka.attributes {
				_, exists := tc.expectedAttrs[attr.GetAttrType()]
				require.True(t, exists, "Unexpected attribute type: %d", attr.GetAttrType())
			}
		})
	}
}
