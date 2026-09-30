package eap

import (
	"bytes"
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
			name:      "Set AT_KDF_INPUT max length",
			attrType:  AT_KDF_INPUT,
			value:     make([]byte, 1016), // 255*4 - 4 header bytes
			expectErr: false,
		},
		{
			name:      "Set AT_KDF_INPUT too long",
			attrType:  AT_KDF_INPUT,
			value:     make([]byte, 1017),
			expectErr: true,
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
		{
			name:      "Set AT_NOTIFICATION with valid length",
			attrType:  AT_NOTIFICATION,
			value:     []byte{0x12, 0x34},
			expectErr: false,
		},
		{
			name:      "Set AT_NOTIFICATION with invalid length",
			attrType:  AT_NOTIFICATION,
			value:     []byte{0x12},
			expectErr: true,
		},
		{
			name:     "Set AT_AUTS",
			attrType: AT_AUTS,
			value: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
			},
			expectErr: false,
		},
		{
			name:      "Set AT_AUTS with invalid length",
			attrType:  AT_AUTS,
			value:     []byte{0x01, 0x02, 0x03},
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
			case AT_NOTIFICATION:
				require.Equal(t, uint8(1), attr.length)
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
			expectedReserved: uint16(len("test.free5gc.org")),
		},
		{
			name:             "AT_KDF_INPUT max length",
			attrType:         AT_KDF_INPUT,
			value:            make([]byte, 1016),
			expectedLen:      255,
			expectedReserved: 1016,
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
				0x00, 0x0b, // AT_KDF_INPUT reserved (11 bytes)
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
		{
			name:    "AT_NOTIFICATION basic",
			subType: SubtypeAkaNotification,
			attrs: map[EapAkaPrimeAttrType][]byte{
				AT_NOTIFICATION: {0x12, 0x34},
			},
			expectedResult: []byte{
				byte(EapTypeAkaPrime),
				byte(SubtypeAkaNotification),
				0x00, 0x00,
				0x0c, 0x01, 0x12, 0x34, // AT_NOTIFICATION (type=12, length=1, value=0x12 0x34)
			},
			expectErr: false,
		},
		{
			name:    "AT_AUTS basic",
			subType: SubtypeAkaChallenge,
			attrs: map[EapAkaPrimeAttrType][]byte{
				AT_AUTS: {
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
				},
			},
			expectedResult: []byte{
				byte(EapTypeAkaPrime),     // EAP-AKA' type
				byte(SubtypeAkaChallenge), // Subtype
				0x00, 0x00,                // Reserved
				0x04, 0x04, // AT_AUTS type=4, length=4
				// 14 bytes AUTS
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
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
				0x00, 0x0b, // AT_KDF_INPUT reserved (11 bytes)
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
		{
			name: "AT_NOTIFICATION basic",
			rawData: []byte{
				byte(EapTypeAkaPrime),
				byte(SubtypeAkaNotification),
				0x00, 0x00,
				0x0c, 0x01, 0x12, 0x34, // AT_NOTIFICATION (type=12, length=1, value=0x12 0x34)
			},
			expectedAttrs: map[EapAkaPrimeAttrType][]byte{
				AT_NOTIFICATION: {0x12, 0x34},
			},
			expectErr: false,
		},
		{
			name: "AT_AUTS basic",
			rawData: []byte{
				byte(EapTypeAkaPrime),
				byte(SubtypeAkaChallenge),
				0x00, 0x00,
				0x04, 0x04, // AT_AUTS type=4, length=4
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
			},
			expectedAttrs: map[EapAkaPrimeAttrType][]byte{
				AT_AUTS: {
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
				},
			},
			expectErr: false,
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

func TestEapAkaPrimeKdfInputLongNameRoundTrip(t *testing.T) {
	// attr.length >= 64 (name >= 249 bytes) used to overflow uint8 in Unmarshal
	for _, n := range []int{248, 249, 300, 1016} {
		name := bytes.Repeat([]byte{'a'}, n)
		m := NewEapAkaPrime(SubtypeAkaChallenge)
		require.NoError(t, m.SetAttr(AT_KDF_INPUT, name))
		raw, err := m.Marshal()
		require.NoError(t, err)

		var got EapAkaPrime
		require.NoError(t, got.Unmarshal(raw), "n=%d", n)
		attr, err := got.GetAttr(AT_KDF_INPUT)
		require.NoError(t, err)
		require.Equal(t, name, attr.GetValue(), "n=%d", n)
	}
}

func TestEapAkaPrimeUnmarshalValueLengthExceedsAttr(t *testing.T) {
	testCases := []struct {
		name string
		raw  []byte
	}{
		{
			name: "AT_KDF_INPUT",
			raw: []byte{
				byte(EapTypeAkaPrime), byte(SubtypeAkaChallenge), 0x00, 0x00,
				0x17, 0x02, 0x00, 0x05, // length=2 (8 bytes) but claims 5-byte name
				'a', 'b', 'c', 'd',
			},
		},
		{
			name: "AT_RES",
			raw: []byte{
				byte(EapTypeAkaPrime), byte(SubtypeAkaChallenge), 0x00, 0x00,
				0x03, 0x02, 0x00, 0x40, // length=2 (8 bytes) but claims 64-bit RES
				0x01, 0x02, 0x03, 0x04,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var got EapAkaPrime
			require.ErrorContains(t, got.Unmarshal(tc.raw), "exceeds attribute length")
		})
	}
}

func TestEapAkaPrimePaddingRoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		raw  []byte
	}{
		{
			name: "AT_KDF_INPUT 11-byte name",
			raw: []byte{
				byte(EapTypeAkaPrime), byte(SubtypeAkaIdentity), 0x00, 0x00,
				0x17, 0x04, 0x00, 0x0b, 'f', 'r', 'e', 'e', '5', 'g', 'c', '.', 'o', 'r', 'g', 0x00,
				0x18, 0x01, 0x00, 0x01,
			},
		},
		{
			name: "AT_RES 40 bits",
			raw: []byte{
				byte(EapTypeAkaPrime), byte(SubtypeAkaChallenge), 0x00, 0x00,
				0x03, 0x03, 0x00, 0x28, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x00, 0x00,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var m EapAkaPrime
			require.NoError(t, m.Unmarshal(tc.raw))
			out, err := m.Marshal()
			require.NoError(t, err)
			require.Equal(t, tc.raw, out)
		})
	}
}

func TestEapAkaPrimeSetAttrValueExcludesPadding(t *testing.T) {
	testCases := []struct {
		name     string
		attrType EapAkaPrimeAttrType
		value    []byte
		expected []byte
	}{
		{
			name:     "AT_KDF_INPUT 11-byte name",
			attrType: AT_KDF_INPUT,
			value:    []byte("free5gc.org"),
			expected: []byte{0x17, 0x04, 0x00, 0x0b, 'f', 'r', 'e', 'e', '5', 'g', 'c', '.', 'o', 'r', 'g', 0x00},
		},
		{
			name:     "AT_RES 40 bits",
			attrType: AT_RES,
			value:    []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expected: []byte{0x03, 0x03, 0x00, 0x28, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x00, 0x00},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewEapAkaPrime(SubtypeAkaChallenge)
			require.NoError(t, m.SetAttr(tc.attrType, tc.value))

			attr, err := m.GetAttr(tc.attrType)
			require.NoError(t, err)
			require.Equal(t, tc.value, attr.GetValue())

			out, err := m.Marshal()
			require.NoError(t, err)
			require.Equal(t, tc.expected, out[4:])
		})
	}
}

func TestEapAkaPrimeUnmarshalInvalidAttr(t *testing.T) {
	header := []byte{byte(EapTypeAkaPrime), byte(SubtypeAkaChallenge), 0x00, 0x00}
	testCases := []struct {
		name        string
		attr        []byte
		errContains string
	}{
		{
			name:        "AT_CHECKCODE length 0",
			attr:        []byte{0x86, 0x00, 0x00, 0x00},
			errContains: "exceeds attribute length",
		},
		{
			name:        "AT_CHECKCODE length 64 truncated",
			attr:        append([]byte{0x86, 0x40, 0x00, 0x00}, make([]byte, 20)...),
			errContains: "value length mismatch",
		},
		{
			name:        "AT_RES shorter than 32 bits",
			attr:        []byte{0x03, 0x02, 0x00, 0x18, 0x01, 0x02, 0x03, 0x00},
			errContains: "between 32 and 128 bits",
		},
		{
			name:        "AT_RES longer than 128 bits",
			attr:        append([]byte{0x03, 0x06, 0x00, 0x88}, make([]byte, 20)...),
			errContains: "between 32 and 128 bits",
		},
		{
			name:        "Unknown attribute length 0",
			attr:        []byte{0x87, 0x00, 0x00, 0x00},
			errContains: "exceeds attribute length",
		},
		{
			name: "Duplicate AT_MAC",
			attr: append(
				append([]byte{0x0b, 0x05, 0x00, 0x00}, make([]byte, 16)...),
				append([]byte{0x0b, 0x05, 0x00, 0x00}, make([]byte, 16)...)...,
			),
			errContains: "duplicate AT_MAC",
		},
		{
			name:        "Truncated attribute header",
			attr:        []byte{0x18},
			errContains: "incomplete attribute header",
		},
		{
			name:        "Unrecognized non-skippable attribute",
			attr:        []byte{0x7f, 0x01, 0x00, 0x00},
			errContains: "unrecognized non-skippable attribute type 127",
		},
		{
			name:        "AT_PADDING outside AT_ENCR_DATA",
			attr:        []byte{0x06, 0x01, 0x00, 0x00},
			errContains: "unrecognized non-skippable attribute type 6",
		},
		{
			name:        "Unknown attribute truncated",
			attr:        []byte{0x87, 0x02, 0x00, 0x00, 0x01},
			errContains: "value length mismatch",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			raw := append(append([]byte{}, header...), tc.attr...)
			var m EapAkaPrime
			require.ErrorContains(t, m.Unmarshal(raw), tc.errContains)
		})
	}
}

func TestEapAkaPrimeUnmarshalResNonByteAlignedBits(t *testing.T) {
	// 36-bit RES occupies 5 bytes (last 4 bits are zero padding)
	raw := []byte{
		byte(EapTypeAkaPrime), byte(SubtypeAkaChallenge), 0x00, 0x00,
		0x03, 0x03, 0x00, 0x24, 0x01, 0x02, 0x03, 0x04, 0x50, 0x00, 0x00, 0x00,
	}
	var m EapAkaPrime
	require.NoError(t, m.Unmarshal(raw))
	attr, err := m.GetAttr(AT_RES)
	require.NoError(t, err)
	require.Equal(t, []byte{0x01, 0x02, 0x03, 0x04, 0x50}, attr.GetValue())
}

func TestEapAkaPrimeRawRoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		raw  []byte
	}{
		{
			name: "Multiple AT_KDF",
			raw: []byte{
				byte(EapTypeAkaPrime), byte(SubtypeAkaChallenge), 0x00, 0x00,
				0x18, 0x01, 0x00, 0x02,
				0x18, 0x01, 0x00, 0x01,
			},
		},
		{
			name: "Unknown skippable AT_RESULT_IND",
			raw: []byte{
				byte(EapTypeAkaPrime), byte(SubtypeAkaChallenge), 0x00, 0x00,
				0x87, 0x01, 0x00, 0x00,
				0x18, 0x01, 0x00, 0x01,
			},
		},
		{
			name: "Non-skippable AT_ANY_ID_REQ",
			raw: []byte{
				byte(EapTypeAkaPrime), byte(SubtypeAkaChallenge), 0x00, 0x00,
				0x0d, 0x01, 0x00, 0x00,
				0x18, 0x01, 0x00, 0x01,
			},
		},
		{
			name: "Unknown attribute with value",
			raw: []byte{
				byte(EapTypeAkaPrime), byte(SubtypeAkaChallenge), 0x00, 0x00,
				0x0e, 0x03, 0x00, 0x05, 'a', 'l', 'i', 'c', 'e', 0x00, 0x00, 0x00, // AT_IDENTITY
				0x18, 0x01, 0x00, 0x01,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var m EapAkaPrime
			require.NoError(t, m.Unmarshal(tc.raw))

			attr, err := m.GetAttr(AT_KDF)
			require.NoError(t, err)
			require.Equal(t, []byte{0x00, 0x01}, attr.GetValue())

			out, err := m.Marshal()
			require.NoError(t, err)
			require.Equal(t, tc.raw, out)
		})
	}
}

func TestEapAkaPrimeSetAttrAfterUnmarshal(t *testing.T) {
	raw := []byte{
		byte(EapTypeAkaPrime), byte(SubtypeAkaChallenge), 0x00, 0x00,
		0x18, 0x01, 0x00, 0x02,
		0x18, 0x01, 0x00, 0x01,
		0x0b, 0x05, 0x00, 0x00,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	mac := bytes.Repeat([]byte{0xaa}, 16)

	t.Run("AT_MAC falls back to re-marshal", func(t *testing.T) {
		var m EapAkaPrime
		require.NoError(t, m.Unmarshal(raw))
		require.NoError(t, m.SetAttr(AT_MAC, mac))

		out, err := m.Marshal()
		require.NoError(t, err)
		// Re-marshaled in attribute type order; only the last AT_KDF is kept
		expected := append([]byte{
			byte(EapTypeAkaPrime), byte(SubtypeAkaChallenge), 0x00, 0x00,
			0x0b, 0x05, 0x00, 0x00,
		}, mac...)
		expected = append(expected, 0x18, 0x01, 0x00, 0x01)
		require.Equal(t, expected, out)
		// The caller's buffer must not be modified
		require.Equal(t, make([]byte, 16), raw[16:])
	})

	t.Run("Other attribute falls back to re-marshal", func(t *testing.T) {
		var m EapAkaPrime
		require.NoError(t, m.Unmarshal(raw))
		require.NoError(t, m.SetAttr(AT_KDF, []byte{0x00, 0x03}))

		out, err := m.Marshal()
		require.NoError(t, err)
		require.Equal(t, []byte{
			byte(EapTypeAkaPrime), byte(SubtypeAkaChallenge), 0x00, 0x00,
			0x0b, 0x05, 0x00, 0x00,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0x18, 0x01, 0x00, 0x03,
		}, out)
	})
}
