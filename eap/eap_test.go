package eap_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	eap_message "github.com/free5gc/ike/eap"
)

var (
	eapIdentity = eap_message.EAP{
		Code:       eap_message.EapCodeRequest,
		Identifier: 9,
		EapTypeData: &eap_message.EapIdentity{
			IdentityData: []byte{
				0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
				0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
				0xb8, 0x56, 0x81, 0x8a,
			},
		},
	}

	eapIdentityByte = []byte{
		0x01, 0x09, 0x00, 0x19, 0x01, 0x7d, 0x09,
		0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20, 0x56,
		0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
		0xb8, 0x56, 0x81, 0x8a,
	}

	eapNotification = eap_message.EAP{
		Code:       eap_message.EapCodeRequest,
		Identifier: 9,
		EapTypeData: &eap_message.EapNotification{
			NotificationData: []byte{
				0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
				0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
				0xb8, 0x56, 0x81, 0x8a,
			},
		},
	}

	eapNotificationByte = []byte{
		0x01, 0x09, 0x00, 0x19, 0x02, 0x7d, 0x09, 0x18,
		0x42, 0x60, 0x9c, 0x9e, 0x20, 0x56, 0x9f, 0xc0,
		0x39, 0xda, 0x3f, 0x22, 0x2a, 0xb8, 0x56, 0x81,
		0x8a,
	}

	eapNak = eap_message.EAP{
		Code:       eap_message.EapCodeRequest,
		Identifier: 9,
		EapTypeData: &eap_message.EapNak{
			NakData: []byte{
				0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
				0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
				0xb8, 0x56, 0x81, 0x8a,
			},
		},
	}

	eapNakByte = []byte{
		0x01, 0x09, 0x00, 0x19, 0x03, 0x7d, 0x09, 0x18,
		0x42, 0x60, 0x9c, 0x9e, 0x20, 0x56, 0x9f, 0xc0,
		0x39, 0xda, 0x3f, 0x22, 0x2a, 0xb8, 0x56, 0x81,
		0x8a,
	}

	eapExpanded = eap_message.EAP{
		Code:       eap_message.EapCodeRequest,
		Identifier: 9,
		EapTypeData: &eap_message.EapExpanded{
			VendorID:   eap_message.VendorId3GPP,
			VendorType: eap_message.VendorTypeEAP5G,
			VendorData: []byte{
				0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
				0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
				0xb8, 0x56, 0x81, 0x8a,
			},
		},
	}

	eapExpandedByte = []byte{
		0x01, 0x09, 0x00, 0x20, 0xfe, 0x00, 0x28, 0xaf,
		0x00, 0x00, 0x00, 0x03, 0x7d, 0x09, 0x18, 0x42,
		0x60, 0x9c, 0x9e, 0x20, 0x56, 0x9f, 0xc0, 0x39,
		0xda, 0x3f, 0x22, 0x2a, 0xb8, 0x56, 0x81, 0x8a,
	}

	eapMD5 = eap_message.EAP{
		Code:       eap_message.EapCodeRequest,
		Identifier: 9,
		EapTypeData: &eap_message.EapMD5{
			ValueSize: eap_message.EapMD5ChallengeSize,
			Value:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			Name:      "testuser",
		},
	}
	eapMD5Byte = append(
		[]byte{
			0x01,       // Code
			0x09,       // Identifier
			0x00, 0x1e, // Length (30 bytes)
			0x04, 0x10, // Type and ValueSize
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		},
		[]byte("testuser")...,
	)
)

func TestEapMarshal(t *testing.T) {
	testcases := []struct {
		description string
		eap         eap_message.EAP
		expMarshal  []byte
		expErr      bool
	}{
		{
			description: "EAP identity is empty",
			eap: eap_message.EAP{
				Code:       eap_message.EapCodeRequest,
				Identifier: 9,
				EapTypeData: &eap_message.EapIdentity{
					IdentityData: nil,
				},
			},
			expErr: true,
		},
		{
			description: "EapIdentity marshal",
			eap:         eapIdentity,
			expMarshal:  eapIdentityByte,
			expErr:      false,
		},
		{
			description: "EAP notification is empty",
			eap: eap_message.EAP{
				Code:       eap_message.EapCodeRequest,
				Identifier: 9,
				EapTypeData: &eap_message.EapNotification{
					NotificationData: nil,
				},
			},
			expErr: true,
		},
		{
			description: "EapNotification marshal",
			eap:         eapNotification,
			expMarshal:  eapNotificationByte,
			expErr:      false,
		},
		{
			description: "EAP nak is empty",
			eap: eap_message.EAP{
				Code:       eap_message.EapCodeRequest,
				Identifier: 9,
				EapTypeData: &eap_message.EapNak{
					NakData: nil,
				},
			},
			expErr: true,
		},
		{
			description: "EapNak marshal",
			eap:         eapNak,
			expMarshal:  eapNakByte,
			expErr:      false,
		},
		{
			description: "EapExpanded marshal",
			eap:         eapExpanded,
			expMarshal:  eapExpandedByte,
			expErr:      false,
		},
		{
			description: "EapMD5 marshal",
			eap:         eapMD5,
			expMarshal:  eapMD5Byte,
			expErr:      false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.eap.Marshal()
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, result)
			}
		})
	}
}

func TestEapUnmarshal(t *testing.T) {
	testcases := []struct {
		description string
		b           []byte
		expMarshal  eap_message.EAP
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
			description: "EapIdentity unmarshal",
			b:           eapIdentityByte,
			expMarshal:  eapIdentity,
			expErr:      false,
		},
		{
			description: "EapNotification unmarshal",
			b:           eapNotificationByte,
			expMarshal:  eapNotification,
			expErr:      false,
		},
		{
			description: "EapNak unmarshal",
			b:           eapNakByte,
			expMarshal:  eapNak,
			expErr:      false,
		},
		{
			description: "EapExpanded: No sufficient bytes to decode the EAP expanded type",
			b: []byte{
				0x01, 0x09, 0x00, 0x20, 0xfe, 0x00, 0x28,
			},
			expErr: true,
		},
		{
			description: "EapExpanded unmarshal",
			b:           eapExpandedByte,
			expMarshal:  eapExpanded,
			expErr:      false,
		},
		{
			description: "EapMD5 unmarshal",
			b:           eapMD5Byte,
			expMarshal:  eapMD5,
			expErr:      false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var eap eap_message.EAP
			err := eap.Unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, eap)
			}
		})
	}
}

func TestEapAkaMac(t *testing.T) {
	tcs := []struct {
		name         string
		eapID        uint8
		atRes        string
		key          string
		expectResult string
	}{
		{
			name:         "test case 1",
			eapID:        64,
			atRes:        "e2f5c0ab3685b3b4",
			key:          "7e28ba2f666944737f6c8a0a008e834895206a02725b5b4b925a399ae6f09cf0",
			expectResult: "fd69971493e2b7f873a06e72e2051e8a",
		},
		{
			name:         "test case 2",
			eapID:        2,
			atRes:        "1e4c99649c900fec",
			key:          "7ee97c273b07a773c29f670d2e688b2a70eb206963bd7d3d40a0eb18955133f8",
			expectResult: "66a5e7f1e0df7cb0043069ae5a9e181c",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			expectResult, err := hex.DecodeString(tc.expectResult)
			require.NoError(t, err)

			// Build test EAP packet
			eap := new(eap_message.EAP)
			eap.Code = eap_message.EapCodeResponse
			eap.Identifier = tc.eapID
			eap.EapTypeData = eap_message.NewEapAkaPrime(eap_message.SubtypeAkaChallenge)

			// Build EAP-AKA' packet
			eapAkaPrime := eap.EapTypeData.(*eap_message.EapAkaPrime)
			attrs := []struct {
				eapAkaPrimeAttrType eap_message.EapAkaPrimeAttrType
				value               string
			}{
				{
					eapAkaPrimeAttrType: eap_message.AT_RES,
					value:               tc.atRes,
				},
				{
					eapAkaPrimeAttrType: eap_message.AT_CHECKCODE,
					value:               "",
				},
			}

			var val []byte
			for i := 0; i < len(attrs); i++ {
				val, err = hex.DecodeString(attrs[i].value)
				require.NoError(t, err)

				err = eapAkaPrime.SetAttr(attrs[i].eapAkaPrimeAttrType, val)
				require.NoError(t, err)
			}

			key, err := hex.DecodeString(tc.key)
			require.NoError(t, err)

			mac, err := eap.CalcEapAkaPrimeAtMAC(key)
			require.NoError(t, err)

			require.Equal(t, expectResult, mac)

			err = eapAkaPrime.SetAttr(eap_message.AT_MAC, mac)
			require.NoError(t, err)
			_, err = eap.Marshal()
			require.NoError(t, err)
		})
	}
}

func TestEapAkaMacPreservesReceivedAttributeOrder(t *testing.T) {
	packet, err := hex.DecodeString(
		"02ab002c32010000" +
			"03030040c4532b691a62a48c" +
			"86010000" +
			"0b050000d5300e0989ee0bbd17d642b1f4abeeb6",
	)
	require.NoError(t, err)

	key, err := hex.DecodeString("36ba2ad66f240be3fc8e793f91d5d39953c07c45232b65b8e2f6cc5c06d3b9d0")
	require.NoError(t, err)

	var eap eap_message.EAP
	require.NoError(t, eap.Unmarshal(packet))

	mac, err := eap.CalcEapAkaPrimeAtMAC(key)
	require.NoError(t, err)
	require.Equal(t, "d5300e0989ee0bbd17d642b1f4abeeb6", hex.EncodeToString(mac))
}

func TestEapAkaMacKdfInputPadding(t *testing.T) {
	// AT_KDF_INPUT with an 11-byte name carries 1 padding byte, which must be
	// part of the MAC input.
	key := bytes.Repeat([]byte{0x11}, 32)
	packet := []byte{
		byte(eap_message.EapCodeRequest), 1, 0, 44,
		byte(eap_message.EapTypeAkaPrime), byte(eap_message.SubtypeAkaChallenge), 0, 0,
		0x17, 0x04, 0x00, 0x0b, 'f', 'r', 'e', 'e', '5', 'g', 'c', '.', 'o', 'r', 'g', 0x00,
		0x0b, 0x05, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	h := hmac.New(sha256.New, key)
	h.Write(packet)

	var eap eap_message.EAP
	require.NoError(t, eap.Unmarshal(packet))

	mac, err := eap.CalcEapAkaPrimeAtMAC(key)
	require.NoError(t, err)
	require.Equal(t, h.Sum(nil)[:16], mac)
}

func TestEapAkaMacRawAttributes(t *testing.T) {
	// Messages that cannot be reproduced from the attribute map: the MAC must
	// be computed over the received bytes with the AT_MAC value zeroed.
	key := bytes.Repeat([]byte{0x22}, 32)
	testCases := []struct {
		name   string
		length byte // EAP length: 8 header bytes + attrs + 20 bytes AT_MAC
		attrs  []byte
	}{
		{
			name:   "Multiple AT_KDF",
			length: 36,
			attrs: []byte{
				0x18, 0x01, 0x00, 0x02,
				0x18, 0x01, 0x00, 0x01,
			},
		},
		{
			name:   "Unknown skippable AT_RESULT_IND",
			length: 32,
			attrs:  []byte{0x87, 0x01, 0x00, 0x00},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			packet := []byte{
				byte(eap_message.EapCodeRequest), 1, 0, tc.length,
				byte(eap_message.EapTypeAkaPrime), byte(eap_message.SubtypeAkaChallenge), 0, 0,
			}
			packet = append(packet, tc.attrs...)
			packet = append(packet, 0x0b, 0x05, 0x00, 0x00)
			packet = append(packet, make([]byte, 16)...)

			h := hmac.New(sha256.New, key)
			h.Write(packet)

			// Put a non-zero MAC on the wire; it must be zeroed for the calculation
			received := append([]byte{}, packet...)
			copy(received[len(received)-16:], bytes.Repeat([]byte{0xff}, 16))

			var eap eap_message.EAP
			require.NoError(t, eap.Unmarshal(received))

			mac, err := eap.CalcEapAkaPrimeAtMAC(key)
			require.NoError(t, err)
			require.Equal(t, h.Sum(nil)[:16], mac)
		})
	}
}

func TestEapAkaMacKeepsReceivedMac(t *testing.T) {
	packet, err := hex.DecodeString(
		"02ab002c32010000" +
			"03030040c4532b691a62a48c" +
			"86010000" +
			"0b050000d5300e0989ee0bbd17d642b1f4abeeb6",
	)
	require.NoError(t, err)
	key, err := hex.DecodeString("36ba2ad66f240be3fc8e793f91d5d39953c07c45232b65b8e2f6cc5c06d3b9d0")
	require.NoError(t, err)

	var eap eap_message.EAP
	require.NoError(t, eap.Unmarshal(packet))
	_, err = eap.CalcEapAkaPrimeAtMAC(key)
	require.NoError(t, err)

	// CalcEapAkaPrimeAtMAC must not zero the received AT_MAC
	attr, err := eap.EapTypeData.(*eap_message.EapAkaPrime).GetAttr(eap_message.AT_MAC)
	require.NoError(t, err)
	require.Equal(t, "d5300e0989ee0bbd17d642b1f4abeeb6", hex.EncodeToString(attr.GetValue()))
	out, err := eap.Marshal()
	require.NoError(t, err)
	require.Equal(t, packet, out)
}

func TestEapAkaMacConstructedMessage(t *testing.T) {
	// A constructed message without AT_MAC: the MAC is calculated as if a
	// zeroed AT_MAC were present, and the message itself is left unchanged.
	key := bytes.Repeat([]byte{0x33}, 32)
	akaPrime := eap_message.NewEapAkaPrime(eap_message.SubtypeAkaChallenge)
	require.NoError(t, akaPrime.SetAttr(eap_message.AT_RES, []byte{1, 2, 3, 4}))
	eap := eap_message.EAP{Code: eap_message.EapCodeResponse, Identifier: 7, EapTypeData: akaPrime}

	mac, err := eap.CalcEapAkaPrimeAtMAC(key)
	require.NoError(t, err)

	_, err = akaPrime.GetAttr(eap_message.AT_MAC)
	require.Error(t, err)

	require.NoError(t, akaPrime.SetAttr(eap_message.AT_MAC, make([]byte, 16)))
	zeroed, err := eap.Marshal()
	require.NoError(t, err)
	h := hmac.New(sha256.New, key)
	h.Write(zeroed)
	require.Equal(t, h.Sum(nil)[:16], mac)
}
