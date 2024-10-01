package message

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewAndMarshalIKEHeader(t *testing.T) {
	ikeHdr := NewHeader(
		0x000000000006f708, 0xc9e2e31f8b64053d, IKE_AUTH,
		false, true, 0x03, uint8(NoNext), nil,
	)
	require.Equal(t, &IKEHeader{
		InitiatorSPI: 0x000000000006f708,
		ResponderSPI: 0xc9e2e31f8b64053d,
		MajorVersion: 2,
		MinorVersion: 0,
		ExchangeType: IKE_AUTH,
		Flags:        InitiatorBitCheck,
		MessageID:    0x03,
		NextPayload:  uint8(NoNext),
	}, ikeHdr)
	require.True(t, ikeHdr.IsInitiator())
	require.False(t, ikeHdr.IsResponse())

	b, err := ikeHdr.Marshal()
	require.NoError(t, err)
	require.Equal(t, []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0xf7, 0x08,
		0xc9, 0xe2, 0xe3, 0x1f, 0x8b, 0x64, 0x05, 0x3d,
		0x00, 0x20, 0x23, 0x08, 0x00, 0x00, 0x00, 0x03,
		0x00, 0x00, 0x00, 0x1c,
	}, b)
}

func TestParseIKEHeader(t *testing.T) {
	ikeHdr, err := ParseHeader(
		[]byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0xf7, 0x08,
			0xc9, 0xe2, 0xe3, 0x1f, 0x8b, 0x64, 0x05, 0x3d,
			0x00, 0x20, 0x23, 0x08, 0x00, 0x00, 0x00, 0x03,
			0x00, 0x00, 0x00, 0x1c,
		},
	)
	require.NoError(t, err)

	require.Equal(t, &IKEHeader{
		InitiatorSPI: 0x000000000006f708,
		ResponderSPI: 0xc9e2e31f8b64053d,
		MajorVersion: 2,
		MinorVersion: 0,
		ExchangeType: IKE_AUTH,
		Flags:        InitiatorBitCheck,
		MessageID:    0x03,
		NextPayload:  uint8(NoNext),
		PayloadBytes: []byte{},
	}, ikeHdr)
	require.True(t, ikeHdr.IsInitiator())
	require.False(t, ikeHdr.IsResponse())
}
