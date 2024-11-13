package message

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	validTSRIPv4 = TrafficSelectorResponder{
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
	}
	validTSRIPv4Byte = []byte{
		0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x10,
		0x00, 0x00, 0xff, 0xff, 0x0a, 0x00, 0x00, 0x01,
		0x0a, 0x00, 0x00, 0x01,
	}

	validTSRIPv6 = TrafficSelectorResponder{
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
	}

	validTSRIPv6Byte = []byte{
		0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x28,
		0x00, 0x00, 0xff, 0xff, 0xb8, 0x46, 0xd2, 0x47,
		0xcf, 0x84, 0xf2, 0x89, 0xcf, 0x7e, 0xce, 0xe6,
		0x6d, 0xb2, 0x1f, 0xc4, 0xb8, 0x46, 0xd2, 0x47,
		0xcf, 0x84, 0xf2, 0x89, 0xcf, 0x7e, 0xce, 0xe6,
		0x6d, 0xb2, 0x1f, 0xc4,
	}
)

func TestTrafficSelectorResponderMarshal(t *testing.T) {
	testcases := []struct {
		description string
		tsi         TrafficSelectorResponder
		expMarshal  []byte
		expErr      bool
	}{
		{
			description: "Contains no traffic selector for marshaling message",
			tsi:         TrafficSelectorResponder{},
			expErr:      true,
		},
		{
			description: "Unsupported traffic selector type",
			tsi: TrafficSelectorResponder{
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
			tsi: TrafficSelectorResponder{
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
			tsi: TrafficSelectorResponder{
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
			tsi:         validTSRIPv4,
			expMarshal:  validTSRIPv4Byte,
			expErr:      false,
		},
		{
			description: "TrafficSelectorResponder Marshal IPv6",
			tsi:         validTSRIPv6,
			expMarshal:  validTSRIPv6Byte,
			expErr:      false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.tsi.Marshal()
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, result)
			}
		})
	}
}

func TestTrafficSelectorResponderUnmarshal(t *testing.T) {
	testcases := []struct {
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
			description: "TrafficSelectorResponder Unmarshal IPv4",
			b:           validTSRIPv4Byte,
			expMarshal:  validTSRIPv4,
			expErr:      false,
		},
		{
			description: "TrafficSelectorResponder Unmarshal IPv6",
			b:           validTSRIPv6Byte,
			expMarshal:  validTSRIPv6,
			expErr:      false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var tsi TrafficSelectorResponder
			err := tsi.Unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, tsi)
			}
		})
	}
}
