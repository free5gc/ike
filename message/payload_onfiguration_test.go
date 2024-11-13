package message

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	validConfiguration = Configuration{
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
	}

	validConfigurationByte = []byte{
		0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x14,
		0x7d, 0x09, 0x18, 0x42, 0x60, 0x9c, 0x9e, 0x20,
		0x56, 0x9f, 0xc0, 0x39, 0xda, 0x3f, 0x22, 0x2a,
		0xb8, 0x56, 0x81, 0x8a,
	}
)

func TestConfigurationMarshal(t *testing.T) {
	testcases := []struct {
		description string
		cfg         Configuration
		expMarshal  []byte
	}{
		{
			description: "Configuration marshal",
			cfg:         validConfiguration,
			expMarshal:  validConfigurationByte,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			result, err := tc.cfg.Marshal()
			require.NoError(t, err)
			require.Equal(t, tc.expMarshal, result)
		})
	}
}

func TestConfigurationUnmarshal(t *testing.T) {
	testcases := []struct {
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
			b:           validConfigurationByte,
			expMarshal:  validConfiguration,
			expErr:      false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var cfg Configuration
			err := cfg.Unmarshal(tc.b)
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expMarshal, cfg)
			}
		})
	}
}
