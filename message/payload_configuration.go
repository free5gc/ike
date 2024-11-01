package message

import (
	"encoding/binary"

	"github.com/pkg/errors"

	ike_types "github.com/free5gc/ike/types"
)

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

func (configuration *Configuration) Type() ike_types.IkePayloadType { return ike_types.TypeCP }

func (configuration *Configuration) Marshal() ([]byte, error) {
	configurationData := make([]byte, 4)
	configurationData[0] = configuration.ConfigurationType

	for _, attribute := range configuration.ConfigurationAttribute {
		individualConfigurationAttributeData := make([]byte, 4)

		binary.BigEndian.PutUint16(individualConfigurationAttributeData[0:2], (attribute.Type & 0x7fff))
		attributeLen := len(attribute.Value)
		if attributeLen > 0xFFFF {
			return nil, errors.Errorf("Configuration: attribute value length exceeds uint16 limit: %d", attributeLen)
		}
		binary.BigEndian.PutUint16(individualConfigurationAttributeData[2:4], uint16(attributeLen))

		individualConfigurationAttributeData = append(individualConfigurationAttributeData, attribute.Value...)

		configurationData = append(configurationData, individualConfigurationAttributeData...)
	}
	return configurationData, nil
}

func (configuration *Configuration) Unmarshal(b []byte) error {
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
