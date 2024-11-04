package message

import (
	"encoding/binary"

	"github.com/pkg/errors"

	ike_types "github.com/free5gc/ike/types"
)

var _ IKEPayload = &TrafficSelectorResponder{}

type TrafficSelectorResponder struct {
	TrafficSelectors IndividualTrafficSelectorContainer
}

func (trafficSelector *TrafficSelectorResponder) Type() ike_types.IkePayloadType {
	return ike_types.TypeTSr
}

func (trafficSelector *TrafficSelectorResponder) Marshal() ([]byte, error) {
	if len(trafficSelector.TrafficSelectors) > 0 {
		trafficSelectorData := make([]byte, 4)
		selectorCount := len(trafficSelector.TrafficSelectors)

		if selectorCount > 0xFF {
			return nil, errors.Errorf("TrafficSelector: too many traffic selectors: %d", selectorCount)
		}

		trafficSelectorData[0] = uint8(selectorCount)

		for _, individualTrafficSelector := range trafficSelector.TrafficSelectors {
			if individualTrafficSelector.TSType == ike_types.TS_IPV4_ADDR_RANGE {
				// Address length checking
				if len(individualTrafficSelector.StartAddress) != 4 {
					return nil, errors.Errorf("TrafficSelector: Start IPv4 address length is not correct")
				}
				if len(individualTrafficSelector.EndAddress) != 4 {
					return nil, errors.Errorf("TrafficSelector: End IPv4 address length is not correct")
				}

				individualTrafficSelectorData := make([]byte, 8)

				individualTrafficSelectorData[0] = individualTrafficSelector.TSType
				individualTrafficSelectorData[1] = individualTrafficSelector.IPProtocolID
				binary.BigEndian.PutUint16(individualTrafficSelectorData[4:6], individualTrafficSelector.StartPort)
				binary.BigEndian.PutUint16(individualTrafficSelectorData[6:8], individualTrafficSelector.EndPort)

				individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.StartAddress...)
				individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.EndAddress...)

				dataLen := len(individualTrafficSelectorData)
				if dataLen > 0xFFFF {
					return nil, errors.Errorf("TrafficSelector: individualTrafficSelectorData length exceeds uint16 "+
						"maximum value: %v", dataLen)
				}
				binary.BigEndian.PutUint16(individualTrafficSelectorData[2:4], uint16(dataLen))

				trafficSelectorData = append(trafficSelectorData, individualTrafficSelectorData...)
			} else if individualTrafficSelector.TSType == ike_types.TS_IPV6_ADDR_RANGE {
				// Address length checking
				if len(individualTrafficSelector.StartAddress) != 16 {
					return nil, errors.Errorf("TrafficSelector: Start IPv6 address length is not correct")
				}
				if len(individualTrafficSelector.EndAddress) != 16 {
					return nil, errors.Errorf("TrafficSelector: End IPv6 address length is not correct")
				}

				individualTrafficSelectorData := make([]byte, 8)

				individualTrafficSelectorData[0] = individualTrafficSelector.TSType
				individualTrafficSelectorData[1] = individualTrafficSelector.IPProtocolID
				binary.BigEndian.PutUint16(individualTrafficSelectorData[4:6], individualTrafficSelector.StartPort)
				binary.BigEndian.PutUint16(individualTrafficSelectorData[6:8], individualTrafficSelector.EndPort)

				individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.StartAddress...)
				individualTrafficSelectorData = append(individualTrafficSelectorData, individualTrafficSelector.EndAddress...)

				dataLen := len(individualTrafficSelectorData)
				if dataLen > 0xFFFF {
					return nil, errors.Errorf("TrafficSelector: individualTrafficSelectorData length exceeds uint16 "+
						"maximum value: %v", dataLen)
				}
				binary.BigEndian.PutUint16(individualTrafficSelectorData[2:4], uint16(dataLen))

				trafficSelectorData = append(trafficSelectorData, individualTrafficSelectorData...)
			} else {
				return nil, errors.Errorf("TrafficSelector: Unsupported traffic selector type")
			}
		}

		return trafficSelectorData, nil
	} else {
		return nil, errors.Errorf("TrafficSelector: Contains no traffic selector for marshaling message")
	}
}

func (trafficSelector *TrafficSelectorResponder) Unmarshal(b []byte) error {
	if len(b) > 0 {
		// bounds checking
		if len(b) < 4 {
			return errors.Errorf("TrafficSelector: No sufficient bytes to get number of traffic selector in header")
		}

		numberOfSPI := b[0]

		b = b[4:]
		for ; numberOfSPI > 0; numberOfSPI-- {
			// bounds checking
			if len(b) < 4 {
				return errors.Errorf(
					"TrafficSelector: No sufficient bytes to decode next individual traffic selector length in header")
			}
			trafficSelectorType := b[0]
			if trafficSelectorType == ike_types.TS_IPV4_ADDR_RANGE {
				selectorLength := binary.BigEndian.Uint16(b[2:4])
				if selectorLength != 16 {
					return errors.Errorf("TrafficSelector: " +
						"A TS_IPV4_ADDR_RANGE type traffic selector should has length 16 bytes")
				}
				if len(b) < int(selectorLength) {
					return errors.Errorf("TrafficSelector: " +
						"No sufficient bytes to decode next individual traffic selector")
				}

				individualTrafficSelector := &IndividualTrafficSelector{}

				individualTrafficSelector.TSType = b[0]
				individualTrafficSelector.IPProtocolID = b[1]
				individualTrafficSelector.StartPort = binary.BigEndian.Uint16(b[4:6])
				individualTrafficSelector.EndPort = binary.BigEndian.Uint16(b[6:8])

				individualTrafficSelector.StartAddress = append(individualTrafficSelector.StartAddress, b[8:12]...)
				individualTrafficSelector.EndAddress = append(individualTrafficSelector.EndAddress, b[12:16]...)

				trafficSelector.TrafficSelectors = append(trafficSelector.TrafficSelectors, individualTrafficSelector)

				b = b[16:]
			} else if trafficSelectorType == ike_types.TS_IPV6_ADDR_RANGE {
				selectorLength := binary.BigEndian.Uint16(b[2:4])
				if selectorLength != 40 {
					return errors.Errorf("TrafficSelector: " +
						"A TS_IPV6_ADDR_RANGE type traffic selector should has length 40 bytes")
				}
				if len(b) < int(selectorLength) {
					return errors.Errorf("TrafficSelector: " +
						"No sufficient bytes to decode next individual traffic selector")
				}

				individualTrafficSelector := &IndividualTrafficSelector{}

				individualTrafficSelector.TSType = b[0]
				individualTrafficSelector.IPProtocolID = b[1]
				individualTrafficSelector.StartPort = binary.BigEndian.Uint16(b[4:6])
				individualTrafficSelector.EndPort = binary.BigEndian.Uint16(b[6:8])

				individualTrafficSelector.StartAddress = append(individualTrafficSelector.StartAddress, b[8:24]...)
				individualTrafficSelector.EndAddress = append(individualTrafficSelector.EndAddress, b[24:40]...)

				trafficSelector.TrafficSelectors = append(trafficSelector.TrafficSelectors, individualTrafficSelector)

				b = b[40:]
			} else {
				return errors.Errorf("TrafficSelector: Unsupported traffic selector type")
			}
		}
	}

	return nil
}
