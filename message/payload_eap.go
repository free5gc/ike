package message

import (
	eap_message "github.com/free5gc/ike/eap"
)

var _ IKEPayload = &PayloadEap{}

type PayloadEap struct {
	*eap_message.EAP
}

func (p *PayloadEap) Type() IkePayloadType { return TypeEAP }

func (p *PayloadEap) Marshal() ([]byte, error) {
	return p.EAP.Marshal()
}

func (p *PayloadEap) Unmarshal(data []byte) error {
	return p.EAP.Unmarshal(data)
}

func NewPayloadEap() *PayloadEap {
	return &PayloadEap{
		EAP: new(eap_message.EAP),
	}
}
