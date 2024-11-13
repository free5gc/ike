package message

var _ IKEPayload = &Nonce{}

type Nonce struct {
	NonceData []byte
}

func (nonce *Nonce) Type() IkePayloadType { return TypeNiNr }

func (nonce *Nonce) Marshal() ([]byte, error) {
	nonceData := make([]byte, 0)
	nonceData = append(nonceData, nonce.NonceData...)
	return nonceData, nil
}

func (nonce *Nonce) Unmarshal(b []byte) error {
	if len(b) > 0 {
		nonce.NonceData = append(nonce.NonceData, b...)
	}
	return nil
}
