package message

var _ IKEPayload = &Nonce{}

type Nonce struct {
	NonceData []byte
}

func (nonce *Nonce) Type() IKEPayloadType { return TypeNiNr }

func (nonce *Nonce) marshal() ([]byte, error) {
	nonceData := make([]byte, 0)
	nonceData = append(nonceData, nonce.NonceData...)
	return nonceData, nil
}

func (nonce *Nonce) unmarshal(b []byte) error {
	if len(b) > 0 {
		nonce.NonceData = append(nonce.NonceData, b...)
	}
	return nil
}
