package eap

import (
	"crypto/tls"

	"github.com/pkg/errors"
)

// TtlsKeys holds the MSK and EMSK derived from a completed EAP-TTLS tunnel.
type TtlsKeys struct {
	MSK  []byte // 64 bytes
	EMSK []byte // 64 bytes
}

// PMK returns a copy of the IEEE 802.11i Pairwise Master Key = MSK[0:32].
func (k *TtlsKeys) PMK() []byte { return append([]byte(nil), k.MSK[:32]...) }

// DeriveTtlsKeys derives 128 bytes of keying material per RFC 5281 §8,
// using the RFC 5705 exporter with version-dependent label/context, and
// splits it into MSK||EMSK. Matches hostapd eap_server_ttls.c.
func DeriveTtlsKeys(cs tls.ConnectionState) (*TtlsKeys, error) {
	var label string
	var context []byte
	if cs.Version == tls.VersionTLS13 {
		label = "EXPORTER_EAP_TLS_Key_Material"
		context = []byte{byte(EapTypeTtls)} // {21}
	} else {
		label = "ttls keying material"
		context = nil
	}
	km, err := cs.ExportKeyingMaterial(label, context, 128)
	if err != nil {
		// On TLS 1.2 this fails without Extended Master Secret (G8, RFC 7627).
		return nil, errors.Wrapf(err, "DeriveTtlsKeys: ExportKeyingMaterial failed (TLS %x)", cs.Version)
	}
	return &TtlsKeys{MSK: km[0:64], EMSK: km[64:128]}, nil
}
