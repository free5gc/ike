package eap

import (
	"bytes"
	"context"
	"crypto/tls"
	"testing"
	"time"
)

// clientExportForTest derives keying material on the client side using the
// identical version-dependent label/context that DeriveTtlsKeys uses on the
// server side, so tests can assert both ends produce the same MSK (RFC 5281
// requires this symmetry).
func clientExportForTest(cs tls.ConnectionState) ([]byte, error) {
	var label string
	var context []byte
	if cs.Version == tls.VersionTLS13 {
		label = "EXPORTER_EAP_TLS_Key_Material"
		context = []byte{21}
	} else {
		label = "ttls keying material"
		context = nil
	}
	return cs.ExportKeyingMaterial(label, context, 128)
}

// establishBridgeSession drives a real tls.Client against the bridge to
// completion using the given client TLS config, and returns the bridge and
// the client's final ConnectionState (for the symmetry cross-check).
func establishBridgeSession(
	t *testing.T, serverCfg *tls.Config, clientCfg *tls.Config,
) (*tlsBridge, tls.ConnectionState) {
	t.Helper()
	bridge := newTLSBridge(serverCfg)
	t.Cleanup(func() {
		if err := bridge.close(); err != nil {
			t.Logf("bridge close: %v", err)
		}
	})
	clientConn, serverFeed := newMemConnPair()
	client := tls.Client(clientConn, clientCfg)

	done := make(chan error, 1)
	go func() { done <- client.HandshakeContext(context.Background()) }()

	shuttle(t, bridge, serverFeed, done)

	waitDeadline := time.After(time.Second)
	for !bridge.handshakeDone() {
		select {
		case <-waitDeadline:
			t.Fatal("bridge did not observe handshake completion")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if err := bridge.handshakeErr(); err != nil {
		t.Fatalf("bridge handshake failed: %v", err)
	}

	return bridge, client.ConnectionState()
}

func TestDeriveTtlsKeysLengthsAndPMK(t *testing.T) {
	tests := []struct {
		name    string
		version uint16
	}{
		{"TLS1.2", tls.VersionTLS12},
		{"TLS1.3", tls.VersionTLS13},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverCfg := testTLSServerConfig(t)
			serverCfg.MinVersion = tt.version
			serverCfg.MaxVersion = tt.version

			clientCfg := testTLSClientConfig(t, serverCfg)
			clientCfg.MinVersion = tt.version
			clientCfg.MaxVersion = tt.version

			bridge, clientCS := establishBridgeSession(t, serverCfg, clientCfg)

			if bridge.connState().Version != tt.version {
				t.Fatalf("negotiated version = %x, want %x", bridge.connState().Version, tt.version)
			}

			keys, err := DeriveTtlsKeys(bridge.connState())
			if err != nil {
				t.Fatalf("DeriveTtlsKeys: %v", err)
			}
			if len(keys.MSK) != 64 || len(keys.EMSK) != 64 {
				t.Fatalf("MSK/EMSK len = %d/%d, want 64/64", len(keys.MSK), len(keys.EMSK))
			}
			if len(keys.PMK()) != 32 {
				t.Fatalf("PMK len = %d, want 32", len(keys.PMK()))
			}

			// Symmetry cross-check: deriving on the client side with the same
			// label/context must yield the identical MSK (RFC 5281 requires
			// both ends derive the same MSK).
			clientKM, err := clientExportForTest(clientCS)
			if err != nil {
				t.Fatalf("client export: %v", err)
			}
			if !bytes.Equal(clientKM[:64], keys.MSK) {
				t.Fatal("server MSK != client-derived MSK (label/context mismatch)")
			}
		})
	}
}

func TestPMKIsACopy(t *testing.T) {
	k := &TtlsKeys{MSK: make([]byte, 64)}
	k.PMK()[0] = 0xff
	if k.MSK[0] != 0 {
		t.Fatal("mutating PMK() result changed MSK")
	}
}

// TestDeriveTtlsKeysLabelHasTeeth: the symmetry cross-check above derives the
// client side with its own copy of the label and context, which only proves
// the two sides agree. It would prove nothing if the exporter ignored those
// inputs, so pin that down here: a different label, and for TLS 1.3 a
// different context, must both change the keying material. Whether the label
// itself is the one the specification names still has to be read off
// RFC 5281 Section 8 and RFC 9427 Section 2.1 by a human.
func TestDeriveTtlsKeysLabelHasTeeth(t *testing.T) {
	for _, tt := range []struct {
		name    string
		version uint16
	}{
		{"TLS1.2", tls.VersionTLS12},
		{"TLS1.3", tls.VersionTLS13},
	} {
		t.Run(tt.name, func(t *testing.T) {
			serverCfg := testTLSServerConfig(t)
			serverCfg.MinVersion = tt.version
			serverCfg.MaxVersion = tt.version
			clientCfg := testTLSClientConfig(t, serverCfg)
			clientCfg.MinVersion = tt.version
			clientCfg.MaxVersion = tt.version

			bridge, _ := establishBridgeSession(t, serverCfg, clientCfg)
			cs := bridge.connState()

			keys, err := DeriveTtlsKeys(cs)
			if err != nil {
				t.Fatalf("DeriveTtlsKeys: %v", err)
			}

			otherLabel, err := cs.ExportKeyingMaterial("not the ttls label", nil, 128)
			if err != nil {
				t.Fatalf("export with another label: %v", err)
			}
			if bytes.Equal(otherLabel[:64], keys.MSK) {
				t.Fatal("changing the exporter label left the MSK unchanged")
			}

			if tt.version != tls.VersionTLS13 {
				return
			}
			otherContext, err := cs.ExportKeyingMaterial(
				"EXPORTER_EAP_TLS_Key_Material", []byte{byte(EapTypeTtls) + 1}, 128)
			if err != nil {
				t.Fatalf("export with another context: %v", err)
			}
			if bytes.Equal(otherContext[:64], keys.MSK) {
				t.Fatal("changing the exporter context left the MSK unchanged")
			}
		})
	}
}
