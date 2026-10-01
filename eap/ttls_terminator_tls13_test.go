package eap

import (
	"context"
	"crypto/tls"
	"testing"
	"time"
)

// TestTerminatorAcceptsInnerDataSentWithFinished proves the terminator honors
// RFC 9427 Section 3: once the TLS session is established it MUST check for
// application data BEFORE starting another round trip. A TLS 1.3 peer is
// allowed to put its Finished flight and the tunneled PAP AVPs in a single
// EAP-TTLS packet -- Windows 11 does exactly that -- and the terminator must
// authenticate from that one packet instead of replying with an empty
// request the peer will not answer.
func TestTerminatorAcceptsInnerDataSentWithFinished(t *testing.T) {
	peer := newMergedFlightPeer(t, tls.VersionTLS13)

	step := peer.handshakeThenMergedFlight(testUserName, testPassword)

	if !step.Done || !step.CredentialsExtracted {
		t.Fatalf("merged Finished+AVP packet must yield credentials in one step,"+
			" got Done=%v CredentialsExtracted=%v (out %d bytes)",
			step.Done, step.CredentialsExtracted, len(step.OutTypeData))
	}
	if string(step.Cred.UserName) != testUserName || string(step.Cred.UserPassword) != testPassword {
		t.Fatalf("got name=%q pass=%q", step.Cred.UserName, step.Cred.UserPassword)
	}
	if step.Keys == nil || len(step.Keys.MSK) != 64 {
		t.Fatalf("keys not derived: %+v", step.Keys)
	}
}

// TestTerminatorAcceptsInnerDataInItsOwnPacket is a regression guard, not a
// new behavior: peers that send their inner AVPs in a separate packet --
// every TLS 1.2 peer, and TLS 1.3 peers such as wpa_supplicant -- must keep
// working now that the terminator probes for inner data after the
// handshake. It pins the TLS version explicitly so a future version cap
// cannot silently stop covering one of the two paths.
func TestTerminatorAcceptsInnerDataInItsOwnPacket(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version uint16
	}{
		{"TLS1.2", tls.VersionTLS12},
		{"TLS1.3", tls.VersionTLS13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srvCfg := testTLSServerConfig(t)
			srvCfg.MinVersion = tc.version
			srvCfg.MaxVersion = tc.version
			term := NewTerminator(srvCfg, 1000)

			start, err := term.Process(nil)
			if err != nil {
				t.Fatalf("start: %v", err)
			}

			cred, keys := runTtlsPeer(t, term, start, testUserName, testPassword, 5*time.Second)
			if string(cred.UserName) != testUserName || string(cred.UserPassword) != testPassword {
				t.Fatalf("got name=%q pass=%q", cred.UserName, cred.UserPassword)
			}
			if len(keys.MSK) != 64 {
				t.Fatalf("MSK len = %d, want 64", len(keys.MSK))
			}
			if got := term.bridge.connState().Version; got != tc.version {
				t.Fatalf("negotiated TLS version = 0x%04x, want 0x%04x", got, tc.version)
			}
		})
	}
}

// TestTerminatorReportsAwaitingInner proves the terminator tells its caller
// when the handshake has finished and the empty packet it is emitting is
// only a prompt for the peer's inner data. Without that signal the caller
// cannot log the one state a stalled authentication sits in -- a session
// that dies there leaves no trace at all, which is how the field failure
// stayed invisible in the TWIF logs.
func TestTerminatorReportsAwaitingInner(t *testing.T) {
	srvCfg := testTLSServerConfig(t)
	srvCfg.MinVersion = tls.VersionTLS13
	srvCfg.MaxVersion = tls.VersionTLS13
	term := NewTerminator(srvCfg, 1000)

	start, err := term.Process(nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if start.AwaitingInner {
		t.Fatal("TTLS-Start must not report AwaitingInner")
	}

	var awaited bool
	observe := func(step *TerminatorStep) {
		if step.AwaitingInner {
			awaited = true
			if step.Done {
				t.Fatal("AwaitingInner and Done are mutually exclusive")
			}
		}
	}
	cred, _ := runTtlsPeerObserved(t, term, start, testUserName, testPassword, 5*time.Second, observe)

	if string(cred.UserName) != testUserName {
		t.Fatalf("got name=%q", cred.UserName)
	}
	if !awaited {
		t.Fatal("no step reported AwaitingInner: the post-handshake prompt is unobservable")
	}
}

// mergedFlightPeer drives a real tls.Client against a Terminator while
// controlling EAP packetization, so a test can deliberately merge the
// client's Finished flight with its first application data record.
type mergedFlightPeer struct {
	t      *testing.T
	term   *Terminator
	client *tls.Conn
	feed   *feedConn
	hsDone chan error
}

func newMergedFlightPeer(t *testing.T, version uint16) *mergedFlightPeer {
	t.Helper()

	srvCfg := testTLSServerConfig(t)
	srvCfg.MinVersion = version
	srvCfg.MaxVersion = version

	clientCfg := testTLSClientConfig(t, srvCfg)
	clientCfg.MinVersion = version
	clientCfg.MaxVersion = version

	clientConn, feed := newMemConnPair()
	p := &mergedFlightPeer{
		t:      t,
		term:   NewTerminator(srvCfg, 4096), // MTU large enough to avoid fragmentation
		client: tls.Client(clientConn, clientCfg),
		feed:   feed,
		hsDone: make(chan error, 1),
	}
	go func() { p.hsDone <- p.client.HandshakeContext(context.Background()) }()
	return p
}

// handshakeThenMergedFlight runs the handshake up to the point where the
// client is about to send its final flight, writes the PAP AVPs before
// draining anything, and hands the terminator one packet holding both.
func (p *mergedFlightPeer) handshakeThenMergedFlight(username, password string) *TerminatorStep {
	p.t.Helper()

	step, err := p.term.Process(nil) // TTLS-Start
	if err != nil {
		p.t.Fatalf("start: %v", err)
	}

	// Drive handshake rounds until the client reports completion, feeding
	// each server flight to the client and each client flight back.
	for {
		var pkt EapTtls
		if err = pkt.Unmarshal(step.OutTypeData); err != nil {
			p.t.Fatalf("unmarshal server output: %v", err)
		}
		if len(pkt.TLSData) > 0 {
			if err = p.feed.writeToClient(pkt.TLSData); err != nil {
				p.t.Fatalf("writeToClient: %v", err)
			}
		}

		// Give the client a chance to finish off the flight we just fed
		// it. Only once it reports completion do we drain -- draining
		// earlier would let its Finished leave on its own, which is the
		// very packetization this test must NOT produce.
		if p.handshakeFinished(200 * time.Millisecond) {
			payload := append(
				encodeAVP(avpCodeUserName, true, []byte(username)),
				encodeAVP(avpCodeUserPassword, true, []byte(password))...)
			if _, err = p.client.Write(payload); err != nil {
				p.t.Fatalf("client write: %v", err)
			}
			merged := p.collect(2 * time.Second)
			p.requireMergedFlight(merged)
			return p.send(merged)
		}

		step = p.send(p.collect(2 * time.Second))
	}
}

// handshakeFinished reports whether the client's handshake completed within
// d. It fatals if the handshake failed.
func (p *mergedFlightPeer) handshakeFinished(d time.Duration) bool {
	p.t.Helper()
	select {
	case err := <-p.hsDone:
		if err != nil {
			p.t.Fatalf("client handshake: %v", err)
		}
		return true
	case <-time.After(d):
		return false
	}
}

// requireMergedFlight fails the test unless raw really carries the client's
// Finished AND a second application-data record (the AVPs) -- otherwise the
// test would silently degrade into the two-packet flow it is meant to
// exclude. TLS 1.3 clients emit ChangeCipherSpec (0x14) followed by two
// application-data records (0x17): the encrypted Finished, then the AVPs.
func (p *mergedFlightPeer) requireMergedFlight(raw []byte) {
	p.t.Helper()
	var appData int
	for rest := raw; len(rest) >= 5; {
		n := 5 + int(rest[3])<<8 + int(rest[4])
		if n > len(rest) {
			p.t.Fatalf("truncated TLS record in merged flight (%d bytes left, record claims %d)", len(rest), n)
		}
		if rest[0] == 0x17 {
			appData++
		}
		rest = rest[n:]
	}
	if appData < 2 {
		p.t.Fatalf("flight is not merged: want Finished plus AVP record, got %d application-data records in %d bytes",
			appData, len(raw))
	}
}

func (p *mergedFlightPeer) send(raw []byte) *TerminatorStep {
	p.t.Helper()
	pkt := &EapTtls{TLSData: raw}
	b, err := pkt.Marshal()
	if err != nil {
		p.t.Fatalf("marshal: %v", err)
	}
	step, err := p.term.Process(b)
	if err != nil {
		p.t.Fatalf("term.Process: %v", err)
	}
	return step
}

// collect drains client output, waiting up to d for the first byte and then
// settling briefly so records emitted back-to-back land in one batch.
func (p *mergedFlightPeer) collect(d time.Duration) []byte {
	p.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		b := p.feed.readFromClient()
		if len(b) == 0 {
			time.Sleep(time.Millisecond)
			continue
		}
		settle := time.Now().Add(50 * time.Millisecond)
		for time.Now().Before(settle) {
			if more := p.feed.readFromClient(); len(more) > 0 {
				b = append(b, more...)
				settle = time.Now().Add(50 * time.Millisecond)
			}
			time.Sleep(time.Millisecond)
		}
		return b
	}
	p.t.Fatalf("collect: no client bytes within %v", d)
	return nil
}
