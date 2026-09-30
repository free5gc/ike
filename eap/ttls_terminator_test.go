package eap

import (
	"bytes"
	"context"
	"crypto/tls"
	"strings"
	"testing"
	"time"
)

// TestTerminatorFullPapFlow drives a full EAP-TTLS authentication (TTLS-Start
// -> TLS handshake -> tunneled PAP AVPs) against a real tls.Client, using an
// MTU large enough that no fragmentation is needed.
func TestTerminatorFullPapFlow(t *testing.T) {
	srvCfg := testTLSServerConfig(t)
	term := NewTerminator(srvCfg, 1000)

	start, err := term.Process(nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if len(start.OutTypeData) < 2 || start.OutTypeData[1]&EapTlsFlagStart == 0 {
		t.Fatal("first packet must have Start flag")
	}

	cred, keys := runTtlsPeer(t, term, start, testUserName, testPassword, 5*time.Second)
	if string(cred.UserName) != testUserName || string(cred.UserPassword) != testPassword {
		t.Fatalf("got name=%q pass=%q", cred.UserName, cred.UserPassword)
	}
	if len(keys.MSK) != 64 {
		t.Fatalf("MSK len = %d, want 64", len(keys.MSK))
	}
	if len(keys.EMSK) != 64 {
		t.Fatalf("EMSK len = %d, want 64", len(keys.EMSK))
	}
}

// TestTerminatorFullPapFlowSmallMTU forces multi-fragment flights in BOTH
// directions (server handshake flight out, and the peer's own flights in),
// proving emitOutbound's fragmentation and Process's reassembly are correct,
// not just adequate for single-packet flows.
func TestTerminatorFullPapFlowSmallMTU(t *testing.T) {
	srvCfg := testTLSServerConfig(t)
	term := NewTerminator(srvCfg, 200)

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
}

// TestTerminatorCloseNilSafeBeforeProcess proves Close is safe to call on a
// Terminator that has never had Process called on it (no bridge exists yet).
func TestTerminatorCloseNilSafeBeforeProcess(t *testing.T) {
	term := NewTerminator(testTLSServerConfig(t), 1000)
	if err := term.Close(); err != nil {
		t.Fatalf("Close on a never-Processed Terminator returned %v, want nil", err)
	}
	// A nil *Terminator must also be safe (defensive, mirrors common Close
	// idioms elsewhere in the stdlib/ecosystem).
	var nilTerm *Terminator
	if err := nilTerm.Close(); err != nil {
		t.Fatalf("Close on a nil *Terminator returned %v, want nil", err)
	}
}

// TestTerminatorCloseAbandonedMidHandshakeDoesNotHang proves the leak fix:
// if a caller abandons an authentication mid-handshake (e.g. the peer
// vanished), Close reaps the bridge's background handshake goroutine
// instead of leaving it parked in engineConn.Read forever. It also proves
// Close is idempotent (safe to call twice).
func TestTerminatorCloseAbandonedMidHandshakeDoesNotHang(t *testing.T) {
	term := NewTerminator(testTLSServerConfig(t), 1000)

	// Start the handshake (creates the bridge) but never feed it a
	// ClientHello -- the peer "vanished". Before the fix, only the
	// Done path in Process called bridge.close(), so this
	// Terminator's bridge goroutine would stay blocked forever.
	if _, err := term.Process(nil); err != nil {
		t.Fatalf("start: %v", err)
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- term.Close() }()

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close on an abandoned mid-handshake Terminator returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return within 2s; bridge goroutine likely leaked")
	}

	// Idempotent: a second Close must also return promptly without error.
	closeAgainDone := make(chan error, 1)
	go func() { closeAgainDone <- term.Close() }()
	select {
	case err := <-closeAgainDone:
		if err != nil {
			t.Fatalf("second Close call returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second Close did not return within 2s")
	}
}

// runTtlsPeer is a test harness that plays the EAP-TTLS peer (supplicant)
// role: it drives a real tls.Client through the Terminator's Process calls
// (including EAP-layer fragmentation in both directions), completes the TLS
// handshake, then writes PAP inner AVPs (User-Name + User-Password) into the
// tunnel, looping term.Process until it reports Done. It returns the
// extracted credential and keys, failing the test on any error or timeout.
func runTtlsPeer(
	t *testing.T, term *Terminator, start *TerminatorStep, username, password string, timeout time.Duration,
) (*PapCredential, *TtlsKeys) {
	t.Helper()
	return runTtlsPeerObserved(t, term, start, username, password, timeout, nil)
}

// runTtlsPeerObserved is runTtlsPeer with a hook that sees every step the
// terminator produces, so a test can assert on intermediate steps and not
// just on the final credential.
func runTtlsPeerObserved(
	t *testing.T, term *Terminator, start *TerminatorStep, username, password string,
	timeout time.Duration, observe func(*TerminatorStep),
) (*PapCredential, *TtlsKeys) {
	t.Helper()
	both := func(c *tls.Conn) error {
		_, err := c.Write(append(
			encodeAVP(avpCodeUserName, true, []byte(username)),
			encodeAVP(avpCodeUserPassword, true, []byte(password))...))
		return err
	}
	return runTtlsPeerWriters(t, term, start, []func(*tls.Conn) error{both}, timeout, observe)
}

// runTtlsPeerWriters is runTtlsPeerObserved with the inner writes spelled out
// as a queue. Each writer runs when the handshake is done and the peer has no
// bytes of its own left to send, so one writer sends its AVPs in a single
// flight and several writers spread them over as many prompt/answer rounds.
func runTtlsPeerWriters(
	t *testing.T, term *Terminator, start *TerminatorStep, writers []func(*tls.Conn) error,
	timeout time.Duration, observe func(*TerminatorStep),
) (*PapCredential, *TtlsKeys) {
	t.Helper()
	if observe == nil {
		observe = func(*TerminatorStep) {}
	}
	observe(start)

	// term.cfg/term.mtu are accessed directly since this harness lives in
	// the same package -- it needs a client config that trusts the same
	// self-signed cert the terminator's server config presents, and a peer
	// MTU to fragment its own output at (using the terminator's own MTU
	// keeps both directions symmetric for the small-MTU test).
	clientCfg := testTLSClientConfig(t, term.cfg)
	clientConn, feed := newMemConnPair()
	client := tls.Client(clientConn, clientCfg)
	peerMTU := term.mtu

	hsDone := make(chan error, 1)
	go func() { hsDone <- client.HandshakeContext(context.Background()) }()

	writeDone := make(chan error, 1)
	handshakeChecked := false
	pending := writers

	deadline := time.Now().Add(timeout)

	// pendingToServer holds the remaining bytes of the client's own
	// outbound message currently being fragmented to the server. Symmetric
	// to Terminator.outPending: non-nil/non-empty means the terminator's
	// next reply is expected to just be its own fragment-continuation, not
	// something requiring us to fetch fresh client bytes.
	var pendingToServer []byte

	step := start
	for {
		if step.Done {
			if !step.CredentialsExtracted {
				t.Fatalf("terminator finished without extracting credentials")
			}
			return step.Cred, step.Keys
		}

		var pkt EapTtls
		if err := pkt.Unmarshal(step.OutTypeData); err != nil {
			t.Fatalf("unmarshal server output: %v", err)
		}
		// The underlying transport to the real tls.Client is a plain byte
		// stream (memConn), so fragment boundaries on the server->client
		// direction don't need to be preserved beyond delivering the bytes
		// in order -- the client's TLS engine just reads a continuous
		// stream regardless of how the server chopped it into EAP packets.
		if len(pkt.TLSData) > 0 {
			if err := feed.writeToClient(pkt.TLSData); err != nil {
				t.Fatalf("writeToClient: %v", err)
			}
		}

		var inTypeData []byte
		switch {
		case pkt.Flags&EapTlsFlagMoreFragments != 0:
			// Server sent a non-final fragment; ack it to request the next
			// one. No client bytes are consumed for this round.
			ack := &EapTtls{}
			out, err := ack.Marshal()
			if err != nil {
				t.Fatalf("marshal ack: %v", err)
			}
			inTypeData = out

		case len(pendingToServer) > 0:
			// Continue fragmenting out the client's in-flight message.
			inTypeData = nextClientFragment(t, &pendingToServer, peerMTU)

		default:
			raw := waitForClientBytes(
				t, feed, hsDone, writeDone, &handshakeChecked, &pending, client, deadline,
			)
			pendingToServer = raw
			inTypeData = nextClientFragment(t, &pendingToServer, peerMTU)
		}

		next, err := term.Process(inTypeData)
		if err != nil {
			t.Fatalf("term.Process: %v", err)
		}
		observe(next)
		step = next
	}
}

// nextClientFragment pops up to mtu bytes off the front of *pending,
// building one EAP-TTLS packet with the M flag set iff bytes remain
// afterwards.
func nextClientFragment(t *testing.T, pending *[]byte, mtu int) []byte {
	t.Helper()
	out := &EapTtls{}
	if mtu > 0 && len(*pending) > mtu {
		out.TLSData = (*pending)[:mtu]
		*pending = (*pending)[mtu:]
		out.Flags |= EapTlsFlagMoreFragments
	} else {
		out.TLSData = *pending
		*pending = nil
	}
	b, err := out.Marshal()
	if err != nil {
		t.Fatalf("marshal client fragment: %v", err)
	}
	return b
}

// waitForClientBytes polls the feed for TLS bytes the real tls.Client has
// produced (handshake flights, or the post-handshake AVP write), kicking off
// the AVP write once the handshake has completed. It deliberately never
// calls term.Process itself: doing so before the corresponding TLS record
// has been fully delivered is exactly the sequencing hazard Task 3 flagged
// for the inner read (calling it before the record is delivered stalls).
func waitForClientBytes(
	t *testing.T, feed *feedConn, hsDone, writeDone chan error, handshakeChecked *bool,
	pending *[]func(*tls.Conn) error, client *tls.Conn, deadline time.Time,
) []byte {
	t.Helper()
	for {
		if raw := feed.readFromClient(); len(raw) > 0 {
			return raw
		}
		if !*handshakeChecked {
			select {
			case err := <-hsDone:
				if err != nil {
					t.Fatalf("client handshake failed: %v", err)
				}
				*handshakeChecked = true
			default:
			}
		}
		if *handshakeChecked && len(*pending) > 0 {
			write := (*pending)[0]
			*pending = (*pending)[1:]
			go func() { writeDone <- write(client) }()
		}
		select {
		case err := <-writeDone:
			if err != nil {
				t.Fatalf("client write failed: %v", err)
			}
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("waitForClientBytes: timed out waiting for client output")
		}
		time.Sleep(time.Millisecond)
	}
}

// driveToAwaitingInner runs a real TLS 1.2 peer through the handshake and
// stops the moment the terminator reports AwaitingInner, leaving it parked
// in the inner state with no inner data delivered.
func driveToAwaitingInner(t *testing.T) *Terminator {
	t.Helper()
	srvCfg := testTLSServerConfig(t)
	srvCfg.MinVersion = tls.VersionTLS12
	srvCfg.MaxVersion = tls.VersionTLS12
	term := NewTerminator(srvCfg, 0)
	start, err := term.Process(nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	type stopAtAwaiting struct{}
	reached := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(stopAtAwaiting); !ok {
					panic(r)
				}
			}
		}()
		runTtlsPeerObserved(t, term, start, testUserName, testPassword, 5*time.Second, func(s *TerminatorStep) {
			if s.AwaitingInner {
				reached = true
				panic(stopAtAwaiting{})
			}
		})
	}()
	if !reached {
		t.Fatal("never reached AwaitingInner")
	}
	return term
}

// processWithin calls Process and fails the test if it does not return
// within d -- the regression shape for a Process that blocks forever.
func processWithin(t *testing.T, term *Terminator, in []byte, d time.Duration) (*TerminatorStep, error) {
	t.Helper()
	type res struct {
		step *TerminatorStep
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		s, e := term.Process(in)
		ch <- res{s, e}
	}()
	select {
	case r := <-ch:
		return r.step, r.err
	case <-time.After(d):
		t.Fatalf("Process blocked >%v", d)
		return nil, nil
	}
}

// TestTerminatorEmptyPacketInInnerStateRePrompts: a peer that answers the
// post-handshake prompt with a bare ack (no TLS data) must get another
// prompt, not hang the caller forever waiting for inner data.
func TestTerminatorEmptyPacketInInnerStateRePrompts(t *testing.T) {
	term := driveToAwaitingInner(t)
	t.Cleanup(func() {
		if err := term.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	step, err := processWithin(t, term, []byte{byte(EapTypeTtls), 0x00}, 2*time.Second)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !step.AwaitingInner || step.Done {
		t.Fatalf("want AwaitingInner re-prompt, got %+v", step)
	}
	if !bytes.Equal(step.OutTypeData, []byte{byte(EapTypeTtls), 0x00}) {
		t.Fatalf("re-prompt = %x, want empty TTLS packet", step.OutTypeData)
	}
}

// TestTerminatorEmptyPacketsInInnerStateEventuallyFail: the re-prompt is
// bounded so a peer that never sends inner data cannot ping-pong forever.
func TestTerminatorEmptyPacketsInInnerStateEventuallyFail(t *testing.T) {
	term := driveToAwaitingInner(t)
	t.Cleanup(func() {
		if err := term.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	empty := []byte{byte(EapTypeTtls), 0x00}
	for i := 0; i < maxInnerRounds; i++ {
		if _, err := processWithin(t, term, empty, 2*time.Second); err != nil {
			t.Fatalf("round %d: unexpected error %v", i, err)
		}
	}
	if _, err := processWithin(t, term, empty, 2*time.Second); err == nil {
		t.Fatal("expected error after exceeding maxInnerRounds, got nil")
	}
	if !term.closed {
		t.Fatal("terminator not closed after round-cap error")
	}
}

// TestTerminatorRejectsOversizedInboundMessage: a peer streaming M-flagged
// fragments must be cut off once the reassembly buffer exceeds the cap.
func TestTerminatorRejectsOversizedInboundMessage(t *testing.T) {
	term := NewTerminator(testTLSServerConfig(t), 0)
	if _, err := term.Process(nil); err != nil {
		t.Fatalf("start: %v", err)
	}
	frag, err := (&EapTtls{Flags: EapTlsFlagMoreFragments, TLSData: make([]byte, 4096)}).Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var lastErr error
	for i := 0; i < maxInboundMessage/4096+2 && lastErr == nil; i++ {
		_, lastErr = term.Process(frag)
	}
	if lastErr == nil {
		t.Fatal("expected error once inbound exceeds maxInboundMessage, got nil")
	}
	if !term.closed {
		t.Fatal("terminator not closed after oversize error")
	}
}

// TestTerminatorAcceptsAVPsInSeparateRecords: RFC 5281 carries the tunneled
// AVPs as a byte stream, so a peer may put User-Name and User-Password in
// records of their own. Reading one record and parsing it alone rejected such
// a peer with "missing User-Name or User-Password".
func TestTerminatorAcceptsAVPsInSeparateRecords(t *testing.T) {
	term := NewTerminator(testTLSServerConfig(t), 0)
	defer func() {
		if err := term.Close(); err != nil {
			t.Logf("close: %v", err)
		}
	}()
	start, err := term.Process(nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	twoRecords := func(c *tls.Conn) error {
		if _, werr := c.Write(encodeAVP(avpCodeUserName, true, []byte(testUserName))); werr != nil {
			return werr
		}
		_, werr := c.Write(encodeAVP(avpCodeUserPassword, true, []byte(testPassword)))
		return werr
	}

	cred, keys := runTtlsPeerWriters(
		t, term, start, []func(*tls.Conn) error{twoRecords}, 5*time.Second, nil)
	if string(cred.UserName) != testUserName || string(cred.UserPassword) != testPassword {
		t.Fatalf("cred = %q/%q, want %q/%q",
			cred.UserName, cred.UserPassword, testUserName, testPassword)
	}
	if keys == nil {
		t.Fatal("keys not derived")
	}
}

// TestTerminatorAcceptsAVPsAcrossRounds: the same byte stream may also arrive
// in separate EAP packets, one prompt apart. The terminator must accumulate
// the inner bytes rather than parse each round in isolation.
func TestTerminatorAcceptsAVPsAcrossRounds(t *testing.T) {
	term := NewTerminator(testTLSServerConfig(t), 0)
	defer func() {
		if err := term.Close(); err != nil {
			t.Logf("close: %v", err)
		}
	}()
	start, err := term.Process(nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	writeName := func(c *tls.Conn) error {
		_, werr := c.Write(encodeAVP(avpCodeUserName, true, []byte(testUserName)))
		return werr
	}
	writePassword := func(c *tls.Conn) error {
		_, werr := c.Write(encodeAVP(avpCodeUserPassword, true, []byte(testPassword)))
		return werr
	}

	cred, _ := runTtlsPeerWriters(
		t, term, start, []func(*tls.Conn) error{writeName, writePassword}, 5*time.Second, nil)
	if string(cred.UserName) != testUserName || string(cred.UserPassword) != testPassword {
		t.Fatalf("cred = %q/%q, want %q/%q",
			cred.UserName, cred.UserPassword, testUserName, testPassword)
	}
}

// TestTerminatorReportsTunnelClosedByPeer: once the peer has torn the tunnel
// down, every further read is EOF. Reading that as "no data this round" spent
// the re-prompt budget and then blamed the peer for sending no inner data,
// hiding what actually happened.
func TestTerminatorReportsTunnelClosedByPeer(t *testing.T) {
	term := driveToAwaitingInner(t)
	t.Cleanup(func() {
		// The bridge is closed below, so this second close is expected to
		// report the already-closed engine; the test is about Process.
		if err := term.Close(); err != nil {
			t.Logf("Close: %v", err)
		}
	})

	if err := term.bridge.close(); err != nil {
		t.Logf("bridge close: %v", err)
	}

	_, err := processWithin(t, term, []byte{byte(EapTypeTtls), 0x00}, 2*time.Second)
	if err == nil {
		t.Fatal("Process succeeded after the tunnel closed, want an error")
	}
	if !strings.Contains(err.Error(), "tunnel closed") {
		t.Fatalf("error = %v, want it to name the closed tunnel", err)
	}
}

// TestTerminatorRejectsPeerDataDuringFragmentTrain: while the terminator is
// sending its own fragments the peer's only legal reply is a bare ack. Any
// payload it sends there used to be dropped on the floor, so a TLS alert --
// the peer rejecting the server certificate, say -- surfaced later as an
// unexplained desync instead of the failure it is.
func TestTerminatorRejectsPeerDataDuringFragmentTrain(t *testing.T) {
	newMidTrain := func() *Terminator {
		term := NewTerminator(testTLSServerConfig(t), 4)
		term.state = ttlsStateHandshake
		term.outPending = []byte("fragment tail")
		return term
	}

	withData := &EapTtls{TLSData: []byte{0x15, 0x03, 0x03}} // start of a TLS alert
	in, err := withData.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err = newMidTrain().Process(in); err == nil {
		t.Fatal("peer payload during the fragment train was accepted")
	}

	withFlag := &EapTtls{Flags: EapTlsFlagMoreFragments}
	if in, err = withFlag.Marshal(); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err = newMidTrain().Process(in); err == nil {
		t.Fatal("peer fragment flag during the fragment train was accepted")
	}

	// A bare ack, including one that carries only the version bits an
	// implementation may set, still advances the train.
	ack := &EapTtls{Flags: 0x01}
	if in, err = ack.Marshal(); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	step, err := newMidTrain().Process(in)
	if err != nil {
		t.Fatalf("bare ack rejected: %v", err)
	}
	if len(step.OutTypeData) == 0 {
		t.Fatal("bare ack produced no next fragment")
	}
}

// TestTerminatorDoesNotStallOnPartialRecord: a peer that sends the first few
// bytes of a TLS record and stops leaves the engine waiting for the rest. That
// is an ordinary "nothing to say yet", but it used to be indistinguishable
// from a stuck engine, so Process sat on the caller's goroutine for the whole
// bridgeOutputTimeout before giving up. The peer pays one small packet for it
// and can repeat it at will.
func TestTerminatorDoesNotStallOnPartialRecord(t *testing.T) {
	term := NewTerminator(testTLSServerConfig(t), 0)
	t.Cleanup(func() {
		if err := term.Close(); err != nil {
			t.Logf("Close: %v", err)
		}
	})
	if _, err := term.Process(nil); err != nil {
		t.Fatalf("start: %v", err)
	}

	partial := &EapTtls{TLSData: []byte{0x16, 0x03, 0x01}} // a record header, cut short
	in, err := partial.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	started := time.Now()
	if _, err = processWithin(t, term, in, 2*time.Second); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Process took %v on a partial record; it waited out a timeout instead of"+
			" noticing the engine was waiting for input", elapsed)
	}
}

// deliverToPeer hands one terminator step's TLS bytes to the peer's transport.
func deliverToPeer(t *testing.T, feed *feedConn, step *TerminatorStep) {
	t.Helper()
	var pkt EapTtls
	if err := pkt.Unmarshal(step.OutTypeData); err != nil {
		t.Fatalf("unmarshal server output: %v", err)
	}
	if len(pkt.TLSData) == 0 {
		return
	}
	if err := feed.writeToClient(pkt.TLSData); err != nil {
		t.Fatalf("writeToClient: %v", err)
	}
}

// pollClientBytes waits for the peer's TLS engine to produce its next flight.
func pollClientBytes(t *testing.T, feed *feedConn, deadline time.Time) []byte {
	t.Helper()
	for {
		if raw := feed.readFromClient(); len(raw) > 0 {
			return raw
		}
		if time.Now().After(deadline) {
			t.Fatal("pollClientBytes: timed out waiting for peer output")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestTerminatorReportsHandshakeCompleteOnTls12: waitForBridgeOutput returned
// the instant any outbound bytes appeared, which races the bridge's handshake
// goroutine. On TLS 1.2 Go writes the server's ChangeCipherSpec+Finished
// before HandshakeContext returns, so hsDone was still false when the
// terminator checked it right afterwards. The round carrying that final
// flight therefore came back without AwaitingInner and with the terminator
// still in the handshake state, so the RFC 9427 Section 3 check for inner
// data delivered alongside the peer's Finished was skipped for exactly the
// round in which it can first apply.
func TestTerminatorReportsHandshakeCompleteOnTls12(t *testing.T) {
	srvCfg := testTLSServerConfig(t)
	srvCfg.MinVersion = tls.VersionTLS12
	srvCfg.MaxVersion = tls.VersionTLS12
	term := NewTerminator(srvCfg, 0)
	t.Cleanup(func() {
		if cerr := term.Close(); cerr != nil {
			t.Errorf("Close: %v", cerr)
		}
	})

	step, err := term.Process(nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	clientConn, feed := newMemConnPair()
	client := tls.Client(clientConn, testTLSClientConfig(t, term.cfg))
	hsDone := make(chan error, 1)
	go func() { hsDone <- client.HandshakeContext(context.Background()) }()

	deadline := time.Now().Add(5 * time.Second)
	// TLS 1.2 with no fragmentation: the peer sends exactly two handshake
	// flights (ClientHello, then ChangeCipherSpec+Finished), so the step
	// produced after the second one is the server's final flight.
	for round := 1; round <= 2; round++ {
		deliverToPeer(t, feed, step)
		pending := pollClientBytes(t, feed, deadline)
		if step, err = term.Process(nextClientFragment(t, &pending, 0)); err != nil {
			t.Fatalf("round %d: Process: %v", round, err)
		}
	}

	if !step.AwaitingInner {
		t.Errorf("the step carrying the server's final TLS 1.2 flight lacks AwaitingInner: %+v", step)
	}
	if term.state != ttlsStateInner {
		t.Errorf("terminator state = %v after the final flight, want the inner state", term.state)
	}

	// Prove that step really was the final flight: delivering it, and
	// nothing else, completes the peer's handshake.
	deliverToPeer(t, feed, step)
	select {
	case err = <-hsDone:
		if err != nil {
			t.Fatalf("client handshake failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("peer handshake did not complete on the step asserted to be the final flight")
	}
}
