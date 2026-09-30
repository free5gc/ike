package eap

import (
	"crypto/tls"
	"io"
	"math"
	"time"

	"github.com/pkg/errors"
)

// bridgeOutputTimeout bounds how long emitOutbound waits for the bridge's
// background handshake goroutine to produce output after writeInbound
// returns (writeInbound only enqueues bytes; the goroutine consumes and
// reacts to them asynchronously). In practice this resolves in well under a
// millisecond; a multi-second bound only guards against a genuinely stuck
// handshake goroutine, which should surface as an error rather than a
// silent hang.
const bridgeOutputTimeout = 3 * time.Second

// innerProbeTimeout bounds each check for decrypted inner data. Right after
// the handshake it is the grace period RFC 9427 Section 3 requires for the
// TLS engine to surface records that arrived with the peer's Finished (a
// TLS 1.2 peer, or a TLS 1.3 peer such as wpa_supplicant that sends its
// inner data separately, simply costs this much once per authentication).
// In the inner state it bounds the wait for the peer's reply to decrypt
// to application data, so a bare ack or a post-handshake TLS message
// results in a re-prompt instead of a blocked caller.
const innerProbeTimeout = 250 * time.Millisecond

// maxInnerRounds bounds how many times the terminator re-prompts a peer that
// answers the post-handshake prompt without inner data (e.g. with a bare
// ack) before giving up. A conforming peer needs zero such rounds.
const maxInnerRounds = 3

// maxInboundMessage caps the reassembly buffer for one inbound TLS message.
// The peer's flights are a few KiB in the common case (no client
// certificate); this only stops a peer from streaming M-flagged fragments
// without bound.
const maxInboundMessage = 64 << 10

// ttlsState tracks where a single EAP-TTLS authentication is in its
// lifecycle: before anything has been sent, mid-handshake, waiting for the
// tunneled inner (PAP) data once the handshake has completed, or finished.
type ttlsState int

const (
	ttlsStateStart ttlsState = iota
	ttlsStateHandshake
	ttlsStateInner
	ttlsStateDone
)

// Terminator drives one server-side EAP-TTLS authentication: it emits
// TTLS-Start, runs the TLS handshake via a tlsBridge (fragmenting/
// reassembling EAP-TTLS TLS-data as needed), and once the tunnel is up reads
// the peer's decrypted inner PAP AVPs and derives keying material.
//
// P1 scope: Terminator does not verify the password. It only extracts the
// inner identity/password (PapCredential) and the MSK/EMSK and hands them to
// the caller; credential verification is a separate, later concern.
//
// A Terminator drives exactly one authentication and is not safe for
// concurrent use from multiple goroutines (the caller is expected to call
// Process sequentially, matching the EAP request/response ping-pong).
type Terminator struct {
	bridge *tlsBridge
	cfg    *tls.Config
	mtu    int
	state  ttlsState

	// inPending accumulates TLS bytes for the inbound message currently
	// being reassembled. The peer sets EapTlsFlagMoreFragments on every
	// fragment but the last one of a multi-fragment message.
	inPending []byte

	// outPending holds the remaining bytes of the outbound message we are
	// currently fragmenting out to the peer. It is nil whenever no
	// fragmented send is in flight -- either because we haven't started a
	// message yet, or because the message we were sending has been fully
	// delivered. A non-nil/non-empty outPending after emitOutbound returns
	// means the peer's next inbound packet is expected to be a bare
	// fragment-ack (empty TLS-data, no flags), not a new message: see the
	// check at the top of the handshake/inner branch of Process.
	outPending []byte
	// outTotal is the total length of the outbound message currently being
	// fragmented, recorded once when the message is first pulled off the
	// bridge. It is used for the Message-Length field, which per RFC 5281
	// is only meaningful (and only sent, with the L flag) on that message's
	// FIRST fragment -- not the first chunk's own length, but the length of
	// the complete message across all its fragments.
	outTotal uint32
	// outFirst is true exactly when the next fragment emitOutbound sends is
	// the first fragment of outTotal's message.
	outFirst bool

	// innerRounds counts post-handshake rounds in which the peer sent no
	// inner data, so the re-prompt in Process is bounded by maxInnerRounds.
	innerRounds int

	// innerBuf accumulates the decrypted tunneled bytes across rounds. The
	// AVPs are a byte stream, so a peer may spread one AVP set over several
	// records or several EAP packets.
	innerBuf []byte

	// closed guards Close so it is idempotent: bridge.close() itself is not
	// documented as safe to call twice, and repeated calls happen naturally
	// (e.g. a caller's own error-handling path calling Close after Process
	// already closed the bridge on an error-return).
	closed bool
}

// NewTerminator creates a Terminator for one EAP-TTLS authentication. mtu is
// the maximum size of the TLS-data carried in a single EAP-TTLS packet;
// larger bridge output is fragmented across multiple packets.
func NewTerminator(cfg *tls.Config, mtu int) *Terminator {
	return &Terminator{cfg: cfg, mtu: mtu, state: ttlsStateStart}
}

// Close releases the underlying TLS engine, if one has been started. It is
// nil-safe (a Terminator on which Process has never been called has no
// bridge yet) and idempotent (safe to call more than once, including after
// Process has already closed the bridge itself on the Done path or
// on an error path).
//
// Callers MUST call Close if an authentication is abandoned before
// reaching Done -- e.g. the peer disappears mid-handshake, or the caller
// gives up after some number of retries -- since the bridge's background
// handshake goroutine (started in newTLSBridge) otherwise stays parked in
// engineConn.Read forever, waiting for input that will never arrive.
// bridge.close() unblocks it (Close -> cond.Broadcast -> Read returns
// io.EOF -> HandshakeContext returns -> goroutine exits).
func (t *Terminator) Close() error {
	if t == nil || t.bridge == nil || t.closed {
		return nil
	}
	t.closed = true
	return t.bridge.close()
}

// TerminatorStep is the result of one Process call.
type TerminatorStep struct {
	OutTypeData []byte // EAP-TTLS type-data to wrap in an EAP-Request (nil if none pending)
	Done        bool

	// CredentialsExtracted reports that the tunnel completed and Cred holds
	// the inner PAP identity and password the peer presented. It says nothing
	// about whether that password is correct: this package never sees the
	// credential store. A caller that maps this to EAP-Success without
	// verifying Cred first accepts every username and password offered.
	CredentialsExtracted bool

	Cred *PapCredential
	Keys *TtlsKeys

	// AwaitingInner marks the step where the TLS handshake has completed but
	// the peer has not sent its inner AVPs, so OutTypeData is only a prompt
	// for them. Peers that send inner data in their own packet (every TLS
	// 1.2 peer, and TLS 1.3 peers such as wpa_supplicant) legitimately pass
	// through this state; a peer that abandons the authentication also stops
	// here, which is why callers should log it. Never set together with Done.
	AwaitingInner bool
}

// Process advances the EAP-TTLS state machine by one step. Call it first
// with inTypeData == nil to obtain the initial TTLS-Start packet, then once
// per subsequent EAP-Response received from the peer, feeding that
// response's EAP-TTLS type-data (starting at the Type byte) as inTypeData.
func (t *Terminator) Process(inTypeData []byte) (*TerminatorStep, error) {
	step, err := t.process(inTypeData)
	if err != nil {
		// Any error means this authentication attempt is broken and the
		// caller will abandon this Terminator -- close the bridge so its
		// background handshake goroutine doesn't stay parked in
		// engineConn.Read forever. Close is idempotent/nil-safe, so this is
		// harmless on paths that already closed the bridge themselves.
		if cerr := t.Close(); cerr != nil {
			err = errors.Wrapf(err, "Terminator: close after failure: %v", cerr)
		}
	}
	return step, err
}

func (t *Terminator) process(inTypeData []byte) (*TerminatorStep, error) {
	switch t.state {
	case ttlsStateStart:
		t.bridge = newTLSBridge(t.cfg)
		t.state = ttlsStateHandshake
		start := &EapTtls{Flags: EapTlsFlagStart}
		out, err := start.Marshal()
		if err != nil {
			return nil, errors.Wrap(err, "Terminator: marshal TTLS-Start")
		}
		return &TerminatorStep{OutTypeData: out}, nil

	case ttlsStateHandshake, ttlsStateInner:
		var pkt EapTtls
		if err := pkt.Unmarshal(inTypeData); err != nil {
			return nil, errors.Wrap(err, "Terminator: decode inbound")
		}

		// If we're mid-way through sending our own fragmented outbound
		// message, the peer's only legal reply is a bare ack (empty
		// TLS-data, no flags) requesting the next fragment -- it carries no
		// data of its own to reassemble. Continue the outbound send instead
		// of trying to interpret this packet as a new inbound message.
		if len(t.outPending) > 0 {
			// Only the L/M/S bits are ours to judge: the low bits of the
			// flags byte carry the EAP-TTLS version, which a peer may set on
			// an otherwise bare ack.
			if len(pkt.TLSData) > 0 ||
				pkt.Flags&(EapTlsFlagLengthIncluded|EapTlsFlagMoreFragments|EapTlsFlagStart) != 0 {
				return nil, errors.Errorf(
					"Terminator: peer sent %d bytes with flags 0x%02x during an outbound fragment train,"+
						" expected a bare ack", len(pkt.TLSData), pkt.Flags)
			}
			return t.emitOutbound()
		}

		// Reassemble the peer's (possibly fragmented) inbound message.
		t.inPending = append(t.inPending, pkt.TLSData...)
		if len(t.inPending) > maxInboundMessage {
			return nil, errors.Errorf("Terminator: inbound message exceeds %d bytes", maxInboundMessage)
		}
		if pkt.Flags&EapTlsFlagMoreFragments != 0 {
			ack := &EapTtls{}
			out, err := ack.Marshal()
			if err != nil {
				return nil, errors.Wrap(err, "Terminator: marshal fragment ack")
			}
			return &TerminatorStep{OutTypeData: out}, nil
		}
		msg := t.inPending
		t.inPending = nil

		// wasInner: whether we had already finished the handshake as of the
		// START of this round (i.e. in a previous Process call). If so, the
		// message we just reassembled is expected to be encrypted inner
		// (tunneled PAP) application data, and we read it back below. If
		// the handshake only *just* finished (this round), the message we
		// fed was the peer's final handshake flight; any inner data can at
		// most have ridden along with it (the RFC 9427 probe further down).
		wasInner := t.state == ttlsStateInner

		if len(msg) > 0 {
			if err := t.bridge.writeInbound(msg); err != nil {
				return nil, errors.Wrap(err, "Terminator: feed TLS")
			}
		}

		if wasInner {
			// Bounded, not blocking: the peer may legitimately answer the
			// post-handshake prompt with a bare ack (empty msg, nothing fed
			// above) or with a TLS record that decrypts to no application
			// data (a TLS 1.3 post-handshake message). A blocking read
			// would park this goroutine forever in either case, so treat
			// "no data" as "prompt again", up to maxInnerRounds.
			app, err := t.bridge.takeAppData(innerProbeTimeout)
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, errors.Wrap(err, "Terminator: read inner")
			}
			if step, done, ferr := t.tryFinishInner(app); done {
				return step, ferr
			}
			if errors.Is(err, io.EOF) {
				return nil, errors.Errorf(
					"Terminator: tunnel closed by peer before the inner AVPs were complete")
			}
			t.innerRounds++
			if t.innerRounds > maxInnerRounds {
				if len(t.innerBuf) > 0 {
					return nil, errors.Errorf(
						"Terminator: inner AVPs still incomplete after %d prompts", maxInnerRounds)
				}
				return nil, errors.Errorf("Terminator: no inner data after %d prompts", maxInnerRounds)
			}
			step, err := t.emitOutbound()
			if err != nil {
				return nil, err
			}
			step.AwaitingInner = true
			return step, nil
		}

		// Flush whatever the bridge has queued as output this round (the
		// next handshake flight; or, once the handshake finishes, its final
		// flight and/or TLS 1.3 post-handshake session tickets; or nothing
		// at all, in which case emitOutbound sends an empty packet that
		// both keeps the EAP exchange alive and acts as the implicit
		// prompt for the peer to start sending its inner PAP data).
		//
		// emitOutbound's internal wait (waitForBridgeOutput) returns only
		// once the round has settled -- the handshake goroutine has
		// recorded its result, or the engine is parked waiting for input --
		// so only AFTER it returns is bridge.handshakeDone() guaranteed to
		// reflect that goroutine's current state. Checking handshakeDone()
		// before calling emitOutbound (as an earlier version of this code
		// did) races: the goroutine may not have processed the just-fed
		// inbound record yet, so the check can read false even though the
		// handshake is about to complete, leaving t.state stuck at
		// ttlsStateHandshake forever and causing the next round's inner AVP
		// data to be misrouted through the handshake path instead of
		// takeAppData.
		step, err := t.emitOutbound()
		if err != nil {
			return nil, err
		}
		if t.bridge.handshakeDone() {
			if hsErr := t.bridge.handshakeErr(); hsErr != nil {
				return nil, errors.Wrap(hsErr, "Terminator: handshake failed")
			}
			t.state = ttlsStateInner

			// RFC 9427 Section 3: once the TLS session is established the
			// server MUST check for application data BEFORE starting
			// another round trip. A TLS 1.3 peer may carry its Finished
			// and its inner AVPs in one EAP packet (Windows 11 does), and
			// answering such a packet with another request instead of the
			// authentication result leaves the peer waiting forever.
			var inner []byte
			inner, err = t.bridge.takeAppData(innerProbeTimeout)
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, errors.Wrap(err, "Terminator: probe inner")
			}
			if s, done, ferr := t.tryFinishInner(inner); done {
				return s, ferr
			}
			if errors.Is(err, io.EOF) {
				return nil, errors.Errorf("Terminator: tunnel closed by peer after the handshake")
			}
			step.AwaitingInner = true
		}
		return step, nil

	default:
		return nil, errors.Errorf("Terminator: Process called in terminal state")
	}
}

// tryFinishInner adds this round's tunneled bytes to the inner stream and
// completes the authentication once both PAP AVPs are present. done is false
// while the stream is still short, which is the caller's cue to prompt the
// peer again: RFC 5281 tunnels the AVPs as a byte stream, so they may arrive
// over several records or several rounds.
func (t *Terminator) tryFinishInner(app []byte) (step *TerminatorStep, done bool, err error) {
	if len(app) > 0 {
		t.innerBuf = append(t.innerBuf, app...)
	}
	if len(t.innerBuf) == 0 {
		return nil, false, nil
	}
	step, err = t.finishInner(t.innerBuf)
	if errors.Is(err, errPapAVPsIncomplete) {
		return nil, false, nil
	}
	return step, true, err
}

// finishInner parses the peer's inner PAP AVPs, derives the keying material
// and completes the authentication.
func (t *Terminator) finishInner(app []byte) (*TerminatorStep, error) {
	cred, err := ParsePapAVPs(app)
	if err != nil {
		return nil, errors.Wrap(err, "Terminator: parse PAP")
	}
	keys, err := DeriveTtlsKeys(t.bridge.connState())
	if err != nil {
		return nil, errors.Wrap(err, "Terminator: derive keys")
	}
	t.state = ttlsStateDone
	// Close through the terminator, not the bridge directly: this marks the
	// terminator closed so the caller's own Close (callers are told to always
	// call it) stays a no-op instead of hitting an already-closed connection
	// and reporting "use of closed network connection" on every success.
	if err = t.Close(); err != nil {
		return nil, errors.Wrap(err, "Terminator: close")
	}
	return &TerminatorStep{Done: true, CredentialsExtracted: true, Cred: cred, Keys: keys}, nil
}

// emitOutbound takes pending TLS bytes produced by the bridge and returns
// one EAP-TTLS packet, fragmenting to t.mtu. The first fragment of a
// multi-fragment message carries the L flag and Message-Length set to the
// TOTAL length of the message (recorded once, when the message is first
// pulled off the bridge) -- not the length of just that first chunk.
// Non-final fragments carry the M flag.
func (t *Terminator) emitOutbound() (*TerminatorStep, error) {
	if t.outPending == nil {
		msg, err := t.waitForBridgeOutput()
		if err != nil {
			return nil, err
		}
		total := len(msg)
		if total > math.MaxUint32 {
			return nil, errors.Errorf("Terminator: outbound message too large (%d bytes)", total)
		}
		t.outPending = msg
		t.outTotal = uint32(total)
		t.outFirst = true
	}

	pkt := &EapTtls{}
	var chunk []byte
	moreAfter := t.mtu > 0 && len(t.outPending) > t.mtu
	if moreAfter {
		chunk = t.outPending[:t.mtu]
		t.outPending = t.outPending[t.mtu:]
		pkt.Flags |= EapTlsFlagMoreFragments
	} else {
		chunk = t.outPending
		t.outPending = nil
	}
	if t.outFirst && moreAfter {
		pkt.Flags |= EapTlsFlagLengthIncluded
		pkt.MessageLength = t.outTotal
	}
	t.outFirst = false
	pkt.TLSData = chunk

	out, err := pkt.Marshal()
	if err != nil {
		return nil, errors.Wrap(err, "Terminator: marshal outbound fragment")
	}
	return &TerminatorStep{OutTypeData: out}, nil
}

// waitForBridgeOutput polls the bridge for the output its background
// handshake goroutine produces this round, and returns once the round has
// settled: either the handshake goroutine has recorded its result, or the
// engine is parked waiting for input the peer has not sent yet. Both are
// terminal for the round -- Go's tls.Conn.Handshake performs all of its
// writes, including any post-handshake session tickets, before returning, so
// once handshakeDone() is true everything the engine was going to produce is
// already visible to readOutbound().
//
// It deliberately does NOT return the instant output appears. That races the
// handshake goroutine: on TLS 1.2 the engine writes the server's
// ChangeCipherSpec+Finished and only then returns from HandshakeContext, so
// hsDone is still false at the moment the flight becomes readable. A caller
// checking handshakeDone() right afterwards would miss the handshake-complete
// round, and with it the RFC 9427 Section 3 check for inner data the peer
// delivered alongside its Finished.
//
// If the round settles in neither way within bridgeOutputTimeout, something
// is stuck: output already collected is still returned (the peer needs it),
// and only an empty result is reported as an error rather than silently
// returning an empty packet, which would otherwise look identical to the
// legitimate "nothing more to flush" case and desync the peer.
func (t *Terminator) waitForBridgeOutput() ([]byte, error) {
	timer := time.NewTimer(bridgeOutputTimeout)
	defer timer.Stop()
	var out []byte
	for {
		out = append(out, t.bridge.readOutbound()...)
		if t.bridge.handshakeDone() || t.bridge.engineWaiting() {
			// Drain once more before leaving: the engine writes its flight
			// and only then records the handshake result or goes back to
			// read, so output produced since the drain above is there now.
			return append(out, t.bridge.readOutbound()...), nil
		}
		select {
		case <-t.bridge.done:
			return append(out, t.bridge.readOutbound()...), nil
		case <-timer.C:
			if len(out) > 0 {
				return out, nil
			}
			return nil, errors.Errorf("Terminator: timed out waiting for TLS engine output")
		case <-time.After(time.Millisecond):
		}
	}
}
