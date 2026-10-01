package eap

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"time"
)

// tlsBridge drives a server-side TLS handshake whose records are carried
// out-of-band (inside EAP-TTLS packets) rather than over a real socket.
//
// Design note: an earlier draft wired tls.Server directly to one end of a
// net.Pipe, with writeInbound/readOutbound talking to the other end. That
// deadlocks under the lock-step calling pattern EAP-TTLS requires: a caller
// does writeInbound(record) followed immediately by takeAppData() on the
// same goroutine, but net.Pipe's Write blocks until a matching Read occurs,
// and nothing performs that Read until writeInbound has already returned.
// Instead, tls.Server is wired to an internal engineConn backed by two
// plain byte buffers guarded by a mutex/condition variable: writeInbound and
// readOutbound never block, and engineConn.Read blocks only on the
// condition variable (not on a synchronous pipe rendezvous), so it can
// always be unblocked by close().
type tlsBridge struct {
	conn *tls.Conn

	mu       sync.Mutex
	cond     *sync.Cond
	inbound  bytes.Buffer // TLS bytes fed by writeInbound, awaiting engine consumption
	outbound bytes.Buffer // TLS bytes produced by the engine, awaiting readOutbound
	hsDone   bool
	hsErr    error
	closed   bool
	appCh    chan appDataChunk // decrypted inner data, fed by appDataPump's goroutine

	// done is closed by engineConn.Close. It is the second wake-up path the
	// pump goroutine needs: cond.Broadcast only reaches a goroutine parked in
	// engineConn.Read, and the pump can instead be parked on a send into a
	// full appCh that nobody will ever drain again.
	done chan struct{}
	// pumpDone is closed when the pump goroutine returns, so teardown is
	// observable: nothing in the package waits on it, but a leak here is
	// otherwise invisible until the process runs out of memory.
	pumpDone chan struct{}

	// parked counts readers waiting inside engineConn.Read for input. With an
	// empty inbound buffer it is positive evidence that the engine has
	// consumed everything the peer sent and will produce nothing further
	// until more arrives. Without it a caller can only guess by waiting on a
	// clock, which a peer can then make it do on demand.
	parked int
}

// newTLSBridge starts a server-side TLS handshake in the background. The
// handshake progresses as the caller shuttles bytes via writeInbound and
// readOutbound.
func newTLSBridge(cfg *tls.Config) *tlsBridge {
	b := &tlsBridge{
		done:     make(chan struct{}),
		pumpDone: make(chan struct{}),
	}
	b.cond = sync.NewCond(&b.mu)
	b.conn = tls.Server(engineConn{b}, cfg)

	go func() {
		err := b.conn.HandshakeContext(context.Background())
		b.mu.Lock()
		b.hsDone = true
		b.hsErr = err
		b.mu.Unlock()
	}()
	return b
}

// writeInbound feeds TLS bytes received from the peer into the engine. It
// never blocks: bytes are appended to an internal buffer that engineConn.Read
// drains as the TLS engine asks for input.
func (b *tlsBridge) writeInbound(tlsRecord []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return io.ErrClosedPipe
	}
	b.inbound.Write(tlsRecord)
	b.cond.Broadcast()
	return nil
}

// readOutbound returns and clears any TLS bytes the engine has produced for
// the peer. Returns nil if nothing is pending.
func (b *tlsBridge) readOutbound() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.outbound.Len() == 0 {
		return nil
	}
	out := append([]byte(nil), b.outbound.Bytes()...)
	b.outbound.Reset()
	return out
}

// engineWaiting reports whether the TLS engine has drained everything fed so
// far and is parked waiting for more. Both conditions matter: bytes written
// but not yet consumed mean the engine still has work to do, however many
// readers are currently parked.
func (b *tlsBridge) engineWaiting() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	// A closed bridge is never merely waiting: its readers are on their way
	// out and still counted as parked until each one re-acquires the lock,
	// which would otherwise read as "the peer has said all it is going to".
	return !b.closed && b.parked > 0 && b.inbound.Len() == 0
}

// handshakeDone reports whether the TLS handshake has finished (successfully
// or not). Callers should check the error via a subsequent connState/read.
func (b *tlsBridge) handshakeDone() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.hsDone
}

// handshakeErr returns the handshake result error, if the handshake has
// completed. It is nil while the handshake is still in progress or if it
// succeeded.
func (b *tlsBridge) handshakeErr() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.hsErr
}

func (b *tlsBridge) connState() tls.ConnectionState {
	return b.conn.ConnectionState()
}

// takeAppData returns decrypted application data that is already available,
// waiting at most d for the engine to surface it. It never blocks
// indefinitely: no data within d is reported as no data, not as an error.
// RFC 9427 Section 3 requires this check once the TLS session is
// established, because a TLS 1.3 peer may send its Finished and its first
// inner records together.
func (b *tlsBridge) takeAppData(d time.Duration) ([]byte, error) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	ch := b.appDataPump()
	var data []byte
	for {
		select {
		case r, ok := <-ch:
			if !ok {
				return data, io.EOF
			}
			data = append(data, r.data...)
			if r.err != nil {
				return data, r.err
			}
			continue
		default:
		}
		// Nothing queued this instant. A pump parked on an empty inbound
		// buffer has decrypted everything the peer sent, so the flight is
		// complete and waiting longer cannot add to it -- for a peer that
		// sends its inner data in its own packet, which is every TLS 1.2
		// peer, that wait was pure latency once per authentication. While
		// the pump is still working, keep collecting: RFC 5281 tunnels the
		// AVPs as a byte stream and one flight may decrypt to several
		// chunks, so returning after the first would hand the caller a
		// fragment and leave the rest with no packet left to prompt for.
		if b.engineWaiting() {
			select {
			case r, ok := <-ch:
				if !ok {
					return data, io.EOF
				}
				data = append(data, r.data...)
				if r.err != nil {
					return data, r.err
				}
				continue
			default:
				return data, nil
			}
		}
		select {
		case <-timer.C:
			return data, nil
		case <-time.After(time.Millisecond):
		}
	}
}

type appDataChunk struct {
	data []byte
	err  error
}

// appDataPump lazily starts the single goroutine that drains decrypted
// application data off the TLS engine, and returns its channel. A dedicated
// goroutine is what lets takeAppData impose a deadline: tls.Conn.Read
// cannot be bounded here, because engineConn deliberately ignores read
// deadlines -- a deadline error would put tls.Conn into a permanent error
// state and kill the session.
func (b *tlsBridge) appDataPump() <-chan appDataChunk {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.appCh == nil {
		ch := make(chan appDataChunk, 4)
		b.appCh = ch
		go func() {
			defer close(ch)
			defer close(b.pumpDone)
			for {
				buf := make([]byte, 16384)
				n, err := b.conn.Read(buf)
				if n > 0 {
					if !b.send(ch, appDataChunk{data: buf[:n]}) {
						return
					}
				}
				if err != nil {
					if err != io.EOF {
						b.send(ch, appDataChunk{err: err})
					}
					return
				}
			}
		}()
	}
	return b.appCh
}

// send hands one chunk to the reader of ch, or gives up if the bridge is
// closed. A peer decides how many records arrive in one flight, so ch can
// fill up while the only reader has already moved on; without the second
// case the pump would park here for the lifetime of the process.
func (b *tlsBridge) send(ch chan<- appDataChunk, c appDataChunk) bool {
	select {
	case ch <- c:
		return true
	case <-b.done:
		return false
	}
}

// close tears down the TLS engine and unblocks any in-progress reads.
// tls.Conn.Close attempts to send a close_notify alert before tearing down
// the underlying conn, so we let that happen first (via engineConn.Write)
// and only mark the bridge closed once engineConn.Close runs; marking it
// closed up front would make the close_notify write fail immediately.
// engineConn.Close's cond.Broadcast is what unblocks any goroutine parked
// in engineConn.Read (e.g. the pump goroutine behind takeAppData), so it returns
// promptly with io.EOF instead of hanging forever.
//
// Note: close() returning does not imply the handshake goroutine started in
// newTLSBridge has exited yet -- that goroutine observes the close
// asynchronously (via the same Read unblocking) and updates hsDone/hsErr on
// its own schedule shortly after.
func (b *tlsBridge) close() error {
	return b.conn.Close()
}

// engineConn adapts tlsBridge's internal buffers to the net.Conn interface
// crypto/tls needs to drive the handshake and record layer.
type engineConn struct {
	b *tlsBridge
}

// Read blocks until inbound bytes are available, the bridge is closed, or
// an EAP-side error occurs.
func (c engineConn) Read(p []byte) (int, error) {
	b := c.b
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.inbound.Len() == 0 && !b.closed {
		b.parked++
		b.cond.Broadcast()
		b.cond.Wait()
		b.parked--
	}
	if b.inbound.Len() == 0 && b.closed {
		return 0, io.EOF
	}
	return b.inbound.Read(p)
}

// Write appends engine-produced TLS bytes to the outbound buffer; it never
// blocks.
func (c engineConn) Write(p []byte) (int, error) {
	b := c.b
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, io.ErrClosedPipe
	}
	return b.outbound.Write(p)
}

func (c engineConn) Close() error {
	b := c.b
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		close(b.done)
	}
	b.cond.Broadcast()
	b.mu.Unlock()
	return nil
}

func (c engineConn) LocalAddr() net.Addr                { return ttlsEngineAddr{} }
func (c engineConn) RemoteAddr() net.Addr               { return ttlsEngineAddr{} }
func (c engineConn) SetDeadline(t time.Time) error      { return nil }
func (c engineConn) SetReadDeadline(t time.Time) error  { return nil }
func (c engineConn) SetWriteDeadline(t time.Time) error { return nil }

// ttlsEngineAddr is a placeholder net.Addr: the TLS engine never touches a
// real socket, so addresses are meaningless here.
type ttlsEngineAddr struct{}

func (ttlsEngineAddr) Network() string { return "eap-ttls" }
func (ttlsEngineAddr) String() string  { return "eap-ttls-bridge" }
