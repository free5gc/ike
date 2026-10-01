package eap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// ---- shared test helpers (also usable by Task 4/5 tests) ----

// generateSelfSignedCert builds a throwaway ECDSA self-signed certificate
// for use as a tls.Config server certificate in tests.
func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "eap-ttls-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

// testTLSServerConfig returns a self-signed server config for tests.
func testTLSServerConfig(t *testing.T) *tls.Config {
	t.Helper()
	cert := generateSelfSignedCert(t)
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
}

// testTLSClientConfig returns a client config that trusts exactly the given
// self-signed server config's certificate, so tests exercise real chain
// verification instead of disabling it via InsecureSkipVerify.
func testTLSClientConfig(t *testing.T, serverCfg *tls.Config) *tls.Config {
	t.Helper()
	leaf, err := x509.ParseCertificate(serverCfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}
}

// memBuf is a goroutine-safe, unbounded byte buffer with a blocking Read,
// used to build simple in-memory net.Conn-like endpoints for tests.
type memBuf struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    bytes.Buffer
	closed bool
}

func newMemBuf() *memBuf {
	b := &memBuf{}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *memBuf) write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, io.ErrClosedPipe
	}
	n, err := b.buf.Write(p)
	b.cond.Broadcast()
	return n, err
}

// read blocks until at least one byte is available, or the buffer is closed.
func (b *memBuf) read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.buf.Len() == 0 && !b.closed {
		b.cond.Wait()
	}
	if b.buf.Len() == 0 && b.closed {
		return 0, io.EOF
	}
	return b.buf.Read(p)
}

// readAvailable drains and returns whatever bytes are currently buffered,
// without blocking. Returns nil if nothing is available.
func (b *memBuf) readAvailable() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buf.Len() == 0 {
		return nil
	}
	out := append([]byte(nil), b.buf.Bytes()...)
	b.buf.Reset()
	return out
}

func (b *memBuf) close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	b.cond.Broadcast()
	return nil
}

// memConn is a minimal net.Conn backed by two memBuf pipes (one per direction).
type memConn struct {
	readBuf  *memBuf
	writeBuf *memBuf
}

func (c *memConn) Read(p []byte) (int, error)  { return c.readBuf.read(p) }
func (c *memConn) Write(p []byte) (int, error) { return c.writeBuf.write(p) }
func (c *memConn) Close() error {
	return c.writeBuf.close()
}
func (c *memConn) LocalAddr() net.Addr                { return fakeAddr{} }
func (c *memConn) RemoteAddr() net.Addr               { return fakeAddr{} }
func (c *memConn) SetDeadline(t time.Time) error      { return nil }
func (c *memConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *memConn) SetWriteDeadline(t time.Time) error { return nil }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "mem" }
func (fakeAddr) String() string  { return "mem" }

// feedConn is the test-side handle for the non-client end of a memConn pair:
// it lets the test shuttle bytes to/from a real tls.Client without a second
// full TLS stack.
type feedConn struct {
	toClient *memBuf // bridge/test writes here, client reads
	toServer *memBuf // client writes here, bridge/test reads
}

func (f *feedConn) writeToClient(p []byte) error {
	_, err := f.toClient.write(p)
	return err
}

// readFromClient drains whatever the client has written so far, without blocking.
func (f *feedConn) readFromClient() []byte {
	return f.toServer.readAvailable()
}

// newMemConnPair returns a net.Conn suitable for tls.Client, and a feedConn
// handle the test uses to shuttle bytes between that client and the bridge.
func newMemConnPair() (net.Conn, *feedConn) {
	toClient := newMemBuf()
	toServer := newMemBuf()
	client := &memConn{readBuf: toClient, writeBuf: toServer}
	feed := &feedConn{toClient: toClient, toServer: toServer}
	return client, feed
}

// shuttle pumps TLS bytes between a bridge and the real tls.Client on the
// other end of feed until clientDone reports the client-side operation
// (Handshake, or a Handshake+Write, etc.) has completed, or the deadline
// expires. It fatals the test on any transport error or timeout.
//
// Callers MUST wait on clientDone -- the client's own completion signal --
// rather than on bridge.handshakeDone(). The server's final handshake
// flight (ChangeCipherSpec+Finished) is written into the bridge's outbound
// buffer synchronously, just before its Handshake() call returns and
// hsDone is set; a naive "for !bridge.handshakeDone() { pump }" loop can
// observe hsDone==true and exit without ever draining that last flight out
// to the client, leaving the real tls.Client hanging forever. Pumping until
// clientDone fires guarantees every flight the client is waiting on has
// actually been delivered. Task 4/5 tests driving this bridge against a
// real tls.Client should reuse this helper rather than re-deriving the
// pump loop.
func shuttle(t *testing.T, bridge *tlsBridge, feed *feedConn, clientDone <-chan error) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		if out := bridge.readOutbound(); len(out) > 0 {
			if err := feed.writeToClient(out); err != nil {
				t.Fatalf("writeToClient: %v", err)
			}
		}
		if in := feed.readFromClient(); len(in) > 0 {
			if err := bridge.writeInbound(in); err != nil {
				t.Fatalf("writeInbound: %v", err)
			}
		}
		select {
		case err := <-clientDone:
			if err != nil {
				t.Fatalf("client operation failed: %v", err)
			}
			return
		case <-deadline:
			t.Fatal("shuttle timed out waiting for client completion")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

// ---- tests ----

func TestTLSBridgeHandshakeWithRealClient(t *testing.T) {
	serverCfg := testTLSServerConfig(t)
	bridge := newTLSBridge(serverCfg)
	defer func() {
		if err := bridge.close(); err != nil {
			t.Logf("bridge close: %v", err)
		}
	}()

	// A real tls.Client on the other end, connected via an in-memory conn pair.
	clientConn, serverFeed := newMemConnPair()
	clientCfg := testTLSClientConfig(t, serverCfg)
	client := tls.Client(clientConn, clientCfg)

	done := make(chan error, 1)
	go func() { done <- client.HandshakeContext(context.Background()) }()

	shuttle(t, bridge, serverFeed, done)

	// The bridge's own Handshake() call returns essentially in lock-step
	// with producing that final flight, so it should already be done; allow
	// a brief grace period for the goroutine to update hsDone.
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

	if bridge.connState().Version == 0 {
		t.Fatal("bridge reports no negotiated TLS version")
	}
}

func TestTLSBridgeApplicationDataRoundTrip(t *testing.T) {
	serverCfg := testTLSServerConfig(t)
	bridge := newTLSBridge(serverCfg)
	defer func() {
		if err := bridge.close(); err != nil {
			t.Logf("bridge close: %v", err)
		}
	}()

	clientConn, serverFeed := newMemConnPair()
	clientCfg := testTLSClientConfig(t, serverCfg)
	client := tls.Client(clientConn, clientCfg)

	hsDone := make(chan error, 1)
	go func() { hsDone <- client.HandshakeContext(context.Background()) }()

	shuttle(t, bridge, serverFeed, hsDone)

	// Client sends application data through the tunnel to the bridge.
	appWriteDone := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("hello inner AVP"))
		appWriteDone <- err
	}()

	var got []byte
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		readDeadline := time.After(5 * time.Second)
		for {
			select {
			case <-readDeadline:
				return
			default:
			}
			if out := bridge.readOutbound(); len(out) > 0 {
				if err := serverFeed.writeToClient(out); err != nil {
					return
				}
			}
			// Only attempt to read decrypted app data right after feeding a
			// complete inbound chunk: takeAppData waits until the engine has
			// something to decrypt, so calling it with nothing in flight
			// would hang this goroutine forever.
			if in := serverFeed.readFromClient(); len(in) > 0 {
				if err := bridge.writeInbound(in); err != nil {
					return
				}
				data, err := bridge.takeAppData(5 * time.Second)
				if len(data) > 0 {
					got = append(got, data...)
				}
				if err != nil && !errors.Is(err, io.EOF) {
					return
				}
				if len(got) > 0 {
					return
				}
			}
			time.Sleep(time.Millisecond)
		}
	}()

	if err := <-appWriteDone; err != nil {
		t.Fatalf("client write: %v", err)
	}
	<-readDone

	if string(got) != "hello inner AVP" {
		t.Fatalf("takeAppData = %q, want %q", got, "hello inner AVP")
	}
}

// TestTLSBridgeTakeAppDataNeverHangs covers the two ways takeAppData must
// come back rather than park: while the engine is merely waiting for more
// input from the peer it reports "no data" promptly, and once the bridge is
// closed it reports EOF. Either way a caller's goroutine is never pinned by a
// peer that simply stops talking. If the wake-ups behind this were ever
// dropped the test would hang until -timeout killed the binary, so it bounds
// itself and fails informatively instead.
func TestTLSBridgeTakeAppDataNeverHangs(t *testing.T) {
	serverCfg := testTLSServerConfig(t)
	bridge := newTLSBridge(serverCfg)

	// Nothing has been fed, so the engine is parked waiting for input.
	waiting := make(chan error, 1)
	go func() {
		_, err := bridge.takeAppData(10 * time.Second)
		waiting <- err
	}()
	select {
	case err := <-waiting:
		if err != nil {
			t.Fatalf("takeAppData on an idle engine = %v, want no data and no error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("takeAppData did not return while the engine was waiting for input")
	}

	if err := bridge.close(); err != nil {
		t.Logf("bridge close: %v", err)
	}

	closed := make(chan error, 1)
	go func() {
		_, err := bridge.takeAppData(10 * time.Second)
		closed <- err
	}()
	select {
	case err := <-closed:
		if err == nil {
			t.Fatal("takeAppData returned nil error after close, want io.EOF")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("takeAppData did not unblock within 2s after close(); cond.Broadcast likely missing/misrouted")
	}
}

// TestTLSBridgePumpExitsWhenNobodyDrains covers the leak an unauthenticated
// peer can trigger: it packs more application-data records into one flight
// than the pump's channel can buffer, and the terminator stops reading after
// the first chunk (the credentials are in it, or it failed). close() then
// unblocks engineConn.Read, but a pump parked on a channel send is not
// waiting on Read -- without a second wake-up path it never exits, pinning
// the tls.Conn and its buffers for the lifetime of the process.
func TestTLSBridgePumpExitsWhenNobodyDrains(t *testing.T) {
	serverCfg := testTLSServerConfig(t)
	bridge := newTLSBridge(serverCfg)

	clientConn, serverFeed := newMemConnPair()
	clientCfg := testTLSClientConfig(t, serverCfg)
	client := tls.Client(clientConn, clientCfg)

	hsDone := make(chan error, 1)
	go func() { hsDone <- client.HandshakeContext(context.Background()) }()
	shuttle(t, bridge, serverFeed, hsDone)

	// One record per write, more of them than the pump channel can hold.
	writeDone := make(chan error, 1)
	go func() {
		for i := 0; i < 8; i++ {
			if _, err := client.Write([]byte("inner")); err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- nil
	}()
	if err := <-writeDone; err != nil {
		t.Fatalf("client write: %v", err)
	}

	deadline := time.After(5 * time.Second)
	for {
		if in := serverFeed.readFromClient(); len(in) > 0 {
			if err := bridge.writeInbound(in); err != nil {
				t.Fatalf("writeInbound: %v", err)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("client records never reached the bridge")
		default:
			time.Sleep(time.Millisecond)
		}
	}

	// The terminator's behavior: take the first chunk, then stop reading.
	if _, err := bridge.takeAppData(2 * time.Second); err != nil {
		t.Fatalf("takeAppData: %v", err)
	}

	if err := bridge.close(); err != nil {
		t.Logf("bridge close: %v", err)
	}

	select {
	case <-bridge.pumpDone:
	case <-time.After(2 * time.Second):
		t.Fatal("app data pump still running 2s after close(); it is parked on a channel send")
	}
}
