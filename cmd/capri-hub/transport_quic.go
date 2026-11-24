package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/AgentsHarness/capri-hub/internal/hub"
	"github.com/AgentsHarness/capri-hub/wire"
	"github.com/quic-go/quic-go"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ── QUIC host transport ──────────────────────────────────────────────

// quicTLSConfig returns a TLS config for the QUIC listener: from
// QUIC_CERT/QUIC_KEY files when set, else a generated self-signed cert
// when allowSelfSigned is true. Production (FE_TOKEN set) should pass
// false so a missing cert fails closed and Hosts fall back to WS.
// Hosts typically use InsecureSkipVerify for self-signed (documented;
// FE never touches QUIC).
func quicTLSConfig(allowSelfSigned bool) (*tls.Config, error) {
	certFile := os.Getenv("QUIC_CERT")
	keyFile := os.Getenv("QUIC_KEY")
	// Shared ALPN so host clients can dial with the same protocol id.
	const alpn = "capri-hub"
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{alpn}}, nil
	}
	if !allowSelfSigned {
		return nil, fmt.Errorf("QUIC_CERT/QUIC_KEY required when FE_TOKEN is set (set QUIC_ALLOW_SELF_SIGNED=1 only for lab use)")
	}
	// Self-sign in memory (dev / explicit allow).
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "capri-hub"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{alpn}}, nil
}

// listenQUIC opens the UDP QUIC listener for host transport.
func listenQUIC(port int, tlsConf *tls.Config) (*quic.Listener, error) {
	addr := fmt.Sprintf(":%d", port)
	return quic.ListenAddr(addr, tlsConf, &quic.Config{KeepAlivePeriod: 10 * time.Second})
}

// serveQUIC accepts host connections over an already-open QUIC listener.
// One bidirectional stream per connection carries the same JSON frame
// protocol as /ws/host; auth is the first frame {type:"auth", token}.
// Closing the listener ends the accept loop (graceful shutdown).
func serveQUIC(ln *quic.Listener, h *hub.Hub) {
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			// Listener closed on shutdown, or unrecoverable accept error.
			if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "closed") {
				return
			}
			log.Printf("[capri-hub] QUIC accept: %v", err)
			continue
		}
		go serveQUICConn(conn, h)
	}
}

// quicTransport adapts one host QUIC connection. The control stream carries
// the session in both directions as length-prefixed transport units; request
// streams carry the host's `respond` frames as complete length-prefixed
// frames (no units: a request stream is already per-request).
type quicTransport struct {
	conn      *quic.Conn
	control   *quic.Stream
	frames    chan []byte
	term      chan struct{}
	termOnce  sync.Once
	termMu    sync.Mutex
	termErr   error
	stop      chan struct{}
	closeOnce sync.Once

	// reassembler turns control-stream units back into frames; only
	// readControl touches it.
	reassembler  wire.Reassembler
	deflate      atomic.Bool
	lastActivity atomic.Int64
	maxFrameVal  atomic.Int64
	writeTimeout atomic.Int64
	frameID      atomic.Uint32
	// requestStart runs at most once, after ServeHost has validated hello's
	// token. Request streams are the host's relay-response plane; accepting
	// them before authentication let an unauthenticated peer queue 64 ×
	// 32MB frames per connection.
	requestStart sync.Once
}

func newQUICTransport(conn *quic.Conn, control *quic.Stream) *quicTransport {
	t := &quicTransport{
		conn:    conn,
		control: control,
		// Small queue: before auth the frame limit is 1MiB, and after auth
		// every queued frame can be an 8MiB event. Eight slots still absorb
		// a normal relay burst without letting one connection pin hundreds
		// of megabytes.
		frames: make(chan []byte, 8),
		term:   make(chan struct{}),
		stop:   make(chan struct{}),
	}
	// Until hello is validated, only a small handshake frame is possible.
	t.maxFrameVal.Store(quicPreAuthFrameLimit)
	go t.readControl()
	return t
}

// StartRequestStreams begins accepting the host's per-request response
// streams. hub.ServeHost calls it after the hello token has been verified;
// it is a no-op for every transport that does not implement it (WebSocket).
func (t *quicTransport) StartRequestStreams() {
	t.requestStart.Do(func() { go t.acceptRequests() })
}

// fail records the terminal transport error once. Recv drains frames that
// readControl already queued before it reports the error: a close racing the
// last frames must not throw them away.
func (t *quicTransport) fail(err error) {
	t.termOnce.Do(func() {
		t.termMu.Lock()
		t.termErr = err
		t.termMu.Unlock()
		close(t.term)
	})
}

func (t *quicTransport) terminalError() error {
	t.termMu.Lock()
	defer t.termMu.Unlock()
	if t.termErr == nil {
		return io.EOF
	}
	return t.termErr
}

// Send writes one complete logical frame as one transport unit.
func (t *quicTransport) Send(payload []byte) error {
	units, err := wire.SplitFrame(payload, false, t.nextFrameID(), wire.UnitSize)
	if err != nil {
		return err
	}
	for _, unit := range units {
		if err := t.writeUnit(unit); err != nil {
			return err
		}
	}
	return nil
}

// SendFragment writes one already-encoded transport unit.
func (t *quicTransport) SendFragment(unit []byte) error { return t.writeUnit(unit) }

func (t *quicTransport) writeUnit(unit []byte) error {
	if err := t.control.SetWriteDeadline(time.Now().Add(t.timeout())); err != nil {
		return err
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(unit)))
	if _, err := t.control.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := t.control.Write(unit)
	return err
}

func (t *quicTransport) Recv() ([]byte, error) {
	// Complete frames already queued by readControl win over the terminal
	// error: the reader may have queued every frame and then hit EOF, and a
	// select over both channels would otherwise drop the tail at random.
	select {
	case b := <-t.frames:
		return b, nil
	default:
	}
	select {
	case b := <-t.frames:
		return b, nil
	case <-t.stop:
		return nil, io.EOF
	case <-t.term:
		// The terminal signal is sticky; one more non-blocking drain picks up
		// a frame queued in the same instant.
		select {
		case b := <-t.frames:
			return b, nil
		default:
		}
		return nil, t.terminalError()
	}
}

// SetKeepalive is a no-op: QUIC's keepalive is a per-connection transport
// option set when the listener dials (see listenQUIC), not a per-stream one.
func (t *quicTransport) SetKeepalive(time.Duration) {}

func (t *quicTransport) SetDeflate(v bool) { t.deflate.Store(v) }

func (t *quicTransport) SetWriteTimeout(d time.Duration) {
	if d > 0 {
		t.writeTimeout.Store(int64(d))
	}
}

func (t *quicTransport) SetMaxFrame(n int) {
	if n > 0 {
		t.maxFrameVal.Store(int64(n))
	}
}

func (t *quicTransport) LastActivity() time.Time {
	n := t.lastActivity.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

func (t *quicTransport) timeout() time.Duration {
	if d := time.Duration(t.writeTimeout.Load()); d > 0 {
		return d
	}
	return defaultHostWriteTimeout
}

func (t *quicTransport) frameLimit() int {
	if n := int(t.maxFrameVal.Load()); n > 0 {
		return n
	}
	return hostFrameLimit
}

// nextFrameID keeps control-frame ids in a namespace disjoint from the
// writer's fragment ids. Both share the one control stream, and a complete
// unit that reuses the open fragment's frameID is a protocol error, so two
// independent counters starting at 1 would collide on the first interleaved
// heartbeat.
func (t *quicTransport) nextFrameID() uint32 { return 1<<31 | t.frameID.Add(1) }

func (t *quicTransport) Close(r wire.CloseReason) error {
	t.closeOnce.Do(func() { close(t.stop) })
	_ = t.control.Close()
	return t.conn.CloseWithError(quic.ApplicationErrorCode(r.QUICCode()), r.String())
}

// readControl turns control-stream units back into frames and hands each
// complete one to Recv. Compressed frames are inflated once the whole unit
// sequence arrived.
func (t *quicTransport) readControl() {
	for {
		unit, err := readQUICUnit(t.control)
		if err != nil {
			t.fail(err)
			return
		}
		t.lastActivity.Store(time.Now().UnixNano())
		frame, compressed, complete, err := t.reassembler.Accept(unit, t.frameLimit())
		if err != nil {
			t.fail(fmt.Errorf("%w: transport unit: %v", wire.ErrUnreadable, err))
			return
		}
		if !complete {
			continue
		}
		if compressed {
			if !t.deflate.Load() {
				t.fail(fmt.Errorf("%w: compressed unit without deflate negotiation", wire.ErrUnreadable))
				return
			}
			out, err := inflateUplink(frame)
			if err != nil {
				t.fail(fmt.Errorf("%w: inflate: %v", wire.ErrUnreadable, err))
				return
			}
			frame = out
		}
		select {
		case t.frames <- frame:
		case <-t.stop:
			return
		}
	}
}

// acceptRequests drains request streams. Each stream is silent by design
// between dispatch and the host's answer, so its read deadline tracks the
// relay budget; a stream ending is normal and must not end the session.
func (t *quicTransport) acceptRequests() {
	for {
		stream, err := t.conn.AcceptStream(context.Background())
		if err != nil {
			t.fail(err)
			return
		}
		go func(stream *quic.Stream) {
			defer stream.Close()
			for {
				b, err := readQUICFrame(stream, hub.RelayTimeout)
				if err != nil {
					return // EOF / timeout / reset: end of this stream only
				}
				t.lastActivity.Store(time.Now().UnixNano())
				select {
				case t.frames <- b:
				case <-t.stop:
					return
				}
			}
		}(stream)
	}
}

// serveQUICConn serves one host QUIC connection: accept the control stream,
// hand it to the session, and let the transport adapters do the rest.
func serveQUICConn(conn *quic.Conn, h *hub.Hub) {
	// A panic in a bare goroutine (no net/http recover) would kill the whole
	// hub; contain it and drop just this connection.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[capri-hub] quic conn panic recovered: %v", r)
			_ = conn.CloseWithError(quic.ApplicationErrorCode(wire.CloseNormal.QUICCode()), fmt.Sprint(r))
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	stream, err := conn.AcceptStream(ctx)
	cancel()
	if err != nil {
		_ = conn.CloseWithError(0, "no control stream")
		return
	}
	reason := h.ServeHost("", newQUICTransport(conn, stream))
	log.Printf("[capri-hub] host quic session ended (%s) %s", reason, conn.RemoteAddr())
}

// readQUICUnit reads one length-prefixed transport unit from the control
// stream. The length prefix is plain: compression is a unit flag, not a prefix
// bit, on the unit-carrying stream.
func readQUICUnit(stream *quic.Stream) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	// The control stream carries complete logical frames, whose protocol cap
	// is the negotiated maxFrame (8MiB by default), never a relay response.
	if n > uint32(wire.DefaultLimits.MaxFrame) {
		return nil, fmt.Errorf("%w: unit too large: %d", wire.ErrUnreadable, n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(stream, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// readQUICFrame reads one length-prefixed complete frame (bit 31 = raw
// deflate). Request streams keep this framing and are never unit-fragmented.
// readTimeout > 0 arms a per-read deadline for request streams.
func readQUICFrame(stream *quic.Stream, readTimeout time.Duration) ([]byte, error) {
	if readTimeout > 0 {
		if err := stream.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			return nil, err
		}
	}
	var lenBuf [4]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return nil, err
	}
	n, compressed := parseUplinkLen(binary.BigEndian.Uint32(lenBuf[:]))
	if n > hostFrameLimit {
		return nil, fmt.Errorf("%w: frame too large: %d", wire.ErrUnreadable, n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(stream, buf); err != nil {
		return nil, err
	}
	if !compressed {
		return buf, nil
	}
	out, err := inflateUplink(buf)
	if err != nil {
		return nil, fmt.Errorf("%w: inflate: %v", wire.ErrUnreadable, err)
	}
	return out, nil
}
