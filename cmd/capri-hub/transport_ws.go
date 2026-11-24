package main

import (
	"context"
	"fmt"
	"github.com/AgentsHarness/capri-hub/internal/hub"
	"github.com/AgentsHarness/capri-hub/wire"
	"github.com/coder/websocket"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ── host transports ───────────────────────────────────────────────────
//
// One Transport adapter per wire. Both hand the hub complete JSON frames —
// transport units are a transport detail, reassembled before the session sees
// them — and let hub.ServeHost own the session: handshake, seq/ack, retransmit,
// liveness and the close reason all live there. Nothing below interprets the
// protocol.

// defaultHostWriteTimeout caps one downlink write until the session applies
// the configured value (three quarters of the advertised idle period) at
// handshake, so a half-open peer cannot pin a writer forever.
const defaultHostWriteTimeout = 15 * time.Second

// hostFrameLimit bounds one frame (compressed or not) on either transport. A
// relayed respond carries up to 28MB of body, so a tighter cap would kill the
// link on a large history read.
const hostFrameLimit = 32 << 20

// quicPreAuthFrameLimit bounds the control-stream frame a QUIC peer may send
// before hello/token validation. A hello is tiny; keeping this far below the
// post-auth frame limit prevents unauth connections from parking large
// buffers in the reassembler.
const quicPreAuthFrameLimit = 1 << 20

// ── WebSocket ─────────────────────────────────────────────────────────

// wsTransport adapts one /ws/host WebSocket. After hello_ack echoes
// caps.transportUnits the downlink is a text message per complete frame and a
// binary message per transport unit; the uplink accepts the same split, with
// a compressed unit only after caps.deflate was echoed.
type wsTransport struct {
	conn *websocket.Conn
	// deflate is set by the session once the capability was negotiated.
	deflate atomic.Bool
	// stop ends the transport keepalive loop.
	stop      chan struct{}
	closeOnce sync.Once

	// reassembler turns uplink units back into frames; Recv is called from a
	// single reader goroutine, so it needs no lock.
	reassembler wire.Reassembler

	lastActivity atomic.Int64 // unix nanos of the last successful read
	maxFrameVal  atomic.Int64 // 0 until the session applies limits.maxFrame
	writeTimeout atomic.Int64 // 0 until the session applies idle*3/4
}

func newWSTransport(conn *websocket.Conn) *wsTransport {
	return &wsTransport{conn: conn, stop: make(chan struct{})}
}

func (t *wsTransport) Send(payload []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), t.timeout())
	defer cancel()
	return t.conn.Write(ctx, websocket.MessageText, payload)
}

// SendFragment writes one encoded transport unit as a binary message.
func (t *wsTransport) SendFragment(unit []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), t.timeout())
	defer cancel()
	return t.conn.Write(ctx, websocket.MessageBinary, unit)
}

// Recv returns one complete logical frame: text is a whole frame, binary is a
// unit that may need assembly with later ones before it becomes a frame.
func (t *wsTransport) Recv() ([]byte, error) {
	for {
		typ, data, err := t.conn.Read(context.Background())
		if err != nil {
			return nil, err
		}
		t.lastActivity.Store(time.Now().UnixNano())
		switch typ {
		case websocket.MessageText:
			return data, nil
		case websocket.MessageBinary:
			frame, compressed, complete, err := t.reassembler.Accept(data, t.frameLimit())
			if err != nil {
				return nil, fmt.Errorf("%w: transport unit: %v", wire.ErrUnreadable, err)
			}
			if !complete {
				continue
			}
			if !compressed {
				return frame, nil
			}
			if !t.deflate.Load() {
				return nil, fmt.Errorf("%w: compressed unit without deflate negotiation", wire.ErrUnreadable)
			}
			out, err := inflateUplink(frame)
			if err != nil {
				return nil, fmt.Errorf("%w: inflate: %v", wire.ErrUnreadable, err)
			}
			return out, nil
		default:
			return nil, fmt.Errorf("%w: unsupported message type %v", wire.ErrUnreadable, typ)
		}
	}
}

func (t *wsTransport) SetDeflate(v bool) { t.deflate.Store(v) }

func (t *wsTransport) SetWriteTimeout(d time.Duration) {
	if d > 0 {
		t.writeTimeout.Store(int64(d))
	}
}

func (t *wsTransport) SetMaxFrame(n int) {
	if n > 0 {
		t.maxFrameVal.Store(int64(n))
	}
}

func (t *wsTransport) LastActivity() time.Time {
	n := t.lastActivity.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

func (t *wsTransport) timeout() time.Duration {
	if d := time.Duration(t.writeTimeout.Load()); d > 0 {
		return d
	}
	return defaultHostWriteTimeout
}

func (t *wsTransport) frameLimit() int {
	if n := int(t.maxFrameVal.Load()); n > 0 {
		return n
	}
	return hostFrameLimit
}

// SetKeepalive runs WS control pings at the negotiated cadence. The ping is
// not a protocol signal: it keeps NAT bindings alive and surfaces half-open
// sockets. Idle is enforced by the session's own received-frame clock.
func (t *wsTransport) SetKeepalive(d time.Duration) {
	if d <= 0 {
		d = 10 * time.Second
	}
	go func() {
		ticker := time.NewTicker(d)
		defer ticker.Stop()
		for {
			select {
			case <-t.stop:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), d)
				err := t.conn.Ping(ctx)
				cancel()
				if err != nil {
					return // the session's next read or write ends it
				}
			}
		}
	}()
}

// Close maps the session verdict onto the one WS close table.
func (t *wsTransport) Close(r wire.CloseReason) error {
	t.closeOnce.Do(func() { close(t.stop) })
	code, reason := r.WS()
	return t.conn.Close(websocket.StatusCode(code), reason)
}

// handleHostWS: host outbound WebSocket. The bearer token authenticates the
// upgrade; hello carries the epoch and the same token, and the session checks
// the two agree.
func handleHostWS(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hostID, ok := authHost(h, r)
		if !ok {
			writeJSON(w, 401, map[string]any{"ok": false, "error": "token 无效"})
			return
		}
		if q := r.URL.Query().Get("host"); q != "" && q != hostID {
			writeJSON(w, 403, map[string]any{"ok": false, "error": "host 与 token 不匹配"})
			return
		}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			// Hosts are non-browser clients; skip Origin checks.
			InsecureSkipVerify: true,
		})
		if err != nil {
			log.Printf("[capri-hub] host ws accept: %v", err)
			return
		}
		conn.SetReadLimit(hostFrameLimit)
		reason := h.ServeHost(hostID, newWSTransport(conn))
		log.Printf("[capri-hub] host %s ws session ended (%s)", hostID, reason)
	}
}
