package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/internal/hub"
	"github.com/coder/websocket"
)

// hostFrame is one decoded downlink frame from a host transport.
type hostFrame map[string]any

// hostConn is a test-side host transport: it reads (so the library answers
// the hub's protocol pings) and offers a send func for uplink frames. A
// second dial would SUPERSEDE the connection under test, so every frame a
// test injects must ride this one.
type hostConn struct {
	frames <-chan hostFrame

	mu   sync.Mutex
	conn *websocket.Conn
	ctx  context.Context
}

func (hc *hostConn) send(t *testing.T, v any) {
	t.Helper()
	payload, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	hc.mu.Lock()
	defer hc.mu.Unlock()
	if err := hc.conn.Write(hc.ctx, websocket.MessageText, payload); err != nil {
		t.Fatalf("uplink write: %v", err)
	}
}

// dialHost connects to /ws/host with extra handshake headers, defaulting the
// protocol capability headers (unless hdr already has one, possibly empty).
func dialHost(t *testing.T, srv *httptest.Server, tok string, hdr http.Header) (*hostConn, func()) {
	t.Helper()
	if hdr == nil {
		hdr = http.Header{}
	}
	hdr.Set("Authorization", "Bearer "+tok)
	if _, ok := hdr["X-Hub-Deflate"]; !ok {
		hdr.Set("X-Hub-Deflate", "1")
	}
	if _, ok := hdr["X-Hub-State-Ack"]; !ok {
		hdr.Set("X-Hub-State-Ack", "1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	conn, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/host",
		&websocket.DialOptions{HTTPHeader: hdr})
	if err != nil {
		cancel()
		t.Fatalf("dial: %v", err)
	}
	out := make(chan hostFrame, 256)
	go func() {
		defer close(out)
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var f hostFrame
			if json.Unmarshal(data, &f) != nil {
				continue
			}
			select {
			case out <- f:
			default:
			}
		}
	}()
	stop := func() {
		_ = conn.Close(websocket.StatusNormalClosure, "")
		cancel()
	}
	return &hostConn{frames: out, conn: conn, ctx: ctx}, stop
}

// awaitFrame returns the first frame of typ, failing the test on timeout.
func awaitFrame(t *testing.T, frames <-chan hostFrame, typ string, within time.Duration) hostFrame {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				t.Fatalf("connection closed while waiting for %q", typ)
			}
			if f["type"] == typ {
				return f
			}
		case <-deadline:
			t.Fatalf("no %q frame within %s", typ, within)
		}
	}
}

// pairHost pairs hostID directly through the hub API — tests that only need
// a registry entry and not a live HTTP transport.
func pairHost(t *testing.T, h *hub.Hub, hostID string) {
	t.Helper()
	code, _ := h.PairingCode()
	if _, err := h.Pair(code, hostID, strings.ToUpper(hostID)); err != nil {
		t.Fatalf("pair %s: %v", hostID, err)
	}
}

// negotiationHub starts a hub with one paired host and returns both.
func negotiationHub(t *testing.T) (*hub.Hub, *httptest.Server, string) {
	t.Helper()
	h := hub.NewWithDir("")
	srv := httptest.NewServer(buildHandler(h, "secret", newFETicketStore(), newPairLimiter(), nil))
	t.Cleanup(srv.Close)
	return h, srv, pairedHost(t, h, srv)
}

// A host that speaks the protocol is tracked from the moment it connects:
// edge-triggered state frames stay unconfirmed until the host acks them.
func TestHostWSStateAckTracking(t *testing.T) {
	h, srv, tok := negotiationHub(t)
	hc, stop := dialHost(t, srv, tok, nil)
	defer stop()

	awaitFrame(t, hc.frames, "hello", 3*time.Second)
	waitHostOnline(t, h, 3*time.Second)

	// A browser arriving bumps the per-host count: that edge frame must be
	// unconfirmed until the host acks it.
	_, unsub := h.Subscribe()
	defer unsub()
	frame := awaitFrame(t, hc.frames, "subscribers", 3*time.Second)
	genF, _ := frame["gen"].(float64)
	if genF == 0 {
		t.Fatalf("subscribers frame carries no gen: %v", frame)
	}
	gen := uint64(genF)
	if got, ok := h.UnackedState("h1", "subscribers"); !ok || got != gen {
		t.Fatalf("unacked subscribers = %d,%v; want gen %d", got, ok, gen)
	}

	hc.send(t, map[string]any{"v": 1, "type": "state_ack", "kind": "subscribers", "gen": gen})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := h.UnackedState("h1", "subscribers"); !ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("state_ack did not clear the unacked entry")
}

// A host that does not offer confirmed state delivery in its handshake is
// running an older protocol and is dropped with a protocol-version close.
func TestHostWSRequiresStateAck(t *testing.T) {
	h, srv, tok := negotiationHub(t)
	hc, stop := dialHost(t, srv, tok, http.Header{"X-Hub-State-Ack": []string{""}})
	defer stop()

	// The hub closes with a protocol-version reason and never sends hello.
	select {
	case f, ok := <-hc.frames:
		if ok {
			t.Fatalf("a plain host must not receive %v", f)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("plain host was left connected")
	}
	if hosts := h.ListHosts(); len(hosts) == 1 && hosts[0].Online {
		t.Fatal("a plain host must not be registered online")
	}
}

// The ping is the data-plane delivery ack only: absolute state rides its own
// confirmed frames, so no host ever sees subscribers/viewing piggy-backed on
// it.
func TestHostPingCarriesOnlyDataPlaneAck(t *testing.T) {
	h := hub.NewWithDir("")
	pairHost(t, h, "h1")

	var raw []byte
	if err := writeHostPing(h, "h1", func(p []byte) error { raw = p; return nil }); err != nil {
		t.Fatalf("writeHostPing: %v", err)
	}

	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("ping: %v", err)
	}
	for _, k := range []string{"subscribers", "subsGen", "viewing"} {
		if _, ok := got[k]; ok {
			t.Errorf("ping still carries absolute state %q: %s", k, raw)
		}
	}
	if _, ok := got["seq"]; !ok {
		t.Errorf("ping dropped the data-plane seq ack: %s", raw)
	}
}
