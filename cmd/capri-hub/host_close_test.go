package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/internal/hub"
	"github.com/coder/websocket"
)

// closeSink dials /ws/host and keeps a reader on it: that is what makes the
// library answer the hub's protocol pings, and it is the only place the
// terminal close frame surfaces.
type closeSink struct {
	conn   *websocket.Conn
	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	closed *websocket.CloseError
	done   chan struct{}
}

// dialCloseSink connects a host and starts the reader.
func dialCloseSink(t *testing.T, srv *httptest.Server, tok string) *closeSink {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	conn, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/host",
		&websocket.DialOptions{HTTPHeader: http.Header{
			"Authorization":   []string{"Bearer " + tok},
			"X-Hub-Deflate":   []string{"1"},
			"X-Hub-State-Ack": []string{"1"},
		}})
	if err != nil {
		cancel()
		t.Fatalf("dial: %v", err)
	}
	s := &closeSink{conn: conn, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(s.done)
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				var ce websocket.CloseError
				if errors.As(err, &ce) {
					s.mu.Lock()
					s.closed = &ce
					s.mu.Unlock()
				}
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = conn.Close(websocket.StatusNormalClosure, "")
		cancel()
	})
	return s
}

// send writes one uplink frame.
func (s *closeSink) send(t *testing.T, v any) {
	t.Helper()
	payload, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := s.conn.Write(s.ctx, websocket.MessageText, payload); err != nil {
		t.Fatalf("uplink write: %v", err)
	}
}

// awaitClose returns the close frame the hub sent.
func (s *closeSink) awaitClose(t *testing.T, within time.Duration) websocket.CloseError {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(within):
		t.Fatal("no close frame: the hub never ended the session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed == nil {
		t.Fatal("connection ended without a close frame from the hub")
	}
	return *s.closed
}

// wantClose asserts the exact (code, reason) pair, spelled out literally:
// these strings are the wire contract acp-host switches on, so the assertion
// must fail when a constant changes, not follow it.
func wantClose(t *testing.T, got websocket.CloseError, code websocket.StatusCode, reason string) {
	t.Helper()
	if got.Code != code || got.Reason != reason {
		t.Fatalf("close = (%v, %q), want (%v, %q)", got.Code, got.Reason, code, reason)
	}
}

func newCloseTestServer(t *testing.T) (*hub.Hub, *httptest.Server) {
	t.Helper()
	h := hub.NewWithDir("")
	srv := httptest.NewServer(buildHandler(h, "secret", newFETicketStore(), newPairLimiter(), nil))
	t.Cleanup(srv.Close)
	return h, srv
}

// A host replaced by a newer connection for the same hostId is told exactly
// that. Closing with a bare normal closure (or with 1008 and no reason) is
// what made the host re-pair and throw away a credential that was fine.
func TestHostWSCloseSuperseded(t *testing.T) {
	h, srv := newCloseTestServer(t)
	tok := pairedHost(t, h, srv)

	first := dialCloseSink(t, srv, tok)
	waitHostOnline(t, h, 3*time.Second)

	// A second connection takes the hostId over. The old handler only
	// notices on its next uplink frame, because ownership is checked there.
	second := dialCloseSink(t, srv, tok)
	first.send(t, map[string]any{"v": 1, "type": "host_status", "ready": true})

	wantClose(t, first.awaitClose(t, 5*time.Second), websocket.StatusNormalClosure, "superseded")

	// The replacement must survive: a supersede that also killed it would
	// be a reconnect storm.
	second.send(t, map[string]any{"v": 1, "type": "host_status", "ready": true})
	select {
	case <-second.done:
		got := second.awaitClose(t, time.Second)
		t.Fatalf("replacement connection was closed too: (%v, %q)", got.Code, got.Reason)
	case <-time.After(300 * time.Millisecond):
	}
}

// A half-open link: the peer's pongs stop, the probe gives up, and the host
// is told the probe (not its credential, not the hub) is the problem.
func TestHostWSCloseLivenessProbeTimeout(t *testing.T) {
	probeTiming(t, 20*time.Millisecond, 20*time.Millisecond)
	h, srv := newCloseTestServer(t)
	tok := pairedHost(t, h, srv)

	// Swallow pings so no pong ever proves the link alive.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/host", &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization":   []string{"Bearer " + tok},
			"X-Hub-Deflate":   []string{"1"},
			"X-Hub-State-Ack": []string{"1"},
		},
		OnPingReceived: func(context.Context, []byte) bool { return false },
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	waitHostOnline(t, h, 3*time.Second)

	closeCtx, closeCancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer closeCancel()
	var ce websocket.CloseError
	for {
		_, _, err := conn.Read(closeCtx)
		if err == nil {
			continue
		}
		if !errors.As(err, &ce) {
			t.Fatalf("read ended without a close frame: %v", err)
		}
		break
	}
	wantClose(t, ce, websocket.StatusPolicyViolation, "liveness probe timeout")
}

// The transport backstop has its own reason, so a host can tell "you stopped
// talking" from "I am broken" (1011) or "re-pair" (1008 auth).
func TestHostWSCloseUplinkIdle(t *testing.T) {
	// Both other liveness bounds out of reach: only the idle timer may fire.
	probeTiming(t, time.Hour, time.Hour)
	prev := hostReadTimeout
	hostReadTimeout = 100 * time.Millisecond
	t.Cleanup(func() { hostReadTimeout = prev })

	h, srv := newCloseTestServer(t)
	tok := pairedHost(t, h, srv)
	sink := dialCloseSink(t, srv, tok)
	waitHostOnline(t, h, 3*time.Second)

	wantClose(t, sink.awaitClose(t, 8*time.Second), websocket.StatusGoingAway, "uplink idle timeout")

	// The handler may still be finishing its loop (and reading
	// hostReadTimeout) after the close reaches the sink. Close our end and
	// wait for the registry to drop the host, so the cleanup that restores
	// the package knob cannot race a live handler.
	_ = sink.conn.Close(websocket.StatusNormalClosure, "")
	waitHostGone(t, h, 3*time.Second)
}

// Server shutdown: the request context ends, so the host sees "shutdown" and
// retries with backoff instead of treating the drop as a rejected token.
func TestHostWSCloseShutdown(t *testing.T) {
	probeTiming(t, time.Hour, time.Hour)

	h := hub.NewWithDir("")
	// Stands in for main's runCtx: cancelling it is what a graceful shutdown
	// does to the contexts of handlers that are still running.
	base, cancelBase := context.WithCancel(context.Background())
	t.Cleanup(cancelBase)
	srv := httptest.NewUnstartedServer(buildHandler(h, "secret", newFETicketStore(), newPairLimiter(), nil))
	srv.Config.BaseContext = func(net.Listener) context.Context { return base }
	srv.Start()
	t.Cleanup(srv.Close)
	tok := pairedHost(t, h, srv)

	sink := dialCloseSink(t, srv, tok)
	waitHostOnline(t, h, 3*time.Second)

	cancelBase()

	wantClose(t, sink.awaitClose(t, 8*time.Second), websocket.StatusNormalClosure, "shutdown")
}

// A peer that vanished is reported as "peer closed", not as a liveness or
// auth verdict: nothing about the hub's own health is implied, and the host
// must treat it as an ordinary redial.
//
// (The sibling path — the JSON ping's write failing before the read loop
// notices — reports reasonPingWrite. Both are plain backoff, and forcing one
// or the other from a test would be a race between two real socket errors,
// so only the observable one is asserted here; the table test pins the
// ping string.)
func TestHostWSClosePeerGone(t *testing.T) {
	probeTiming(t, time.Hour, time.Hour)
	prev := hostReadTimeout
	hostReadTimeout = time.Hour // nothing else may end this session
	t.Cleanup(func() { hostReadTimeout = prev })

	h, srv := newCloseTestServer(t)
	tok := pairedHost(t, h, srv)
	sink := dialCloseSink(t, srv, tok)
	waitHostOnline(t, h, 3*time.Second)

	// RST rather than a close handshake: the hub's reader reports the error
	// instead of a clean close from the peer.
	netConn := websocket.NetConn(sink.ctx, sink.conn, websocket.MessageText)
	if tc, ok := netConn.(interface{ SetLinger(int) error }); ok {
		_ = tc.SetLinger(0)
	}
	_ = netConn.Close()

	// The peer cannot read the frame it caused, so this asserts only that the
	// session ended; the value is checked through the reason table.
	waitHostGone(t, h, 8*time.Second)
}

// The table itself: every reason is non-empty, short enough to fit a close
// frame (coder/websocket refuses >123 bytes at write time, so an overlong
// reason would silently degrade to 1011 with no reason), and unique. A
// duplicate would collapse two reconnect policies into one.
func TestHostCloseReasonTable(t *testing.T) {
	all := []struct {
		name string
		c    hostClose
	}{
		{"shutdown", closeShutdown},
		{"superseded", closeSuperseded},
		{"peer gone", closePeerGone},
		{"liveness", closeLiveness},
		{"ping write", closePingWrite},
		{"uplink idle", closeUplinkIdle},
		{"auth", closeAuth},
		{"hello write", closeHelloWrite},
		{"internal", closeInternal},
	}
	seen := make(map[string]string, len(all))
	for _, tc := range all {
		if tc.c.reason == "" {
			t.Errorf("%s: empty reason", tc.name)
		}
		if len(tc.c.reason) > 123 {
			t.Errorf("%s: reason %q too long for a close frame", tc.name, tc.c.reason)
		}
		if prev, dup := seen[tc.c.reason]; dup {
			t.Errorf("%s and %s share reason %q", prev, tc.name, tc.c.reason)
		}
		seen[tc.c.reason] = tc.name
	}
	// The pair the host switches on must separate the two 1000s: a code
	// alone cannot tell "hub restarting" from "you were replaced".
	if closeShutdown.code != closeSuperseded.code {
		t.Fatalf("shutdown and superseded codes diverged (%v vs %v); the reason is the contract, keep one code",
			closeShutdown.code, closeSuperseded.code)
	}
	if closeShutdown.reason == closeSuperseded.reason {
		t.Fatal("shutdown and superseded collapsed into one reason")
	}
}
