package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/internal/hub"
	"github.com/coder/websocket"
)

// hostEpochSeq hands every test host connection a distinct epoch, so a
// re-dial in a test is a new sequence space unless it deliberately reuses one.
var hostEpochSeq atomic.Uint64

// dialPairedHost pairs a host, opens its /ws/host WebSocket and performs the
// v3 handshake (hello → hello_ack). The connection is returned ready for
// events / requests.
func dialPairedHost(t *testing.T, ctx context.Context, srv *httptest.Server, h *hub.Hub, hostID, name string) *websocket.Conn {
	t.Helper()
	code, _ := h.PairingCode()
	token, err := h.Pair(code, hostID, name)
	if err != nil {
		t.Fatalf("pair %s: %v", hostID, err)
	}
	return dialHostWithToken(t, ctx, srv, hostID, token, 1000+hostEpochSeq.Add(1))
}

// dialHostWithToken opens /ws/host for token and completes the handshake with
// the given epoch.
func dialHostWithToken(t *testing.T, ctx context.Context, srv *httptest.Server, hostID, token string, epoch uint64) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/host", &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}},
	})
	if err != nil {
		t.Fatalf("host ws dial %s: %v", hostID, err)
	}
	conn.SetReadLimit(32 << 20)
	hello, _ := json.Marshal(map[string]any{
		"v": 3, "type": "hello", "epoch": epoch, "token": token,
		"resume": map[string]any{"up": 0, "down": 0},
		"caps":   map[string]any{"transportUnits": true},
	})
	if err := conn.Write(ctx, websocket.MessageText, hello); err != nil {
		t.Fatalf("host hello %s: %v", hostID, err)
	}
	_, raw, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("host hello_ack %s: %v", hostID, err)
	}
	var ack map[string]any
	if json.Unmarshal(raw, &ack) != nil || ack["type"] != "hello_ack" {
		t.Fatalf("host hello_ack frame %s = %s", hostID, raw)
	}
	return conn
}

// answerRelayProbe replies to the hub's preflight/liveness probe on a fake
// host. It reports whether frame was a probe and has been handled.
func answerRelayProbe(ctx context.Context, conn *websocket.Conn, frame map[string]any) bool {
	if frame["type"] != "hb" {
		return false
	}
	n, ok := frame["probe"].(float64)
	if !ok || n == 0 {
		return false
	}
	out, _ := json.Marshal(map[string]any{
		"v": 3, "type": "hb", "probeAck": uint64(n), "status": map[string]any{},
	})
	_ = conn.Write(ctx, websocket.MessageText, out)
	return true
}

// pushHostEvent sends one events frame from a host uplink. The session seq
// space is the event seq space, so the frame seq is the event's seq.
func pushHostEvent(t *testing.T, ctx context.Context, conn *websocket.Conn, seq int, body map[string]any) {
	t.Helper()
	ev := map[string]any{"seq": seq}
	for k, v := range body {
		ev[k] = v
	}
	frame, _ := json.Marshal(map[string]any{
		"v": 3, "type": "events", "seq": seq, "ack": 0,
		"events": []map[string]any{ev},
	})
	if err := conn.Write(ctx, websocket.MessageText, frame); err != nil {
		t.Fatalf("host write: %v", err)
	}
}

// feFrames reads FE WS frames into a channel. Per-read context timeouts are
// NOT usable here — a cancelled Read tears the connection down in this
// library — so one long-lived reader owns the connection and the test
// selects on the channel instead.
func feFrames(ctx context.Context, conn *websocket.Conn) chan map[string]any {
	out := make(chan map[string]any, 256)
	go func() {
		defer close(out)
		for {
			_, raw, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var f map[string]any
			if json.Unmarshal(raw, &f) != nil {
				continue
			}
			out <- f
		}
	}()
	return out
}

// chunkTextsOf collects events-frame chunk texts (and everything else) for d,
// returning the texts and any frame of wantType seen along the way.
func chunkTextsOf(ctx context.Context, frames chan map[string]any, d time.Duration) []string {
	var out []string
	deadline := time.After(d)
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				return out
			}
			if f["type"] != "events" {
				continue
			}
			evs, _ := f["events"].([]any)
			for _, e := range evs {
				m, _ := e.(map[string]any)
				if m["type"] == "chunk" {
					if txt, _ := m["text"].(string); txt != "" {
						out = append(out, txt)
					}
				}
			}
		case <-deadline:
			return out
		case <-ctx.Done():
			return out
		}
	}
}

// waitForFrameType returns the next frame of the given type, or nil after d.
func waitForFrameType(frames chan map[string]any, typ string, d time.Duration) map[string]any {
	deadline := time.After(d)
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				return nil
			}
			if f["type"] == typ {
				return f
			}
		case <-deadline:
			return nil
		}
	}
}
