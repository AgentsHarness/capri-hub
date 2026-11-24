package hub

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/wire"
)

// TestSessionProbeAckKeepsSessionAlive: after silence the hub probes; each
// probe ack keeps the session alive past several probe intervals.
func TestSessionProbeAckKeepsSessionAlive(t *testing.T) {
	shortLiveness(t, 1, 10)
	shortProbe(t, 200*time.Millisecond, 200*time.Millisecond)
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	var probes int
	deadline := time.Now().Add(1200 * time.Millisecond)
	for time.Now().Before(deadline) {
		select {
		case raw := <-fh.ft.outbox:
			f, err := wire.Decode(raw)
			if err != nil {
				t.Fatalf("decode downlink: %v", err)
			}
			if f.Type == wire.TypeHeartbeat && f.Probe != 0 {
				probes++
				ack, err := wire.NewHeartbeatProbe(0, f.Probe, wire.HeartbeatStatus{}, true)
				if err != nil {
					t.Fatal(err)
				}
				fh.send(ack)
			}
		case <-fh.done:
			t.Fatalf("session closed despite probe acks")
		case <-time.After(50 * time.Millisecond):
		}
	}
	if probes == 0 {
		t.Fatal("no liveness probe was sent after silence")
	}
	select {
	case r := <-fh.end:
		t.Fatalf("session ended: %s", r)
	default:
	}
}

// TestSessionProbeTimeoutClosesLiveness: a probe the host never answers ends
// the session with liveness, ahead of the idle timer.
func TestSessionProbeTimeoutClosesLiveness(t *testing.T) {
	shortLiveness(t, 5, 20)
	shortProbe(t, 100*time.Millisecond, 150*time.Millisecond)
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	sawProbe := false
	timeout := time.After(3 * time.Second)
	for !sawProbe {
		select {
		case raw := <-fh.ft.outbox:
			f, err := wire.Decode(raw)
			if err != nil {
				t.Fatalf("decode downlink: %v", err)
			}
			if f.Type == wire.TypeHeartbeat && f.Probe != 0 {
				sawProbe = true
			}
		case <-timeout:
			t.Fatal("no probe was sent")
		}
	}
	if got := fh.waitReason(3 * time.Second); got != wire.CloseLiveness {
		t.Fatalf("close reason = %s, want liveness", got)
	}
}

// TestSessionLastSeenAdvancesOnHostFrame: every host frame refreshes the
// registry stamp without broadcasting hosts_changed.
func TestSessionLastSeenAdvancesOnHostFrame(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	h.mu.Lock()
	before := h.hosts["h1"].info.LastSeen
	h.mu.Unlock()
	time.Sleep(20 * time.Millisecond)

	hb, err := wire.NewHeartbeat(0, wire.HeartbeatStatus{Ready: true})
	if err != nil {
		t.Fatal(err)
	}
	fh.send(hb)
	waitFor(t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.hosts["h1"].info.LastSeen.After(before)
	}, 2*time.Second)
}

// TestSessionHelloRequiresTransportUnits: a peer that cannot reassemble units
// is speaking the wrong protocol.
func TestSessionHelloRequiresTransportUnits(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	h.mu.Lock()
	token := h.hosts["h1"].token
	h.mu.Unlock()

	ft := newFakeTransport()
	done := make(chan wire.CloseReason, 1)
	go func() { done <- h.ServeHost("", ft) }()
	b, err := wire.Encode(wire.NewHello(wire.Hello{
		Epoch: 1, Token: token, Resume: &wire.Resume{}, Caps: &wire.Caps{Deflate: true},
	}))
	if err != nil {
		t.Fatal(err)
	}
	ft.inbox <- b
	select {
	case got := <-done:
		if got != wire.CloseProtocol {
			t.Fatalf("close reason = %s, want protocol", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("session did not close")
	}
}

// TestSessionSurvivesSlowAnswer: a 5.1s wait before the answer used to trip
// the old 5s fast-read window. With no ack deadline, a slow host answer must
// resolve instead of failing the request.
func TestSessionSurvivesSlowAnswer(t *testing.T) {
	shortLiveness(t, 5, 20)
	shortProbe(t, 30*time.Second, 3*time.Second)
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	done := make(chan RelayResponse, 1)
	go func() {
		resp, _ := h.Dispatch(context.Background(), "h1", "POST", "/api/session-updates", nil)
		done <- resp
	}()
	req := fh.recvType(wire.TypeRequest, 2*time.Second)
	time.Sleep(5100 * time.Millisecond)
	fh.send(wire.Frame{V: wire.ProtocolVersion, Type: wire.TypeHeartbeat, Ack: req.Seq, Status: json.RawMessage(`{}`)})
	fh.send(wire.Frame{
		V: wire.ProtocolVersion, Type: wire.TypeRespond, Ack: req.Seq, ChunkSeq: 1,
		ReqID: req.ReqID, Status: json.RawMessage(`200`), Body: json.RawMessage(`{"ok":true}`),
	})
	select {
	case resp := <-done:
		if resp.Status != 200 {
			t.Fatalf("status = %d, want 200; a slow answer must still resolve", resp.Status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dispatch did not resolve after the 5.1s answer")
	}
}
