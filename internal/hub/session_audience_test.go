package hub

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/wire"
)

// TestSessionDownOverflowCloses: a down log over its byte budget is a hard
// stop — the hub closes with overflow rather than buffering without limit.
// The budget follows the advertised limits.maxRelayBody (2x), so shrinking the
// advertised cap shrinks the log budget with it.
func TestSessionDownOverflowCloses(t *testing.T) {
	prev := SessionLimits
	SessionLimits = wire.DefaultLimits
	SessionLimits.MaxRelayBody = 1 << 10
	t.Cleanup(func() { SessionLimits = prev })

	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	body := json.RawMessage(`{"pad":"` + strings.Repeat("x", 4<<10) + `"}`)
	if _, err := h.Dispatch(t.Context(), "h1", "POST", "/api/prompt", body); err == nil {
		t.Fatal("oversized dispatch was accepted")
	}
	if got := fh.waitReason(2 * time.Second); got != wire.CloseOverflow {
		t.Fatalf("close reason = %s, want overflow", got)
	}
}

// TestSessionAudienceConsumesNoSeq: audience is absolute state on the
// unreliable path, so a request behind it still gets down seq 1.
func TestSessionAudienceConsumesNoSeq(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	_, unsub := h.Subscribe()
	defer unsub()
	if f := fh.recvType(wire.TypeAudience, 2*time.Second); f.Seq != 0 {
		t.Fatalf("audience carries seq %d, want none", f.Seq)
	}

	// Dispatch waits for the request ack, so it runs beside the frame read.
	go func() { _, _ = h.Dispatch(context.Background(), "h1", "GET", "/api/ping", nil) }()
	if got := fh.recvType(wire.TypeRequest, 2*time.Second).Seq; got != 1 {
		t.Fatalf("request seq = %d, want 1 (audience must not consume a seq)", got)
	}
}

// TestSessionAudienceRefreshCorrectsLostFrame: audience has no ack and no
// retransmit entry, so the next heartbeat repeats the newest snapshot. A
// receiver that missed the first copy gets it again with the same gen.
func TestSessionAudienceRefreshCorrectsLostFrame(t *testing.T) {
	shortLiveness(t, 1, 4)
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	_, unsub := h.Subscribe()
	defer unsub()
	lost := fh.recvType(wire.TypeAudience, 2*time.Second) // pretend this one was lost
	again := fh.recvType(wire.TypeAudience, 3*time.Second)

	if again.Gen != lost.Gen || again.Watchers != lost.Watchers || again.All != lost.All {
		t.Fatalf("refresh = %+v, want the same snapshot as %+v", again.AudienceState(), lost.AudienceState())
	}

	// Nothing entered the down log, so there is no ack to wait for.
	h.mu.Lock()
	p := h.hosts["h1"].proto
	h.mu.Unlock()
	if p.hasUnacked() || p.downLen() != 0 {
		t.Fatalf("audience left %d unacked down entries", p.downLen())
	}
}

// TestSessionAudienceNotify: a browser subscribing produces one audience
// frame with a new generation; an unchanged snapshot is not resent.
func TestSessionAudienceNotify(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)
	gen0 := fh.ack.Audience.Gen

	_, unsub := h.Subscribe()
	f := fh.recvType(wire.TypeAudience, 2*time.Second)
	a := f.AudienceState()
	if a.Watchers != 1 || a.Gen <= gen0 {
		t.Fatalf("audience = %+v, want watchers 1 and gen > %d", a, gen0)
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("audience is invalid: %v", err)
	}

	// A notify with an unchanged snapshot must not produce a frame.
	h.notifyAudience()
	fh.noFrame(200 * time.Millisecond)

	unsub()
	f = fh.recvType(wire.TypeAudience, 2*time.Second)
	if a := f.AudienceState(); a.Watchers != 0 || a.Gen <= gen0+1 {
		t.Fatalf("audience after unsub = %+v", a)
	}
}

// TestSessionHeartbeatStatus: an hb snapshot is applied to the registry and
// the host's ack releases the down log.
func TestSessionHeartbeatStatus(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	busy, ready := true, true
	st := wire.HeartbeatStatus{Ready: ready, Busy: busy, PendingCount: 2, Port: 8765, Version: "v0.5.0"}
	frame, err := wire.NewHeartbeat(0, st)
	if err != nil {
		t.Fatal(err)
	}
	fh.send(frame)
	waitFor(t, func() bool {
		hosts := h.ListHosts()
		return hosts[0].Busy && hosts[0].PendingCount == 2 && hosts[0].Port == 8765 &&
			hosts[0].Version == "v0.5.0"
	}, 2*time.Second)
}

// TestSessionUnreadableFrame: a transport that reports an undecodable frame
// ends the session with unreadable so the host replays from its log.
func TestSessionUnreadableFrame(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	ft := newFakeTransport()
	done := make(chan wire.CloseReason, 1)
	go func() { done <- h.ServeHost("", ft) }()

	h.mu.Lock()
	token := h.hosts["h1"].token
	h.mu.Unlock()
	b, _ := wire.Encode(wire.NewHello(wire.Hello{Epoch: 1, Token: token, Resume: &wire.Resume{}, Caps: &wire.Caps{TransportUnits: true}}))
	ft.inbox <- b
	select {
	case <-ft.outbox:
	case <-time.After(2 * time.Second):
		t.Fatal("no hello_ack")
	}

	ft.hangup() // the transport maps its own decode failures to an error
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("session did not end")
	}
}

// ── hub-side test hooks ──────────────────────────────────────────────
