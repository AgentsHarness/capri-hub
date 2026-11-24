package hub

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/wire"
)

// shortPendingGrace shrinks the detach grace for one test.
func shortPendingGrace(t *testing.T, d time.Duration) {
	t.Helper()
	prev := pendingGrace
	pendingGrace = d
	t.Cleanup(func() { pendingGrace = prev })
}

// waitDetached waits until hostID has no attached session.
func waitDetached(t *testing.T, h *Hub, hostID string) {
	t.Helper()
	waitFor(t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		hs := h.hosts[hostID]
		return hs != nil && hs.session == nil
	}, 2*time.Second)
}

// TestDetachGraceKeepsRequestForSameEpoch: a transport drop must not fail a
// request the host may already be running. The pending entry survives, the
// same-epoch reconnect replays the down log, and the answer reaches the
// browser.
func TestDetachGraceKeepsRequestForSameEpoch(t *testing.T) {
	shortPendingGrace(t, 2*time.Second)
	shortLiveness(t, 1, 10)
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	type result struct {
		resp RelayResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := h.Dispatch(context.Background(), "h1", "POST", "/api/prompt", nil)
		done <- result{resp, err}
	}()
	req := fh.recvType(wire.TypeRequest, 2*time.Second)

	fh.ft.hangup()
	waitDetached(t, h, "h1")

	h.mu.Lock()
	_, still := h.pending["h1"][req.ReqID]
	h.mu.Unlock()
	if !still {
		t.Fatal("detach dropped a pending request the host may have executed")
	}
	select {
	case r := <-done:
		t.Fatalf("request failed on detach: %+v / %v", r.resp, r.err)
	case <-time.After(200 * time.Millisecond):
	}

	again := dialFakeHost(t, h, "h1", 1)
	replay := again.recvType(wire.TypeRequest, 2*time.Second)
	if replay.ReqID != req.ReqID || replay.Seq != req.Seq {
		t.Fatalf("replayed request = seq %d req %q, want seq %d req %q",
			replay.Seq, replay.ReqID, req.Seq, req.ReqID)
	}
	again.send(wire.Frame{
		V: wire.ProtocolVersion, Type: wire.TypeRespond, Ack: replay.Seq, ChunkSeq: 1,
		ReqID: replay.ReqID, Status: json.RawMessage(`200`), Body: json.RawMessage(`{"ok":true}`),
	})
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("dispatch after same-epoch resume: %v", r.err)
		}
		if r.resp.Status != 200 {
			t.Fatalf("status = %d, want 200", r.resp.Status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("replayed request did not resolve")
	}
}

// TestDetachGraceExpiryFailsPending: with no reconnect, the grace timer fails
// the request with 503 and the host learns to drop its answer.
func TestDetachGraceExpiryFailsPending(t *testing.T) {
	const grace = 300 * time.Millisecond
	shortPendingGrace(t, grace)
	shortLiveness(t, 1, 10)
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	type result struct {
		resp RelayResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := h.Dispatch(context.Background(), "h1", "POST", "/api/prompt", nil)
		done <- result{resp, err}
	}()
	req := fh.recvType(wire.TypeRequest, 2*time.Second)

	start := time.Now()
	fh.ft.hangup()
	waitDetached(t, h, "h1")
	select {
	case r := <-done:
		var re *RelayError
		if !errors.As(r.err, &re) || re.Status != 503 {
			t.Fatalf("dispatch err = %v, want RelayError 503 after the grace", r.err)
		}
		if elapsed := time.Since(start); elapsed < grace/2 {
			t.Fatalf("request failed after %s, before the %s grace", elapsed, grace)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("request did not fail after the detach grace")
	}

	// The down log cannot drop one seq without breaking the strict receiver,
	// so a reconnect may still replay the frame. hello_ack carries the abort,
	// which the host checks before executing it.
	again := dialFakeHost(t, h, "h1", 1)
	if a, ok := findRelayAck(again.ack.RelayAcks, req.ReqID); !ok || !a.Abort {
		t.Fatalf("hello_ack entry for %s = %+v (found %v), want abort", req.ReqID, a, ok)
	}
	if replay := again.recvType(wire.TypeRequest, 2*time.Second); replay.ReqID != req.ReqID {
		t.Fatalf("replayed request = %q, want %q", replay.ReqID, req.ReqID)
	}
}

// TestNewEpochAttachFailsPendingImmediately: the host process restarted, so
// requests from the old sequence space cannot be answered. They fail at
// attach, not after the grace.
func TestNewEpochAttachFailsPendingImmediately(t *testing.T) {
	shortPendingGrace(t, 5*time.Second)
	shortLiveness(t, 1, 10)
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	type result struct {
		resp RelayResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := h.Dispatch(context.Background(), "h1", "POST", "/api/prompt", nil)
		done <- result{resp, err}
	}()
	fh.recvType(wire.TypeRequest, 2*time.Second)

	fh.ft.hangup()
	waitDetached(t, h, "h1")

	// The 5s grace is still pending here: attach itself must fail the request.
	dialFakeHost(t, h, "h1", 2)
	select {
	case r := <-done:
		var re *RelayError
		if !errors.As(r.err, &re) || re.Status != 503 {
			t.Fatalf("dispatch err = %v, want RelayError 503 on the epoch change", r.err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("pending request not failed at the new-epoch attach")
	}
}
