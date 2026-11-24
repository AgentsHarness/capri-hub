package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/wire"
)

// A reconnect in a NEW epoch cannot deliver requests dispatched in the old
// sequence space, so their pending entries are failed immediately instead of
// waiting for RelayTimeout. A same-epoch resume keeps them: the frame is still
// in the down log and is replayed on the new link.
func TestSessionSupersedeFailsPendingOnEpochChange(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	first := dialFakeHost(t, h, "h1", 1)

	done := make(chan error, 1)
	go func() {
		_, err := h.Dispatch(context.Background(), "h1", "GET", "/api/status", nil)
		done <- err
	}()
	first.recvType(wire.TypeRequest, 2*time.Second)

	second := dialFakeHost(t, h, "h1", 2)
	select {
	case err := <-done:
		var re *RelayError
		if !errors.As(err, &re) || re.Status != 503 {
			t.Errorf("dispatch err = %v, want RelayError 503", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending request not failed on the epoch change")
	}
	if !h.ListHosts()[0].Online {
		t.Error("host should stay online after the reconnect")
	}
	// The new epoch starts from seq 0: the old request frame is gone.
	second.noFrame(200 * time.Millisecond)

	// Same epoch: the request is replayed on the new link and resolves there.
	first = dialFakeHost(t, h, "h1", 2)
	done2 := make(chan error, 1)
	go func() {
		_, err := h.Dispatch(context.Background(), "h1", "GET", "/api/status", nil)
		done2 <- err
	}()
	req := first.recvType(wire.TypeRequest, 2*time.Second)

	resumed := dialFakeHost(t, h, "h1", 2)
	replay := resumed.recvType(wire.TypeRequest, 2*time.Second)
	if replay.ReqID != req.ReqID {
		t.Fatalf("replayed request = %q, want %q", replay.ReqID, req.ReqID)
	}
	resumed.send(wire.Frame{
		V: wire.ProtocolVersion, Type: wire.TypeRespond, Ack: replay.Seq, ChunkSeq: 1,
		ReqID: replay.ReqID, Status: json.RawMessage(`200`), Body: json.RawMessage(`{"ok":true}`),
	})
	select {
	case err := <-done2:
		if err != nil {
			t.Fatalf("dispatch after same-epoch resume: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("replayed request did not resolve")
	}
}

func TestUnpair(t *testing.T) {
	dir := t.TempDir()
	h := NewWithDir(dir)
	tok := testPair(t, h, "h1", "H1")

	// Online with an attached session: unpair should clear the registry.
	dialFakeHost(t, h, "h1", 1)

	if err := h.Unpair("h1"); err != nil {
		t.Fatalf("Unpair: %v", err)
	}
	if _, ok := h.HostIDForToken(tok); ok {
		t.Error("token must be revoked after unpair")
	}
	if len(h.ListHosts()) != 0 {
		t.Errorf("hosts after unpair = %+v", h.ListHosts())
	}
	if err := h.Unpair("h1"); !errors.Is(err, ErrHostUnknown) {
		t.Errorf("second Unpair err = %v, want ErrHostUnknown", err)
	}

	// Survives restart.
	h2 := NewWithDir(dir)
	if len(h2.ListHosts()) != 0 {
		t.Errorf("hosts after restart = %+v, want empty", h2.ListHosts())
	}
	if _, ok := h2.HostIDForToken(tok); ok {
		t.Error("token must stay revoked across restart")
	}
}

func TestUnpairKicksLiveSubscribers(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	_, unsub, kicked, ok := h.TrySubscribeScopedInfo(0, "", "root", "admin", []string{"h1"}, SubscriberInfo{Role: "admin"})
	if !ok {
		t.Fatal("subscribe refused")
	}
	defer unsub()
	if err := h.Unpair("h1"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-kicked:
	case <-time.After(time.Second):
		t.Fatal("live subscriber survived host unpair")
	}
}

func TestMaxHosts(t *testing.T) {
	h := NewWithDir("")
	// Codes are single-use; each successful pair rotates the deployment code.
	for i := 0; i < MaxHosts; i++ {
		code, _ := h.PairingCode()
		if _, err := h.Pair(code, fmt.Sprintf("host-%d", i), "H"); err != nil {
			t.Fatalf("pair %d: %v", i, err)
		}
	}
	code, _ := h.PairingCode()
	if _, err := h.Pair(code, "overflow", "H"); !errors.Is(err, ErrHostLimit) {
		t.Errorf("pair beyond cap err = %v, want ErrHostLimit", err)
	}
	// Re-pair of an existing host must still work.
	code, _ = h.PairingCode()
	if _, err := h.Pair(code, "host-0", "renamed"); err != nil {
		t.Errorf("re-pair within cap: %v", err)
	}
}

func TestEvBufTrimCopies(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	// The buffer compacts at evBufHighWater (amortized: compacting on
	// every overflow would copy the whole buffer per event under h.mu).
	// Invariants: it never grows past the high-water mark, and each
	// compaction produces a FRESH array — never a reslice, which would
	// pin the dropped Event maps until the next reallocation.
	total := evBufHighWater + 10
	for i := 1; i <= total; i++ {
		if !hubRaw(h, "h1", Event{"type": "chunk", "seq": uint64(i)}) {
			t.Fatalf("register %d", i)
		}
		h.mu.Lock()
		n := len(h.hosts["h1"].evBuf)
		h.mu.Unlock()
		if n > evBufHighWater {
			t.Fatalf("evBuf len = %d after %d events, must stay <= %d", n, i, evBufHighWater)
		}
	}
	h.mu.Lock()
	buf := h.hosts["h1"].evBuf
	h.mu.Unlock()
	// Compaction ran at event evBufHighWater+1, leaving eventBufCap
	// entries; the remaining events appended into the spare capacity.
	wantLen := eventBufCap + (total - evBufHighWater - 1)
	if len(buf) != wantLen {
		t.Fatalf("len = %d, want %d", len(buf), wantLen)
	}
	if cap(buf) != evBufHighWater {
		t.Errorf("cap = %d, want %d (fresh compacted array, not a reslice)", cap(buf), evBufHighWater)
	}
	wantFirst := uint64(evBufHighWater + 1 - eventBufCap + 1)
	if got := evSeq(buf[0]); got != wantFirst {
		t.Errorf("first buffered seq = %d, want %d", got, wantFirst)
	}
	if got := evSeq(buf[len(buf)-1]); got != uint64(total) {
		t.Errorf("last buffered seq = %d, want %d", got, total)
	}
	// EventsAfter (binary search over the compacted buffer) must agree.
	if evs := h.EventsAfter("h1", uint64(total-3)); len(evs) != 3 {
		t.Errorf("EventsAfter(total-3) = %d events, want 3", len(evs))
	}
	if evs := h.EventsAfter("h1", uint64(total)); len(evs) != 0 {
		t.Errorf("EventsAfter(total) = %d events, want 0", len(evs))
	}
	if evs := h.EventsAfter("h1", 0); len(evs) != wantLen {
		t.Errorf("EventsAfter(0) = %d events, want %d (whole buffer)", len(evs), wantLen)
	}
}

// TestEventsAfterBinarySearch pins the gap-pull cut point at every
// boundary: EventsAfter is the reconnect catch-up path, so an off-by-one
// there either re-delivers a seen event or silently loses one.
func TestEventsAfterBinarySearch(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	for i := 1; i <= 10; i++ {
		hubRaw(h, "h1", Event{"type": "chunk", "seq": uint64(i)})
	}
	for after := uint64(0); after <= 11; after++ {
		evs := h.EventsAfter("h1", after)
		want := 0
		if after < 10 {
			want = int(10 - after)
		}
		if len(evs) != want {
			t.Fatalf("EventsAfter(%d) = %d events, want %d", after, len(evs), want)
		}
		for i, ev := range evs {
			if got, exp := evSeq(ev), after+uint64(i)+1; got != exp {
				t.Fatalf("EventsAfter(%d)[%d] seq = %d, want %d", after, i, got, exp)
			}
		}
	}
	if evs := h.EventsAfter("nope", 0); evs != nil {
		t.Errorf("EventsAfter for unknown host = %v, want nil", evs)
	}
}

// TestSubscribersChangedBroadcast: the browser-facing total (what the FE top
// bar shows) is pushed to every page on connect/disconnect, unfiltered — a
// page watching h1 still needs the hub-wide figure. Unchanged counts are not
// re-sent, and the frame carries no hostId so the per-host filter cannot
// swallow it.
func TestSubscribersChangedBroadcast(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	testPair(t, h, "h2", "H2")

	ch1, unsub1 := h.Subscribe()
	defer unsub1()
	scoped, scopedUnsub, ok := h.TrySubscribeHost(0, "h2")
	if !ok {
		t.Fatal("TrySubscribeHost refused")
	}
	defer scopedUnsub()

	// First subscriber's count=1 (pushed before ch2 existed) is irrelevant;
	// what matters is the current total reaching BOTH filters.
	counts := func(evs []Event) []int {
		var out []int
		for _, ev := range evs {
			if ev["type"] != "subscribers_changed" {
				continue
			}
			if _, hasHost := ev["hostId"]; hasHost {
				t.Fatalf("subscribers_changed must not carry hostId: %v", ev)
			}
			if c, ok := ev["count"].(int); ok {
				out = append(out, c)
			}
		}
		return out
	}
	// The second subscriber's join announces the new total to the first one
	// (a hub-level subscribers_changed frame) — that is the FE top-bar count.
	if got := counts(drainEvents(ch1, 200*time.Millisecond)); len(got) == 0 || got[len(got)-1] != 2 {
		t.Fatalf("watch-all page counts = %v, want the latest 2", got)
	}

	// A page leaving pushes the new total to the rest — including pages
	// filtered to a single host (the frame is hub-level, not per-host).
	unsub1()
	if got := counts(drainEvents(scoped, 300*time.Millisecond)); len(got) == 0 || got[len(got)-1] != 1 {
		t.Fatalf("after one page left, counts = %v, want 1", got)
	}
}
