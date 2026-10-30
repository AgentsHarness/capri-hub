package hub

import (
	"testing"
	"time"

	"github.com/AgentsHarness/capri-wire"
)

// This file is the Stage-4 fault matrix at the hub end of the session: the
// failure modes v2 must answer, driven through the real
// ServeHost path with an in-process fake host transport.

// collectHostSeqs drains ch until n events of hostID arrived and returns
// their seqs in delivery order.
func collectHostSeqs(t *testing.T, ch chan Event, hostID string, n int, timeout time.Duration) []uint64 {
	t.Helper()
	var seqs []uint64
	deadline := time.After(timeout)
	for len(seqs) < n {
		select {
		case ev := <-ch:
			if ev["hostId"] == hostID {
				seqs = append(seqs, evSeq(ev))
			}
		case <-deadline:
			t.Fatalf("only %v of %d events arrived", seqs, n)
		}
	}
	return seqs
}

// TestSessionDuplicateFramesAppliedOnce: a retransmitted events frame is a
// duplicate at the receiver — applied once, still acked, never fanned out
// twice, and it never opens a seq hole.
func TestSessionDuplicateFramesAppliedOnce(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	ch, unsub := h.Subscribe()
	defer unsub()
	drainEvents(ch, 50*time.Millisecond)

	fh := dialFakeHost(t, h, "h1", 1)
	fh.events(1, 0, chunkEvent(1, "a"), chunkEvent(2, "b"))
	waitFor(t, func() bool { return h.LastSeq("h1") == 2 }, 2*time.Second)

	// The same frame again (the hub's ack was lost), then the next event.
	fh.events(1, 0, chunkEvent(1, "a"), chunkEvent(2, "b"))
	fh.events(3, 0, chunkEvent(3, "c"))

	seqs := collectHostSeqs(t, ch, "h1", 3, 2*time.Second)
	if len(seqs) != 3 || seqs[0] != 1 || seqs[1] != 2 || seqs[2] != 3 {
		t.Fatalf("fan-out = %v, want each event exactly once in order", seqs)
	}
	// Nothing else may show up (a duplicate would be a 4th event).
	select {
	case ev := <-ch:
		if ev["hostId"] == "h1" {
			t.Fatalf("a duplicate frame was fanned out again: seq %d", evSeq(ev))
		}
	case <-time.After(100 * time.Millisecond):
	}
	if got := h.LastSeq("h1"); got != 3 {
		t.Fatalf("watermark = %d, want 3", got)
	}
}

// TestSessionDuplicateTransportSupersedes: a second transport for the same
// hostId replaces the first. The old one closes `superseded`, its late frames
// are refused, and neither branch corrupts the seq/watermark.
func TestSessionDuplicateTransportSupersedes(t *testing.T) {
	t.Run("same epoch", func(t *testing.T) {
		h := NewWithDir("")
		testPair(t, h, "h1", "H1")

		first := dialFakeHost(t, h, "h1", 7)
		first.events(1, 0, chunkEvent(1, "a"), chunkEvent(2, "b"))
		waitFor(t, func() bool { return h.LastSeq("h1") == 2 }, 2*time.Second)

		second := dialFakeHost(t, h, "h1", 7)
		if got := second.ack.AckUp; got != 2 {
			t.Fatalf("replacement ackUp = %d, want 2 (resumed)", got)
		}
		if got := first.waitReason(2 * time.Second); got != wire.CloseSuperseded {
			t.Fatalf("old session close = %s, want superseded", got)
		}

		// Frames the old transport still pushes must not land.
		first.events(3, 0, chunkEvent(3, "stale"))
		time.Sleep(200 * time.Millisecond)
		if got := h.LastSeq("h1"); got != 2 {
			t.Fatalf("a stale frame from the superseded transport moved the watermark to %d", got)
		}

		second.events(3, 0, chunkEvent(3, "fresh"))
		waitFor(t, func() bool { return h.LastSeq("h1") == 3 }, 2*time.Second)
	})

	t.Run("new epoch", func(t *testing.T) {
		h := NewWithDir("")
		testPair(t, h, "h1", "H1")

		first := dialFakeHost(t, h, "h1", 1)
		first.events(1, 0, chunkEvent(1, "a"), chunkEvent(2, "b"))
		waitFor(t, func() bool { return h.LastSeq("h1") == 2 }, 2*time.Second)

		// A second process claims the host with a fresh sequence space.
		second := dialFakeHostResume(t, h, "h1", 2, 100)
		if got := second.ack.AckUp; got != 100 {
			t.Fatalf("new epoch ackUp = %d, want the declared baseline 100", got)
		}
		if got := first.waitReason(2 * time.Second); got != wire.CloseSuperseded {
			t.Fatalf("old epoch close = %s, want superseded", got)
		}

		first.events(3, 0, chunkEvent(3, "old-space"))
		time.Sleep(200 * time.Millisecond)
		if got := h.LastSeq("h1"); got != 100 {
			t.Fatalf("old epoch's late event moved the new watermark to %d", got)
		}

		second.events(101, 0, chunkEvent(101, "new-space"))
		waitFor(t, func() bool { return h.LastSeq("h1") == 101 }, 2*time.Second)
	})
}

// TestSessionNewEpochBaselineOrder: a new epoch resets the up watermark to
// hello.resume.up, tells /ws/fe with subscribed{seq:baseline} before any
// new-epoch event, and discards the retired epoch's unacked log.
func TestSessionNewEpochBaselineOrder(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	ch, unsub := h.Subscribe()
	defer unsub()
	drainEvents(ch, 50*time.Millisecond)

	first := dialFakeHost(t, h, "h1", 1)
	first.events(1, 0, chunkEvent(1, "old-a"), chunkEvent(2, "old-b"))
	waitFor(t, func() bool { return h.LastSeq("h1") == 2 }, 2*time.Second)
	if evs := h.EventsAfter("h1", 0); len(evs) != 2 {
		t.Fatalf("gap-pull buffer = %d events before the epoch change", len(evs))
	}
	drainEvents(ch, 50*time.Millisecond)

	fresh := dialFakeHostResume(t, h, "h1", 2, 500)
	if got := fresh.ack.AckUp; got != 500 {
		t.Fatalf("new epoch ackUp = %d, want 500", got)
	}
	if got := h.LastSeq("h1"); got != 500 {
		t.Fatalf("up watermark = %d, want the declared baseline 500", got)
	}
	if evs := h.EventsAfter("h1", 0); len(evs) != 0 {
		t.Fatalf("the retired epoch's gap-pull buffer survived (%d events)", len(evs))
	}

	// The FE is told the new coordinate before it sees an event in it.
	fresh.events(501, 0, chunkEvent(501, "new-a"))
	var order []string
	deadline := time.After(2 * time.Second)
	for len(order) < 2 {
		select {
		case ev := <-ch:
			switch {
			case ev["type"] == "subscribed":
				if ev["host"] != "h1" || evSeq(ev) != 500 {
					t.Fatalf("subscribed frame = %v, want host h1 seq 500", ev)
				}
				order = append(order, "subscribed")
			case ev["hostId"] == "h1":
				order = append(order, "event")
				if evSeq(ev) != 501 {
					t.Fatalf("first new-epoch event seq = %d, want 501", evSeq(ev))
				}
			}
		case <-deadline:
			t.Fatalf("only saw %v", order)
		}
	}
	if order[0] != "subscribed" || order[1] != "event" {
		t.Fatalf("FE order = %v, want subscribed before the first event", order)
	}
}

// TestSessionSameEpochResumeKeepsWatermark: a same-epoch reconnect keeps the
// up watermark and the gap-pull buffer; the host's declared resume.up is
// advisory there.
func TestSessionSameEpochResumeKeepsWatermark(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")

	first := dialFakeHost(t, h, "h1", 9)
	first.events(1, 0, chunkEvent(1, "a"), chunkEvent(2, "b"))
	waitFor(t, func() bool { return h.LastSeq("h1") == 2 }, 2*time.Second)

	// The host claims a stale resume.up; the hub's own watermark must win.
	second := dialFakeHostResume(t, h, "h1", 9, 1)
	if got := second.ack.AckUp; got != 2 {
		t.Fatalf("resume ackUp = %d, want the hub's 2", got)
	}
	if got := h.LastSeq("h1"); got != 2 {
		t.Fatalf("LastSeq = %d, want 2", got)
	}
	if evs := h.EventsAfter("h1", 0); len(evs) != 2 {
		t.Fatalf("gap-pull buffer = %d events, want 2", len(evs))
	}

	// The unacked tail replays cleanly on the new transport.
	second.events(3, 0, chunkEvent(3, "c"))
	waitFor(t, func() bool { return h.LastSeq("h1") == 3 }, 2*time.Second)
}

// TestSessionBlackholeClosesLiveness: frames stop in both directions; the hub
// must close with liveness, take the registry offline, and accept the
// reconnect. A busy link must not be killed by the same timer.
func TestSessionBlackholeClosesLiveness(t *testing.T) {
	shortLiveness(t, 1, 2)
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")

	fh := dialFakeHost(t, h, "h1", 1)
	waitFor(t, func() bool { return h.ListHosts()[0].Online }, time.Second)
	if got := fh.waitReason(5 * time.Second); got != wire.CloseLiveness {
		t.Fatalf("blackhole close = %s, want liveness", got)
	}
	waitFor(t, func() bool { return !h.ListHosts()[0].Online }, time.Second)

	// The host comes back with the same epoch and carries on.
	again := dialFakeHost(t, h, "h1", 1)
	again.events(1, 0, chunkEvent(1, "back"))
	waitFor(t, func() bool { return h.LastSeq("h1") == 1 }, 2*time.Second)
}

// TestSessionBusyLinkSurvivesIdle: a frame every 400ms keeps a 2s-idle
// session alive; silence afterwards closes it.
func TestSessionBusyLinkSurvivesIdle(t *testing.T) {
	shortLiveness(t, 1, 2)
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	hb, err := wire.NewHeartbeat(0, wire.HeartbeatStatus{Ready: true})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2500 * time.Millisecond)
	for time.Now().Before(deadline) {
		fh.send(hb)
		time.Sleep(400 * time.Millisecond)
	}
	select {
	case r := <-fh.end:
		t.Fatalf("a busy session was closed with %s", r)
	default:
	}
	if got := fh.waitReason(5 * time.Second); got != wire.CloseLiveness {
		t.Fatalf("close after silence = %s, want liveness", got)
	}
}

// TestSessionSlowSubscriberDoesNotStall: a browser that stops reading must not
// stall the host session (the watermark still advances) or its peers, and its
// eventual catch-up still carries a resync frame for the dropped range.
func TestSessionSlowSubscriberDoesNotStall(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")

	slow, unsubSlow := h.Subscribe()
	defer unsubSlow()
	fast, unsubFast := h.Subscribe()
	defer unsubFast()
	drainEvents(fast, 50*time.Millisecond)

	fh := dialFakeHost(t, h, "h1", 1)

	// Read the fast peer concurrently: it must keep up throughout.
	fastSeen := make(chan uint64, 8192)
	stopReader := make(chan struct{})
	defer close(stopReader)
	go func() {
		for {
			select {
			case ev := <-fast:
				if ev["hostId"] == "h1" {
					fastSeen <- evSeq(ev)
				}
			case <-stopReader:
				return
			}
		}
	}()

	const total = 4000
	const batch = 100
	for start := uint64(1); start <= total; start += batch {
		bodies := make([]string, 0, batch)
		for i := uint64(0); i < batch; i++ {
			bodies = append(bodies, chunkEvent(start+i, "x"))
		}
		fh.events(start, 0, bodies...)
	}

	// The host session is acked over the whole run even though one browser
	// never read a single frame.
	deadline := time.Now().Add(10 * time.Second)
	var acked uint64
	for acked < total {
		if time.Now().After(deadline) {
			t.Fatalf("host was never acked past %d/%d (a slow browser stalled ingest)", acked, total)
		}
		hb := fh.recvType(wire.TypeHeartbeat, time.Until(deadline))
		if hb.Ack > acked {
			acked = hb.Ack
		}
	}
	if got := h.LastSeq("h1"); got != total {
		t.Fatalf("watermark = %d, want %d", got, total)
	}

	// A peer that reads normally made progress too.
	select {
	case seq := <-fastSeen:
		if seq == 0 {
			t.Fatal("peer saw a zero-seq event")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a live peer received nothing while another browser was stalled")
	}

	// The stalled subscriber's backlog drops past the threshold; draining it
	// must surface a resync frame (the recovery path is unchanged).
	foundResync := false
	slowDeadline := time.After(5 * time.Second)
	for !foundResync {
		select {
		case ev := <-slow:
			if ev["type"] == "resync" {
				foundResync = true
			}
		case <-slowDeadline:
			t.Fatal("the stalled subscriber never received a resync frame")
		}
	}
}

// TestSessionUnreadableClosesAndReplays: a frame the hub cannot decode ends
// the session with `unreadable`; the host reconnects at the hub's watermark
// and the replay continues from there, not from zero.
func TestSessionUnreadableClosesAndReplays(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	ch, unsub := h.Subscribe()
	defer unsub()
	drainEvents(ch, 50*time.Millisecond)

	fh := dialFakeHost(t, h, "h1", 1)
	fh.events(1, 0, chunkEvent(1, "a"), chunkEvent(2, "b"))
	waitFor(t, func() bool { return h.LastSeq("h1") == 2 }, 2*time.Second)

	select {
	case fh.ft.inbox <- []byte(`{"v":2,"type":"events","seq":3,"events":[`):
	case <-time.After(2 * time.Second):
		t.Fatal("could not inject the corrupt frame")
	}
	if got := fh.waitReason(2 * time.Second); got != wire.CloseUnreadable {
		t.Fatalf("corrupt frame close = %s, want unreadable", got)
	}
	if got := h.LastSeq("h1"); got != 2 {
		t.Fatalf("watermark jumped to %d on a corrupt frame", got)
	}

	again := dialFakeHost(t, h, "h1", 1)
	if got := again.ack.AckUp; got != 2 {
		t.Fatalf("resume ackUp = %d, want 2 (replay from the hub watermark)", got)
	}
	again.events(3, 0, chunkEvent(3, "c"))
	waitFor(t, func() bool { return h.LastSeq("h1") == 3 }, 2*time.Second)

	seqs := collectHostSeqs(t, ch, "h1", 3, 2*time.Second)
	if seqs[0] != 1 || seqs[1] != 2 || seqs[2] != 3 {
		t.Fatalf("fan-out = %v, want 1 2 3 exactly once", seqs)
	}
}

// TestSessionAudienceRevivesUploadAfterWatchersLeave: watchers 0 pauses the
// host (no audience progress required from it), and the next browser produces
// a new generation rather than reusing the old one.
func TestSessionAudienceWatchersRoundTrip(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)
	gen := fh.ack.Audience.Gen

	ch, unsub := h.Subscribe()
	defer unsub()
	a := fh.recvType(wire.TypeAudience, 2*time.Second).AudienceState()
	if a.Watchers != 1 || a.Gen <= gen {
		t.Fatalf("audience after subscribe = %+v, want watchers 1 and a new gen", a)
	}
	unsub()
	_ = ch
	a = fh.recvType(wire.TypeAudience, 2*time.Second).AudienceState()
	if a.Watchers != 0 || a.Gen <= gen+1 {
		t.Fatalf("audience after unsubscribe = %+v, want watchers 0 and gen > %d", a, gen+1)
	}
}
