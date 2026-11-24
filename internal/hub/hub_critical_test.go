package hub

import (
	"testing"
	"time"
)

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, cond func() bool, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	if !cond() {
		t.Fatal("condition not met before deadline")
	}
}

// TestCriticalEventTypesCoverFETurnTerminals: the hub's never-drop set must
// match what the FE treats as a turn terminal / pending transition
// (capri-fe store/chat/turnLifecycle.ts TURN_TERMINAL_TYPES + turnEnd.ts).
// A gap here is silent: a dropped "cancelled"/"prompt_complete" leaves the
// composer on "Responding…" forever, and a dropped session "error" hides
// the failure, because no later event of that turn can reveal the hole.
func TestCriticalEventTypesCoverFETurnTerminals(t *testing.T) {
	for _, typ := range []string{
		"done", "turn_completed", "cancelled", "prompt_complete",
		"error", "client_request", "client_request_resolved",
	} {
		if !criticalEvent(Event{"type": typ}) {
			t.Errorf("%q must never be dropped to a slow subscriber", typ)
		}
	}
	for _, typ := range []string{"chunk", "thought", "user_chunk", "usage", "status"} {
		if criticalEvent(Event{"type": typ}) {
			t.Errorf("%q is streaming noise and stays droppable", typ)
		}
	}
}

// TestDroppedCriticalEventForcesResync: a critical event lost to a wedged
// subscriber escalates to a resync immediately instead of waiting for
// resyncDropThreshold drops — the FE otherwise waits on a turn that already
// ended, with no later event to expose the seq hole.
func TestDroppedCriticalEventForcesResync(t *testing.T) {
	s := newFeSubscriber(1)
	defer s.stop()
	s.host.Store("h1")

	// Saturate the consumer channel, then the ring, so the next critical
	// event has nowhere to go (its drop is the case under test).
	s.deliver(Event{"seq": uint64(1), "type": "chunk"})
	waitFor(t, func() bool { return len(s.ch) == 1 }, time.Second)
	s.mu.Lock()
	for i := 0; i < len(s.ring); i++ {
		s.ring[i] = Event{"seq": uint64(1), "type": "tool_call_update"}
	}
	s.n = len(s.ring)
	s.mu.Unlock()

	s.deliver(Event{"type": "cancelled", "seq": float64(777), "hostId": "h1"})

	// Drain: the parked chunk first (it was handed over before the drop),
	// then the resync the escalation queued ahead of the ring backlog.
	if ev := <-s.ch; ev["type"] != "chunk" {
		t.Fatalf("first frame = %v, want the parked chunk", ev)
	}
	select {
	case ev := <-s.ch:
		if ev["type"] != "resync" {
			t.Fatalf("second frame = %v, want a resync for the dropped terminal", ev)
		}
		if got, _ := ev["fromSeq"].(uint64); got != 777 {
			t.Errorf("resync fromSeq = %v, want 777", ev["fromSeq"])
		}
		if got, _ := ev["hostId"].(string); got != "h1" {
			t.Errorf("resync hostId = %v, want h1", ev["hostId"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no resync after a dropped critical event")
	}
}

// TestSlowSubscriberDoesNotDelayIngestOrPeers: one wedged browser must not
// stall uplink ingestion (the old blocking fallback held the fan-out path
// for a blocking per-event wait on the wedged subscriber) nor delay peers
// watching the same host.
func TestSlowSubscriberDoesNotDelayIngestOrPeers(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	wedged, unsubW := h.Subscribe()
	defer unsubW()
	healthy, unsubH := h.Subscribe()
	defer unsubH()

	// Saturate the wedged subscriber's channel and never drain it: its pump
	// parks on the first event it cannot hand over. Filling is non-blocking
	// because the join above may already have queued a subscribers_changed
	// frame (its hello-time count is not the point here); "full" is what
	// this setup needs, not "exactly cap frames".
fill:
	for i := 0; i < cap(wedged); i++ {
		select {
		case wedged <- Event{"seq": uint64(1), "type": "filler"}:
		default:
			break fill
		}
	}

	const n = 200 // all critical: each one waits inline under the old code
	ingestDone := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		for i := 0; i < n; i++ {
			hubRaw(h, "h1", Event{"type": "done", "seq": uint64(i + 1)})
		}
		ingestDone <- time.Since(start)
	}()
	select {
	case d := <-ingestDone:
		if d > 2*time.Second {
			t.Fatalf("ingest took %v behind a wedged subscriber", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ingest blocked behind a wedged subscriber")
	}

	seen := 0
	deadline := time.After(3 * time.Second)
	for seen < n {
		select {
		case ev := <-healthy:
			if ev["type"] == "done" {
				seen++
			}
		case <-deadline:
			t.Fatalf("healthy subscriber saw %d/%d events while a peer was wedged", seen, n)
		}
	}
}

// TestFanoutDropsAreCountedNotBlocking: with the consumer saturated, a
// droppable flood drops (and escalates to a queued resync) while the fan-out
// path itself never waits on the subscriber.
func TestFanoutDropsAreCountedNotBlocking(t *testing.T) {
	s := newFeSubscriber(1)
	defer s.stop()
	s.host.Store("h1")
	s.deliver(Event{"type": "chunk", "seq": float64(1)})
	waitFor(t, func() bool { return len(s.ch) == 1 }, time.Second)

	start := time.Now()
	for i := 0; i < 100; i++ {
		s.deliver(Event{"type": "chunk", "seq": float64(i + 2)})
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("droppable flood blocked the fan-out path for %v", d)
	}

	// Crossing the threshold queues one resync, which the pump parks on
	// (critical-tier) instead of dropping further events. It lands as soon
	// as the consumer drains.
	if ev := <-s.ch; ev["type"] != "chunk" {
		t.Fatalf("first frame = %v, want the parked chunk", ev)
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case ev := <-s.ch:
			if ev["type"] == "resync" {
				return
			}
		case <-deadline:
			t.Fatal("no resync after a droppable flood crossed the threshold")
		}
	}
}

// drainEvents collects whatever arrives within d (used where the hub has no
// more events to push, so the only wait is for in-flight fan-out).
// waitForEventType consumes events until one of type typ arrives.
func waitForEventType(t *testing.T, ch chan Event, typ string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case ev := <-ch:
			if ev["type"] == typ {
				return
			}
		case <-deadline:
			t.Fatalf("no %s event", typ)
		}
	}
}

func drainEvents(ch chan Event, d time.Duration) []Event {
	var out []Event
	deadline := time.After(d)
	for {
		select {
		case ev := <-ch:
			out = append(out, ev)
		case <-deadline:
			return out
		}
	}
}

func eventTypes(evs []Event) []string {
	out := make([]string, 0, len(evs))
	for _, ev := range evs {
		t, _ := ev["type"].(string)
		if h, _ := ev["hostId"].(string); h != "" {
			t += "@" + h
		}
		out = append(out, t)
	}
	return out
}
