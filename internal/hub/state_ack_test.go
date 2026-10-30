package hub

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestStateAckBackoffGrows(t *testing.T) {
	if got := stateAckDelay(1); got != StateAckRetryInterval {
		t.Fatalf("first retry = %s, want %s", got, StateAckRetryInterval)
	}
	if got, want := stateAckDelay(2), 2*StateAckRetryInterval; got != want {
		t.Fatalf("second retry = %s, want %s", got, want)
	}
	if got := stateAckDelay(30); got != stateAckBackoffMax {
		t.Fatalf("late retry = %s, want cap %s", got, stateAckBackoffMax)
	}
}

// ackRecorder is a host transport stand-in: it records every downlink frame
// and can be told to swallow the "original" write so a test can model a lost
// frame. A frame counts as lost unless fail returns false for its payload.
type ackRecorder struct {
	mu     sync.Mutex
	frames [][]byte
}

func (r *ackRecorder) write(p []byte) error {
	r.mu.Lock()
	r.frames = append(r.frames, append([]byte(nil), p...))
	r.mu.Unlock()
	return nil
}

// ofType returns the frames of one type, oldest first.
func (r *ackRecorder) ofType(typ string) []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []map[string]any
	for _, f := range r.frames {
		var m map[string]any
		if json.Unmarshal(f, &m) != nil || m["type"] != typ {
			continue
		}
		out = append(out, m)
	}
	return out
}

func (r *ackRecorder) count(typ string) int { return len(r.ofType(typ)) }

// waitFrames waits until n frames of typ have been written, failing the test
// otherwise.
func (r *ackRecorder) waitFrames(t *testing.T, typ string, n int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if r.count(typ) >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("waited %s for %d %q frames, got %d", within, n, typ, r.count(typ))
}

// pumpRetransmits drives the retry pass until n frames of typ exist. The pass
// is a no-op before the entry's deadline, so a test cannot just call it once:
// it has to stay behind the (shrunk) interval.
func pumpRetransmits(t *testing.T, h *Hub, r *ackRecorder, typ string, n int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		h.retransmitStateAcks()
		if r.count(typ) >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("waited %s for %d %q frames while pumping retransmits, got %d", within, n, typ, r.count(typ))
}

// stateAckTiming shrinks the retry cadence so a test can observe
// retransmits, restoring the production values afterwards.
func stateAckTiming(t *testing.T, interval time.Duration) {
	t.Helper()
	prev := StateAckRetryInterval
	StateAckRetryInterval = interval
	t.Cleanup(func() { StateAckRetryInterval = prev })
}

// pairedCapableHost pairs h1 and registers a host transport,
// returning the recorder and the unsubscribe-style stop func.
func pairedCapableHost(t *testing.T, h *Hub) (*ackRecorder, func()) {
	t.Helper()
	testPair(t, h, "h1", "H1")
	rec := &ackRecorder{}
	if _, stop, err := h.ConnectStream("h1", rec.write); err != nil {
		t.Fatalf("ConnectStream: %v", err)
	} else {
		return rec, stop
	}
	return nil, nil
}

// genOf reads the gen field of a decoded frame.
func genOf(t *testing.T, frame map[string]any) uint64 {
	t.Helper()
	g, ok := frame["gen"].(float64)
	if !ok {
		t.Fatalf("frame has no numeric gen: %v", frame)
	}
	return uint64(g)
}

// A lost edge frame is retransmitted by the retry timer, byte-identically:
// same gen, so the host's generation gate discards it if the original did
// land after all.
func TestStateAckRetransmitsLostSubscribersFrame(t *testing.T) {
	stateAckTiming(t, 10*time.Millisecond)
	h := NewWithDir("")
	rec, stop := pairedCapableHost(t, h)
	defer stop()

	// One browser connects; the frame is written to rec. Then a SECOND
	// change happens and we ack only the first gen, so the newest entry stays
	// unconfirmed and must be retransmitted.
	_, unsub := h.Subscribe()
	defer unsub()
	rec.waitFrames(t, "subscribers", 1, time.Second)
	first := rec.ofType("subscribers")[0]
	h.AckState("h1", kindSubscribers, genOf(t, first))

	// A new generation with the same count is not emitted (dedupe), so force
	// a real change: a second subscriber moves the count 1 → 2.
	_, unsub2 := h.Subscribe()
	defer unsub2()
	rec.waitFrames(t, "subscribers", 2, time.Second)
	second := rec.ofType("subscribers")[1]

	pumpRetransmits(t, h, rec, "subscribers", 3, time.Second)
	third := rec.ofType("subscribers")[2]
	if genOf(t, third) != genOf(t, second) {
		t.Fatalf("retransmit gen = %d, want the SAME gen %d", genOf(t, third), genOf(t, second))
	}
	if got, want := third["count"], second["count"]; got != want {
		t.Fatalf("retransmit count = %v, want %v", got, want)
	}
}

// Once the host acks a generation, nothing more is written for it.
func TestStateAckStopsRetransmit(t *testing.T) {
	stateAckTiming(t, 10*time.Millisecond)
	h := NewWithDir("")
	rec, stop := pairedCapableHost(t, h)
	defer stop()

	_, unsub := h.Subscribe()
	defer unsub()
	rec.waitFrames(t, "subscribers", 1, time.Second)
	frame := rec.ofType("subscribers")[0]
	gen := genOf(t, frame)

	if !h.AckState("h1", kindSubscribers, gen) {
		t.Fatalf("ack for the outstanding gen %d was not matched", gen)
	}
	if _, ok := h.UnackedState("h1", kindSubscribers); ok {
		t.Fatal("ack did not clear the unacked entry")
	}
	before := rec.count("subscribers")
	for i := 0; i < 5; i++ {
		h.retransmitStateAcks()
		time.Sleep(5 * time.Millisecond)
	}
	if got := rec.count("subscribers"); got != before {
		t.Fatalf("acked state was retransmitted %d extra times", got-before)
	}
}

// An ack that arrives out of order — the NEWER gen first, then the older one
// — must leave the newer unconfirmed entry in place: otherwise the hub would
// stop repairing state the host has not actually applied.
func TestStateAckOutOfOrderDoesNotClearNewer(t *testing.T) {
	stateAckTiming(t, time.Hour) // no timer interference
	h := NewWithDir("")
	rec, stop := pairedCapableHost(t, h)
	defer stop()

	h.mu.Lock()
	h.trackUnackedLocked("h1", kindSubscribers, 5, []byte(`{"v":1,"type":"subscribers","count":1,"gen":5}`))
	h.trackUnackedLocked("h1", kindSubscribers, 9, []byte(`{"v":1,"type":"subscribers","count":1,"gen":9}`))
	h.mu.Unlock()

	// Newest ack first: it clears gen 9.
	if !h.AckState("h1", kindSubscribers, 9) {
		t.Fatal("ack for gen 9 should match")
	}
	if _, ok := h.UnackedState("h1", kindSubscribers); ok {
		t.Fatal("gen 9 ack should have cleared the entry")
	}

	// Model the actual hazard: a newer entry outstanding, an old ack
	// arriving afterwards.
	h.mu.Lock()
	h.trackUnackedLocked("h1", kindSubscribers, 12, []byte(`{"v":1,"type":"subscribers","count":0,"gen":12}`))
	h.mu.Unlock()
	if h.AckState("h1", kindSubscribers, 4) {
		t.Fatal("a stale ack (gen 4 < 12) must not match")
	}
	gen, ok := h.UnackedState("h1", kindSubscribers)
	if !ok || gen != 12 {
		t.Fatalf("unacked after stale ack = %d,%v; want the newer gen 12 to survive", gen, ok)
	}
	// The viewing family is independent.
	if h.AckState("h1", kindViewing, 12) {
		t.Fatal("a subscribers ack must not clear the viewing entry")
	}
	_ = rec
}

// A host that stops confirming is retransmitted to on the normal cadence:
// confirmed state delivery is the only carrier for absolute state, so there
// is no demotion path back to the ping.
func TestStateAckRetransmitsWithoutConfirmation(t *testing.T) {
	stateAckTiming(t, time.Millisecond)
	h := NewWithDir("")
	rec, stop := pairedCapableHost(t, h)
	defer stop()

	_, unsub := h.Subscribe()
	defer unsub()
	rec.waitFrames(t, "subscribers", 1, time.Second)

	if _, ok := h.UnackedState("h1", kindSubscribers); !ok {
		t.Fatal("a state frame must be tracked until confirmed")
	}
	before := rec.count("subscribers")
	for i := 0; i < 5; i++ {
		h.retransmitStateAcks()
		time.Sleep(5 * time.Millisecond)
	}
	if got := rec.count("subscribers"); got <= before {
		t.Fatalf("unconfirmed state was not retransmitted (count %d)", got)
	}
}

// viewing frames go through the same table, keyed independently.
func TestStateAckTracksViewingKind(t *testing.T) {
	stateAckTiming(t, 10*time.Millisecond)
	h := NewWithDir("")
	rec, stop := pairedCapableHost(t, h)
	defer stop()

	ch, unsub, ok := h.TrySubscribeHostInfo(0, "h1", SubscriberInfo{})
	if !ok {
		t.Fatal("subscribe refused")
	}
	defer unsub()
	if !h.SetSubscriberSession(ch, "s-1") {
		t.Fatal("SetSubscriberSession refused")
	}
	h.notifyHostsViewing()

	rec.waitFrames(t, "viewing", 1, time.Second)
	frame := rec.ofType("viewing")[0]
	gen := genOf(t, frame)

	got, ok := h.UnackedState("h1", kindViewing)
	if !ok || got != gen {
		t.Fatalf("unacked viewing = %d,%v; want gen %d", got, ok, gen)
	}
	if !h.AckState("h1", kindViewing, gen) {
		t.Fatal("viewing ack not matched")
	}
	if _, ok := h.UnackedState("h1", kindViewing); ok {
		t.Fatal("viewing ack did not clear the entry")
	}
}

// A reconnect replaces the transport, so a pending entry from the previous
// session must not be retransmitted over the new one: its hello already
// carries the current state.
func TestStateAckClearedOnReconnect(t *testing.T) {
	stateAckTiming(t, time.Hour)
	h := NewWithDir("")
	_, stop := pairedCapableHost(t, h)
	defer stop()

	_, unsub := h.Subscribe()
	defer unsub()
	if _, ok := h.UnackedState("h1", kindSubscribers); !ok {
		t.Fatal("expected an outstanding subscribers entry")
	}

	rec2 := &ackRecorder{}
	if _, stop2, err := h.ConnectStream("h1", rec2.write); err != nil {
		t.Fatalf("second ConnectStream: %v", err)
	} else {
		defer stop2()
	}
	if _, ok := h.UnackedState("h1", kindSubscribers); ok {
		t.Fatal("entries from the previous transport survived the reconnect")
	}
}
