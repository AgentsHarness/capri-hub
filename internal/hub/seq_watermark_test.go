package hub

import (
	"encoding/json"
	"testing"
)

// The delivery watermark may never step over a hole: the host deletes its
// replay copies and anchors repairs at this number, so a value that skipped a
// gap is what makes a lost frame permanent.
func TestAckedSeqStopsBeforeHole(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	// First number of the epoch defines the baseline (the host can only
	// replay what its ring still holds) — 10 is accepted as the start.
	hubRaw(h, "h1", Event{"type": "chunk", "seq": uint64(10)})
	if got := h.LastSeq("h1"); got != 10 {
		t.Fatalf("acked after baseline = %d, want 10", got)
	}

	// A hole at 11: 12 and 13 arrive out of order and must NOT be counted.
	hubRaw(h, "h1", Event{"type": "chunk", "seq": uint64(12)})
	hubRaw(h, "h1", Event{"type": "chunk", "seq": uint64(13)})
	if got := h.LastSeq("h1"); got != 10 {
		t.Fatalf("acked = %d after out-of-order 12,13, want 10 (hole at 11)", got)
	}
	if got := h.HighestSeq("h1"); got != 13 {
		t.Fatalf("highest = %d, want 13 (holes are still stored)", got)
	}

	// Filling the hole lets the watermark walk the whole run at once.
	hubRaw(h, "h1", Event{"type": "chunk", "seq": uint64(11)})
	if got := h.LastSeq("h1"); got != 13 {
		t.Fatalf("acked = %d after 11 arrived, want 13", got)
	}

	// A stale/duplicate number never regresses either counter.
	hubRaw(h, "h1", Event{"type": "chunk", "seq": uint64(5)})
	if got, want := h.LastSeq("h1"), uint64(13); got != want {
		t.Fatalf("acked = %d after stale 5, want %d", got, want)
	}
}

// seq_reset starts a new epoch: the watermark, the out-of-order set and its
// seal all go back to zero, so a restarted host's numbers are not compared
// against the previous process's.
func TestAckedSeqResetClearsGaps(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	hubRaw(h, "h1", Event{"type": "chunk", "seq": uint64(100)})
	hubRaw(h, "h1", Event{"type": "chunk", "seq": uint64(102)})

	if !h.ResetHostSeq("h1") {
		t.Fatal("ResetHostSeq failed")
	}
	if got := h.LastSeq("h1"); got != 0 {
		t.Fatalf("acked after reset = %d, want 0", got)
	}
	hubRaw(h, "h1", Event{"type": "chunk", "seq": uint64(1)})
	if got := h.LastSeq("h1"); got != 1 {
		t.Fatalf("acked = %d after post-reset seq 1, want 1", got)
	}
}

// An out-of-order set past its bound must not freeze the watermark: a frozen
// number would stop the host from ever compacting, so it would reconnect and
// replay into the same frozen number forever. The hub gives up on the missing
// range instead, exactly as the FE does at PENDING_SEQ_CAP.
func TestAckedSeqGivesUpOnOverflowInsteadOfFreezing(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	hubRaw(h, "h1", Event{"type": "chunk", "seq": uint64(10)})

	// One hole at 11, then far more parked numbers than the set may hold.
	for s := uint64(12); s <= 12+maxGappedSeq+8; s++ {
		hubRaw(h, "h1", Event{"type": "chunk", "seq": s})
	}
	got := h.LastSeq("h1")
	if got <= 10 {
		t.Fatalf("watermark = %d; an overflowed set must move forward, or the session never recovers", got)
	}
	// The next in-order event must still advance it: not sealed, not stuck.
	hubRaw(h, "h1", Event{"type": "chunk", "seq": got + 1})
	if next := h.LastSeq("h1"); next != got+1 {
		t.Fatalf("watermark = %d after seq %d, want %d", next, got+1, got+1)
	}

	// The jump is data loss and must be visible in the diagnostics snapshot.
	stats := h.Stats()
	if len(stats.Hosts) != 1 {
		t.Fatalf("stats hosts = %d, want 1", len(stats.Hosts))
	}
	if stats.Hosts[0].WatermarkJumps == 0 {
		t.Fatal("watermarkJumps = 0 after an overflow; the loss must be counted")
	}
}

// A hole fill is accepted, not staleness — so it must be indexed under the
// seq the host actually sent. Stamping the highest watermark on it puts two
// different events under the same (hostId,seq): a FE gap-pulling would treat
// the fill as a duplicate of the high-water event and drop it, and the map
// value would disagree with the bytes that went out on the wire.
func TestAckedSeqHoleFillKeepsWireSeq(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	// 10 defines the baseline; 11 never arrives, so 12/14 park and 13 is a
	// fill behind the highest number seen.
	for _, s := range []uint64{10, 12, 14, 13} {
		if !hubRaw(h, "h1", Event{"type": "chunk", "seq": s}) {
			t.Fatalf("seq %d rejected", s)
		}
	}
	if got, want := h.LastSeq("h1"), uint64(10); got != want {
		t.Fatalf("acked = %d, want %d (hole at 11 stays open)", got, want)
	}
	if got, want := h.HighestSeq("h1"), uint64(14); got != want {
		t.Fatalf("highest = %d, want %d", got, want)
	}

	// wireSeqs returns the events' wire seqs and asserts that the map seq
	// the hub indexed them under is the same number.
	wireSeqs := func(after uint64) []uint64 {
		t.Helper()
		var out []uint64
		for _, ev := range h.EventsAfter("h1", after) {
			raw, err := MarshalEvent(ev)
			if err != nil {
				t.Fatalf("MarshalEvent: %v", err)
			}
			var wire struct {
				Seq uint64 `json:"seq"`
			}
			if err := json.Unmarshal(raw, &wire); err != nil {
				t.Fatalf("wire event is not JSON: %v", err)
			}
			if got := evSeq(ev); got != wire.Seq {
				t.Fatalf("event indexed as seq %d but its wire seq is %d (after=%d)", got, wire.Seq, after)
			}
			out = append(out, wire.Seq)
		}
		return out
	}

	if got := wireSeqs(10); !equalSeqs(got, []uint64{12, 13, 14}) {
		t.Fatalf("EventsAfter(10) = %v, want [12 13 14]", got)
	}
	if got := wireSeqs(13); !equalSeqs(got, []uint64{14}) {
		t.Fatalf("EventsAfter(13) = %v, want [14]", got)
	}
	if got := wireSeqs(14); len(got) != 0 {
		t.Fatalf("EventsAfter(14) = %v, want empty", got)
	}
}

func equalSeqs(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The hello's absolute state is now registered for confirmation: a hello
// whose subscribers frame never landed must be repairable, and its stamp must
// be the one the host would ack.
func TestHelloStateIsRegisteredForRetransmit(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	rec := &ackRecorder{}
	if _, stop, err := h.ConnectStream("h1", rec.write); err != nil {
		t.Fatalf("ConnectStream: %v", err)
	} else {
		defer stop()
	}

	st := h.PrepareHelloState("h1")
	if st.SubsGen == 0 {
		t.Fatal("hello's subscriber count must carry a generation")
	}
	// Nothing is registered before the caller commits: a hello that never
	// left the hub must not arm the retry timer.
	if _, ok := h.UnackedState("h1", kindSubscribers); ok {
		t.Fatal("hello state registered before commit")
	}
	h.CommitHelloState("h1", st)
	gen, ok := h.UnackedState("h1", kindSubscribers)
	if !ok || gen != st.SubsGen {
		t.Fatalf("unacked subscribers = %d,%v; want gen %d", gen, ok, st.SubsGen)
	}

	// The frame the retry timer holds is byte-identical to a standalone
	// subscribers frame of the same generation, so the host's gate can dedupe.
	var payload struct {
		Type  string `json:"type"`
		Count int    `json:"count"`
		Gen   uint64 `json:"gen"`
	}
	if err := json.Unmarshal(st.subPayload, &payload); err != nil {
		t.Fatalf("subscribers payload is not JSON: %v", err)
	}
	if payload.Type != "subscribers" || payload.Gen != st.SubsGen || payload.Count != st.Subscribers {
		t.Fatalf("payload = %+v, want subscribers gen %d count %d", payload, st.SubsGen, st.Subscribers)
	}

	h.AckState("h1", kindSubscribers, st.SubsGen)
	if _, ok := h.UnackedState("h1", kindSubscribers); ok {
		t.Fatal("ack did not clear the hello's subscriber entry")
	}
}
