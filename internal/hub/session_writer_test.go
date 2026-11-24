package hub

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/wire"
)

// TestWriterInterleavesControlBetweenUnits: a large reliable frame is written
// as transport units, and an hb posted while the frame is being written lands
// between two units instead of after the whole frame.
func TestWriterInterleavesControlBetweenUnits(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	var once sync.Once
	fh.ft.onFragment(func() {
		once.Do(func() {
			// A new up seq makes the session post an hb on the control slot
			// while the writer is parked between fragments.
			fh.events(1, 0, chunkEvent(1, "tick"))
			waitFor(t, func() bool {
				h.mu.Lock()
				s := h.hosts["h1"].session
				h.mu.Unlock()
				if s == nil {
					return false
				}
				w := s.writer.Load()
				return w != nil && w.controlLen() > 0
			}, 2*time.Second)
		})
	})

	body := json.RawMessage(`{"pad":"` + strings.Repeat("x", 100<<10) + `"}`)
	go func() {
		_, _ = h.Dispatch(context.Background(), "h1", "POST", "/api/prompt", body)
	}()

	var (
		units    int
		expected int
		hbIndex  = -1
		last     = -1
	)
	for i := 0; ; i++ {
		raw := fh.recvRaw(2 * time.Second)
		if len(raw) >= 13 && raw[0] <= wire.UnitCompressed|wire.UnitFragment {
			u, err := wire.DecodeUnit(raw)
			if err != nil {
				t.Fatalf("decode unit: %v", err)
			}
			if u.Flags&wire.UnitFragment != 0 {
				if expected == 0 {
					expected = int((uint64(u.Total) + wire.UnitSize - 1) / wire.UnitSize)
				}
				units++
				last = i
			}
			if units >= expected {
				break
			}
			continue
		}
		f, err := wire.Decode(raw)
		if err != nil {
			t.Fatalf("decode control frame: %v", err)
		}
		if f.Type == wire.TypeHeartbeat && hbIndex < 0 {
			hbIndex = i
		}
	}
	if units < 3 {
		t.Fatalf("large frame produced %d fragments, want at least 3", units)
	}
	if hbIndex <= 0 || hbIndex >= last {
		t.Fatalf("control hb at %d, fragments end at %d: hb was not interleaved", hbIndex, last)
	}
}

// TestWriterDoesNotBlockSessionLoop: while the transport's write is wedged,
// the session still applies incoming events and updates its watermark.
func TestWriterDoesNotBlockSessionLoop(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	release := make(chan struct{})
	fh.ft.setBlock(release)
	defer close(release)

	go func() { _, _ = h.Dispatch(context.Background(), "h1", "GET", "/api/status", nil) }()
	waitWriterBusy(t, h, "h1")

	fh.events(1, 0, chunkEvent(1, "a"))
	waitFor(t, func() bool { return h.LastSeq("h1") == 1 }, 2*time.Second)
}

// TestRTOReplaySuppressedWhileWriterBusy: a write stalled past the RTO does not
// queue a replay behind itself; after the write completes the request exists
// on the wire exactly once.
func TestRTOReplaySuppressedWhileWriterBusy(t *testing.T) {
	shortLiveness(t, 1, 10)
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	release := make(chan struct{})
	fh.ft.setBlock(release)
	go func() { _, _ = h.Dispatch(context.Background(), "h1", "GET", "/api/status", nil) }()
	waitWriterBusy(t, h, "h1")

	// Two RTO periods pass with the writer stuck in one write.
	time.Sleep(3 * time.Second)
	close(release)

	requests := 0
	deadline := time.Now().Add(1200 * time.Millisecond)
	for time.Now().Before(deadline) {
		select {
		case raw := <-fh.ft.outbox:
			f, err := wire.Decode(raw)
			if err == nil && f.Type == wire.TypeRequest {
				requests++
			}
		case <-time.After(100 * time.Millisecond):
		}
	}
	if requests != 1 {
		t.Fatalf("request frames after release = %d, want exactly 1 (no replay queued behind a busy writer)", requests)
	}

}
