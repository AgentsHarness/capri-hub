package hub

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/wire"
)

func TestDispatchAbandonedByBrowser(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	// A host that accepts the request and never answers.
	fh := dialFakeHost(t, h, "h1", 1)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, e := h.Dispatch(ctx, "h1", "POST", "/api/prompt", nil)
		done <- e
	}()

	// Wait for the request to be registered as pending.
	deadline := time.Now().Add(2 * time.Second)
	for {
		h.mu.Lock()
		n := len(h.pending["h1"])
		h.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("request never became pending")
		}
		time.Sleep(2 * time.Millisecond)
	}

	fh.recvType(wire.TypeRequest, 2*time.Second)
	cancel() // browser goes away
	select {
	case e := <-done:
		var re *RelayError
		if !errors.As(e, &re) || re.Status != 499 {
			t.Fatalf("err = %v, want *RelayError{Status:499}", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Dispatch kept waiting after the browser cancelled — it would hold the slot for RelayTimeout")
	}

	// The pending slot must be gone, not left for the 45-minute timer.
	deadline = time.Now().Add(2 * time.Second)
	for {
		h.mu.Lock()
		n := len(h.pending["h1"])
		h.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending entry leaked after cancellation (%d left)", n)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestIngestRawEvents: the raw (pre-encoded) path ingests event bodies without
// decoding them into maps — seqs are preserved, hostId/hostName tags are
// spliced in, and the broadcast event serializes via MarshalEvent to the
// original bytes. Ordering and duplicates are the receiver's job, not this
// function's.
func TestIngestRawEvents(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	ch, unsub := h.Subscribe()
	defer unsub()

	raws := []json.RawMessage{
		json.RawMessage(`{"type":"chunk","text":"a","seq":10}`),
		json.RawMessage(`{"type":"chunk","text":"b","seq":11}`),
	}
	if !testIngest(h, "h1", raws) {
		t.Fatal("ingest failed for paired host")
	}
	if got := h.LastSeq("h1"); got != 11 {
		t.Fatalf("LastSeq = %d, want 11", got)
	}
	var wires []map[string]any
	for len(wires) < 2 {
		select {
		case ev := <-ch:
			if ev["type"] != "chunk" {
				continue // hosts_changed / subscribed noise
			}
			wireBytes, err := MarshalEvent(ev)
			if err != nil {
				t.Fatalf("MarshalEvent: %v", err)
			}
			var m map[string]any
			if json.Unmarshal(wireBytes, &m) != nil {
				t.Fatalf("spliced wire is not valid JSON: %s", wireBytes)
			}
			wires = append(wires, m)
		case <-time.After(time.Second):
			t.Fatalf("only %d events", len(wires))
		}
	}
	if wires[0]["text"] != "a" || wires[0]["seq"].(float64) != 10 {
		t.Errorf("event 0 = %v", wires[0])
	}
	if wires[0]["hostId"] != "h1" || wires[0]["hostName"] != "H1" {
		t.Errorf("event 0 tags missing: %v", wires[0])
	}
	if wires[1]["text"] != "b" || wires[1]["seq"].(float64) != 11 {
		t.Errorf("event 1 = %v", wires[1])
	}
	if evs := h.EventsAfter("h1", 0); len(evs) != 2 {
		t.Errorf("EventsAfter = %d events, want 2", len(evs))
	}
	// Non-object entries are skipped.
	testIngest(h, "h1", []json.RawMessage{json.RawMessage(`null`)})
	if got := h.LastSeq("h1"); got != 11 {
		t.Errorf("LastSeq after null entry = %d, want 11", got)
	}
	if testIngest(h, "nope", nil) {
		t.Error("unknown host must return false")
	}
}

// TestRegisterEventPerHostLockParallel: with the per-host data-plane
// lock, concurrent ingestion on different hosts must stay correct (no
// lost/duplicated seqs, strictly ordered buffers) — run under -race this
// also pins the h.mu → hs.mu lock ordering.
func TestRegisterEventPerHostLockParallel(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	testPair(t, h, "h2", "H2")

	const perHost = 500
	var wg sync.WaitGroup
	for _, id := range []string{"h1", "h2"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			for i := 1; i <= perHost; i++ {
				if !hubRaw(h, id, Event{"type": "chunk", "seq": uint64(i)}) {
					t.Errorf("register %s/%d failed", id, i)
					return
				}
			}
		}(id)
	}
	// Concurrent COW churn: subscribe/unsubscribe while events flow, so
	// fan-out snapshots race list swaps (must be torn-read free).
	stopChurn := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopChurn:
				return
			default:
				ch, unsub := h.Subscribe()
				// Non-blocking drain so the channel cannot fill.
				for {
					select {
					case <-ch:
					default:
						goto done
					}
				}
			done:
				unsub()
			}
		}
	}()
	wg.Wait()
	close(stopChurn)

	for _, id := range []string{"h1", "h2"} {
		if got := h.LastSeq(id); got != perHost {
			t.Errorf("%s LastSeq = %d, want %d", id, got, perHost)
		}
		evs := h.EventsAfter(id, 0)
		if len(evs) != perHost {
			t.Fatalf("%s buffered %d events, want %d", id, len(evs), perHost)
		}
		for i, ev := range evs {
			if got, want := evSeq(ev), uint64(i+1); got != want {
				t.Fatalf("%s buffer[%d] seq = %d, want %d (order/loss violated)", id, i, got, want)
			}
		}
	}
}

// TestFanoutResyncOnDropThreshold: once a slow subscriber accumulates
// resyncDropThreshold dropped events, it receives ONE
// {"type":"resync",fromSeq:N} frame and the counter resets (the next
// resync needs another full threshold of drops — no storm).
func TestFanoutResyncOnDropThreshold(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	ch, unsub := h.Subscribe()
	defer unsub()

	// Fill the 512-slot queue synchronously (no drops yet: the counter
	// only starts once the queue is full).
	for i := 1; i <= 512; i++ {
		hubRaw(h, "h1", Event{"type": "chunk", "seq": uint64(i)})
	}
	// 40 more events all drop. The sender runs in a goroutine because
	// the resync delivery (on the 32nd drop) blocks until we drain; we
	// pause first so the goroutine hits a genuinely full queue instead
	// of racing into slots our drain loop frees.
	go func() {
		for i := 513; i <= 552; i++ {
			hubRaw(h, "h1", Event{"type": "chunk", "seq": uint64(i)})
		}
	}()
	time.Sleep(200 * time.Millisecond)
	resyncs := 0
	var lastResyncSeq uint64
	deadline := time.After(5 * time.Second)
	for resyncs < 1 {
		select {
		case ev := <-ch:
			if typ, _ := ev["type"].(string); typ == "resync" {
				resyncs++
				if fs, ok := ev["fromSeq"].(uint64); ok {
					lastResyncSeq = fs
				}
			}
		case <-deadline:
			t.Fatalf("no resync after threshold drops (got %d)", resyncs)
		}
	}
	if lastResyncSeq != 544 {
		t.Errorf("resync fromSeq = %d, want 544 (seq of the 32nd drop after the queue filled)", lastResyncSeq)
	}
	// Drain the rest; no second resync may appear (only 8 further drops
	// since the counter reset).
	quiet := time.After(300 * time.Millisecond)
	for {
		select {
		case ev := <-ch:
			if typ, _ := ev["type"].(string); typ == "resync" {
				t.Fatal("unexpected second resync below threshold (storm)")
			}
		case <-quiet:
			return
		}
	}
}

// TestFanoutCriticalEventSurvivesBackpressure: with the queue full, a
// terminal event is delivered via the blocking fallback rather than
// dropped (the FE would otherwise wait forever on a finished turn).
func TestFanoutCriticalEventSurvivesBackpressure(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	ch, unsub := h.Subscribe()
	defer unsub()

	// Exactly fill the queue with droppable chunks.
	for i := 1; i <= 512; i++ {
		hubRaw(h, "h1", Event{"type": "chunk", "seq": uint64(i)})
	}
	// Queue full. A critical event must still land: the sender blocks
	// briefly, so read concurrently.
	go hubRaw(h, "h1", Event{"type": "done", "seq": 513})
	deadline := time.After(2 * time.Second)
	for {
		select {
		case ev := <-ch:
			if typ, _ := ev["type"].(string); typ == "done" {
				return // delivered despite a full queue
			}
		case <-deadline:
			t.Fatal("critical event dropped on full queue")
		}
	}
}

// TestRawTerminalToolUpdateIsCritical: the raw ingest path must lift a
// tool call's terminal status into the Event so the drop tier can see it,
// without that flag ever reaching the FE wire.
func TestRawTerminalToolUpdateIsCritical(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	ch, unsub := h.Subscribe()
	defer unsub()

	raws := []json.RawMessage{
		json.RawMessage(`{"type":"tool_call_update","toolCallUpdate":{"toolCallId":"c1","status":"in_progress"},"seq":1}`),
		json.RawMessage(`{"type":"tool_call_update","toolCallUpdate":{"toolCallId":"c1","status":"completed"},"seq":2}`),
		json.RawMessage(`{"type":"chunk","text":"x","seq":3}`),
	}
	testIngest(h, "h1", raws)

	wantCritical := map[string]bool{"in_progress": false, "completed": false, "chunk": false}
	seen := 0
	for seen < 3 {
		select {
		case ev := <-ch:
			typ, _ := ev["type"].(string)
			if typ != "tool_call_update" && typ != "chunk" {
				continue // hosts_changed noise
			}
			seen++
			name := typ
			if typ == "tool_call_update" {
				u, _ := ev["toolCallUpdate"].(map[string]any)
				if u != nil {
					t.Errorf("raw event must not decode the body: %v", u)
				}
				wire, err := MarshalEvent(ev)
				if err != nil {
					t.Fatalf("MarshalEvent: %v", err)
				}
				if strings.Contains(string(wire), "terminalTool") {
					t.Errorf("internal flag leaked onto the FE wire: %s", wire)
				}
				if strings.Contains(string(wire), `"completed"`) {
					name = "completed"
				} else {
					name = "in_progress"
				}
			}
			wantCritical[name] = criticalEvent(ev)
		case <-time.After(time.Second):
			t.Fatalf("only %d of 3 events fan-out", seen)
		}
	}
	if !wantCritical["completed"] {
		t.Error("terminal tool_call_update not critical — the FE would wait for the turn-end settle")
	}
	if wantCritical["in_progress"] {
		t.Error("in_progress tool_call_update must stay droppable (streaming deltas)")
	}
	if wantCritical["chunk"] {
		t.Error("chunk must stay droppable")
	}
}

// TestDeliverTerminalToolUpdateOnFullQueue: on a wedged subscriber the
// completion lands via the blocking fallback while a delta drops and counts
// toward the resync threshold.
func TestDeliverTerminalToolUpdateOnFullQueue(t *testing.T) {
	// Delivery is asynchronous (per-subscriber ring + pump): deliver only
	// enqueues, the pump owns ch. A wedged consumer may therefore hold the
	// pump at the terminal event, but must never lose it.
	s := newFeSubscriber(1)
	defer s.stop()
	s.deliver(Event{"seq": uint64(1), "type": "chunk"}) // fills ch
	if ev := <-s.ch; ev["type"] != "chunk" {
		t.Fatalf("first delivery = %v, want chunk", ev)
	}

	s.deliver(Event{
		"type":                "tool_call_update",
		terminalToolUpdateKey: true,
	})
	// The terminal event must arrive even though ch was saturated when it
	// was enqueued (the pump waits for the slot instead of dropping it).
	select {
	case ev := <-s.ch:
		if ev["type"] != "tool_call_update" {
			t.Fatalf("delivered %v, want the terminal tool_call_update", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("terminal tool_call_update dropped on a full queue")
	}
	if got := s.dropped.Load(); got != 0 {
		t.Errorf("dropped = %d, want 0", got)
	}

	// A non-terminal (in_progress) delta stays droppable under pressure: it
	// must not displace the queued event, and it counts toward the resync
	// threshold.
	s2 := newFeSubscriber(1)
	defer s2.stop()
	s2.deliver(Event{"seq": uint64(1), "type": "chunk"}) // fills ch (pump delivers it)
	if ev := <-s2.ch; ev["type"] != "chunk" {
		t.Fatalf("first delivery = %v, want chunk", ev)
	}
	// Re-fill ch so the next droppable delivery has nowhere to go.
	s2.deliver(Event{"seq": uint64(1), "type": "chunk"})
	waitFor(t, func() bool { return len(s2.ch) == 1 }, time.Second)
	s2.deliver(Event{"seq": uint64(1), "type": "tool_call_update"}) // no terminal flag
	waitFor(t, func() bool { return s2.dropped.Load() == 1 }, time.Second)
	if n := len(s2.ch); n != 1 {
		t.Errorf("delta must not displace the queued event (len=%d)", n)
	}
	if got := s2.dropped.Load(); got != 1 {
		t.Errorf("dropped = %d, want 1 (counts toward resync)", got)
	}
}
