package hub

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/wire"
)

func TestSessionAttachDetach(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	fh := dialFakeHost(t, h, "h1", 1)
	hosts := h.ListHosts()
	if len(hosts) != 1 || !hosts[0].Online {
		t.Fatalf("host should be online: %+v", hosts)
	}
	if h.DefaultHostID() != "h1" {
		t.Errorf("default host = %q, want h1", h.DefaultHostID())
	}

	fh.ft.hangup()
	waitFor(t, func() bool { return !h.ListHosts()[0].Online }, 2*time.Second)
	// The known host stays the default (requests would 503 while offline).
	if h.DefaultHostID() != "h1" {
		t.Errorf("default host = %q, want h1", h.DefaultHostID())
	}

	// A reconnect brings it back online.
	again := dialFakeHost(t, h, "h1", 1)
	waitFor(t, func() bool { return h.ListHosts()[0].Online }, 2*time.Second)
	again.ft.hangup()
}

func TestDispatchAndRespond(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	body := json.RawMessage(`{"blocks":[{"type":"text","text":"hi"}]}`)
	type result struct {
		resp RelayResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := h.Dispatch(context.Background(), "h1", "POST", "/api/prompt", body)
		done <- result{resp, err}
	}()

	f := fh.recvType(wire.TypeRequest, 2*time.Second)
	if f.ReqID == "" || f.Method != "POST" || f.Path != "/api/prompt" {
		t.Fatalf("relay frame = %+v", f)
	}
	if string(f.Body) != string(body) {
		t.Errorf("body = %s, want %s", f.Body, body)
	}
	if f.Seq == 0 {
		t.Error("request must consume the down seq space")
	}

	answer := RelayResponse{Status: 200, Body: json.RawMessage(`{"ok":true}`)}
	if !h.Respond("h1", f.ReqID, answer) {
		t.Fatal("Respond should resolve a pending request")
	}
	if h.Respond("h1", f.ReqID, answer) {
		t.Error("second Respond for the same reqId should fail")
	}

	r := <-done
	if r.err != nil || r.resp.Status != 200 || string(r.resp.Body) != `{"ok":true}` {
		t.Errorf("dispatch result = %+v, %v", r.resp, r.err)
	}
}

func TestDispatchOffline(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	_, err := h.Dispatch(context.Background(), "h1", "POST", "/api/prompt", nil)
	var re *RelayError
	if !errors.As(err, &re) || re.Status != 503 {
		t.Errorf("offline dispatch err = %v, want RelayError 503", err)
	}
	if _, err := h.Dispatch(context.Background(), "nope", "POST", "/api/prompt", nil); !errors.As(err, &re) || re.Status != 404 {
		t.Errorf("unknown host dispatch err = %v, want 404", err)
	}
}

func TestEventTaggingAndFanout(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	ch, unsub := h.Subscribe()
	defer unsub()

	if !hubRaw(h, "h1", Event{"type": "chunk", "text": "hi", "seq": uint64(1)}) {
		t.Fatal("ingest failed for paired host")
	}
	select {
	case ev := <-ch:
		if ev["hostId"] != "h1" || ev["hostName"] != "H1" {
			t.Errorf("event tags = %v/%v", ev["hostId"], ev["hostName"])
		}
		if ev["type"] != "chunk" {
			t.Errorf("event type = %v", ev["type"])
		}
	case <-time.After(time.Second):
		t.Fatal("no event received")
	}

	// Unknown host events are rejected.
	if hubRaw(h, "nope", Event{"type": "chunk", "seq": uint64(2)}) {
		t.Error("ingest for unknown host should fail")
	}
}

// UpdateHostStatus is control-plane state: it updates Ready without becoming
// an event or moving the data-plane watermark.
func TestHostStatusIsControlFrame(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	ready := true
	if !h.UpdateHostStatus("h1", HostStatusPatch{Ready: &ready}) {
		t.Fatal("UpdateHostStatus failed")
	}
	if hosts := h.ListHosts(); len(hosts) != 1 || !hosts[0].Ready {
		t.Errorf("ready not tracked: %+v", hosts)
	}
	ch, unsub := h.Subscribe()
	defer unsub()
	if hubRaw(h, "h1", Event{"type": "chunk", "text": "x", "seq": uint64(1)}) != true {
		t.Fatal("ingest failed")
	}
	if hosts := h.ListHosts(); len(hosts) != 1 || hosts[0].Ready {
		t.Log("ready stays independent of data-plane events (informational)")
	}
	drainEvents(ch, 50*time.Millisecond)
}

func TestHostsOrderingAndDefault(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	testPair(t, h, "h2", "H2")

	// h2 connects (online) → sorts first, becomes default.
	fh2 := dialFakeHost(t, h, "h2", 1)
	hosts := h.ListHosts()
	if len(hosts) != 2 || hosts[0].HostID != "h2" {
		t.Errorf("ordering = %+v, want h2 first", hosts)
	}
	if h.DefaultHostID() != "h2" {
		t.Errorf("default = %q, want h2", h.DefaultHostID())
	}

	// After h2 disconnects, default falls back to the most recently seen
	// host — h1, refreshed by a recent event.
	hubRaw(h, "h1", Event{"type": "chunk", "text": "x", "seq": uint64(1), "sessionId": "s1"})
	fh2.ft.hangup()
	waitFor(t, func() bool {
		for _, hi := range h.ListHosts() {
			if hi.HostID == "h2" {
				return !hi.Online
			}
		}
		return false
	}, 2*time.Second)
	if h.DefaultHostID() != "h1" {
		t.Errorf("default after offline = %q, want h1", h.DefaultHostID())
	}
}

// TestListHostsLastSeenAge pins the freshness value the FE silence probe
// reads: it must be measured on the hub clock, so a skewed browser clock
// cannot change the verdict. A host that just sent a frame is fresh; an
// artificially old stamp must show up as an old age.
func TestListHostsLastSeenAge(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	dialFakeHost(t, h, "h1", 1)
	waitFor(t, func() bool {
		hosts := h.ListHosts()
		return len(hosts) == 1 && hosts[0].Online
	}, 2*time.Second)

	hosts := h.ListHosts()
	if len(hosts) != 1 {
		t.Fatalf("hosts = %+v, want one entry", hosts)
	}
	if age := hosts[0].LastSeenAgeMs; age < 0 || age > 1000 {
		t.Fatalf("fresh host LastSeenAgeMs = %d, want 0..1000", age)
	}

	h.mu.Lock()
	h.hosts["h1"].info.LastSeen = time.Now().Add(-5 * time.Second)
	h.mu.Unlock()
	if age := h.ListHosts()[0].LastSeenAgeMs; age < 4_000 || age > 6_000 {
		t.Fatalf("stale host LastSeenAgeMs = %d, want about 5000", age)
	}
}

func TestHostsChangedBroadcast(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	ch, unsub := h.Subscribe()
	defer unsub()

	fh := dialFakeHost(t, h, "h1", 1)
	waitForEventType(t, ch, "hosts_changed")
	fh.ft.hangup()
	waitForEventType(t, ch, "hosts_changed")
}

func TestEventsAfterSeqTypes(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	if !hubRaw(h, "h1", Event{"type": "chunk", "text": "a", "seq": uint64(1)}) {
		t.Fatal("register 1")
	}
	if !hubRaw(h, "h1", Event{"type": "chunk", "text": "b", "seq": float64(2)}) {
		t.Fatal("register 2")
	}

	evs := h.EventsAfter("h1", 1)
	if len(evs) != 1 {
		t.Fatalf("EventsAfter(1) = %d events, want 1: %v", len(evs), evs)
	}
	if evSeq(evs[0]) != 2 {
		t.Errorf("seq = %v, want 2", evSeq(evs[0]))
	}
}

// TestRegisterRawEventsNilEntry: a malformed events frame (e.g.
// {"events":[null]}) must be skipped, not panic.
func TestRegisterRawEventsNilEntry(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	if !testIngest(h, "h1", []json.RawMessage{[]byte("null")}) {
		t.Error("known host should be accepted even when every entry is invalid")
	}
	if n := len(h.EventsAfter("h1", 0)); n != 0 {
		t.Errorf("invalid entry was buffered: %d", n)
	}
}

// TestRegisterRawEventsDoesNotMutateInput: ingest must not rewrite the
// caller's raw JSON — the hub splices its tags into a fresh buffer, leaving
// the frame bytes it was handed untouched.
func TestRegisterRawEventsDoesNotMutateInput(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	ch, unsub := h.Subscribe()
	defer unsub()

	body := json.RawMessage(`{"type":"chunk","text":"x","seq":1}`)
	before := string(body)
	if !testIngest(h, "h1", []json.RawMessage{body}) {
		t.Fatal("ingest failed")
	}
	if string(body) != before {
		t.Errorf("caller bytes mutated: %s", body)
	}
	// The buffered/broadcast copy must carry the injected tags.
	select {
	case got := <-ch:
		if got["type"] != "chunk" {
			t.Errorf("broadcast event = %v, want type=chunk", got)
		}
		if got["hostId"] != "h1" || got["hostName"] != "H1" {
			t.Errorf("broadcast event tags = %v/%v", got["hostId"], got["hostName"])
		}
		if _, ok := got["seq"]; !ok {
			t.Error("broadcast event missing seq")
		}
	case <-time.After(time.Second):
		t.Fatal("no event received")
	}
	// Mutating the broadcast copy must not leak into the replay buffer.
	evs := h.EventsAfter("h1", 0)
	if len(evs) != 1 || evs[0]["type"] != "chunk" {
		t.Fatalf("EventsAfter = %v, want the tagged copy", evs)
	}
}

// TestRegisterEventSeqRegression: a host replaying events with a stale
// or equal seq must not move the per-host counter backwards, must not
// re-fan-out to FE subscribers, and must not re-append to the gap-pull
// buffer. LastSeen is still refreshed (return true). A higher seq still
// advances and fans out as usual.
// TestHostStatusControlFrame: a control-plane status update sets Ready and
// fires hosts_changed on flip, without advancing LastSeq or buffering events.
func TestHostStatusControlFrame(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	// Seed a sequenced event so LastSeq is non-zero.
	if !hubRaw(h, "h1", Event{"type": "chunk", "text": "x", "seq": uint64(7)}) {
		t.Fatal("register seed")
	}
	if got := h.LastSeq("h1"); got != 7 {
		t.Fatalf("LastSeq = %d, want 7", got)
	}

	ch, unsub := h.Subscribe()
	defer unsub()
	// Asynchronous fan-out: the seed chunk registered above may still be in
	// the queue. Drain it so the hosts_changed assertions below read the
	// control-plane frames, not the data-plane seed.
	drainEvents(ch, 100*time.Millisecond)

	setReady := func(ready bool) bool {
		return h.UpdateHostStatus("h1", HostStatusPatch{Ready: &ready})
	}
	if !setReady(true) {
		t.Fatal("status ready=true failed")
	}
	if hosts := h.ListHosts(); len(hosts) != 1 || !hosts[0].Ready {
		t.Errorf("ready not set: %+v", hosts)
	}
	if got := h.LastSeq("h1"); got != 7 {
		t.Errorf("LastSeq = %d after a status update, want 7 (must not advance)", got)
	}
	if n := len(h.EventsAfter("h1", 0)); n != 1 {
		t.Errorf("evBuf len = %d after a status update, want 1", n)
	}
	select {
	case ev := <-ch:
		if ev["type"] != "hosts_changed" {
			t.Errorf("event = %v, want hosts_changed", ev["type"])
		}
	case <-time.After(time.Second):
		t.Fatal("no hosts_changed on ready flip")
	}

	// Same ready value: no second hosts_changed.
	if !setReady(true) {
		t.Fatal("status ready=true (noop) failed")
	}
	select {
	case ev := <-ch:
		t.Fatalf("ready unchanged must not rebroadcast, got %v", ev)
	case <-time.After(50 * time.Millisecond):
		// expected
	}

	// Flip false → hosts_changed again.
	if !setReady(false) {
		t.Fatal("status ready=false failed")
	}
	if hosts := h.ListHosts(); len(hosts) != 1 || hosts[0].Ready {
		t.Errorf("ready should be false: %+v", hosts)
	}
	select {
	case ev := <-ch:
		if ev["type"] != "hosts_changed" {
			t.Errorf("event = %v, want hosts_changed", ev["type"])
		}
	case <-time.After(time.Second):
		t.Fatal("no hosts_changed on ready→false")
	}

	ready := true
	if h.UpdateHostStatus("nope", HostStatusPatch{Ready: &ready}) {
		t.Error("status update for unknown host should fail")
	}
}

// TestUpdateHostStatus: the hb status snapshot carries the live registry
// fields (ready/busy/booting/pendingCount); hosts_changed fires on ANY flip,
// nil fields leave the current value untouched, and identical snapshots stay
// silent.
func TestUpdateHostStatus(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	boolPtr := func(b bool) *bool { return &b }
	intPtr := func(n int) *int { return &n }
	strPtr := func(s string) *string { return &s }

	ch, unsub := h.Subscribe()
	defer unsub()

	// Full update: ready+busy flip → one hosts_changed.
	if !h.UpdateHostStatus("h1", HostStatusPatch{
		Ready: boolPtr(true), Busy: boolPtr(true), Booting: boolPtr(false), PendingCount: intPtr(2),
	}) {
		t.Fatal("UpdateHostStatus failed")
	}
	if hosts := h.ListHosts(); len(hosts) != 1 {
		t.Fatalf("hosts len = %d", len(hosts))
	} else {
		got := hosts[0]
		if !got.Ready || !got.Busy || got.Booting || got.PendingCount != 2 {
			t.Errorf("registry = %+v, want ready+busy, booting=false, pending=2", got)
		}
	}
	select {
	case ev := <-ch:
		if ev["type"] != "hosts_changed" {
			t.Errorf("event = %v, want hosts_changed", ev["type"])
		}
	case <-time.After(time.Second):
		t.Fatal("no hosts_changed on full status update")
	}

	// Identical frame → silent (no rebroadcast).
	if !h.UpdateHostStatus("h1", HostStatusPatch{
		Ready: boolPtr(true), Busy: boolPtr(true), Booting: boolPtr(false), PendingCount: intPtr(2),
	}) {
		t.Fatal("UpdateHostStatus noop failed")
	}
	select {
	case ev := <-ch:
		t.Fatalf("unchanged status must not rebroadcast, got %v", ev)
	case <-time.After(50 * time.Millisecond):
		// expected
	}

	// Busy-only flip fires hosts_changed and leaves other fields intact.
	if !h.UpdateHostStatus("h1", HostStatusPatch{Busy: boolPtr(false)}) {
		t.Fatal("UpdateHostStatus busy flip failed")
	}
	if hosts := h.ListHosts(); len(hosts) != 1 || hosts[0].Busy || hosts[0].PendingCount != 2 || !hosts[0].Ready {
		t.Errorf("registry = %+v, want busy=false, ready/pending untouched", hosts[0])
	}
	select {
	case ev := <-ch:
		if ev["type"] != "hosts_changed" {
			t.Errorf("event = %v, want hosts_changed", ev["type"])
		}
	case <-time.After(time.Second):
		t.Fatal("no hosts_changed on busy flip")
	}

	// Nil fields (older host frame shape) leave current values untouched.
	if !h.UpdateHostStatus("h1", HostStatusPatch{Ready: boolPtr(false)}) {
		t.Fatal("UpdateHostStatus ready-only failed")
	}
	if hosts := h.ListHosts(); len(hosts) != 1 || hosts[0].Busy || hosts[0].Booting || hosts[0].PendingCount != 2 {
		t.Errorf("registry = %+v, want busy/booting/pending untouched by ready-only patch", hosts[0])
	}

	// PendingCount flip alone also broadcasts.
	if !h.UpdateHostStatus("h1", HostStatusPatch{PendingCount: intPtr(0)}) {
		t.Fatal("UpdateHostStatus pending flip failed")
	}
	select {
	case ev := <-ch:
		if ev["type"] != "hosts_changed" {
			t.Errorf("event = %v, want hosts_changed", ev["type"])
		}
	case <-time.After(time.Second):
		t.Fatal("no hosts_changed on pending flip")
	}

	// Port flip updates registry + broadcasts; invalid ports are ignored.
	if !h.UpdateHostStatus("h1", HostStatusPatch{Port: intPtr(8765)}) {
		t.Fatal("UpdateHostStatus port flip failed")
	}
	if hosts := h.ListHosts(); len(hosts) != 1 || hosts[0].Port != 8765 {
		t.Errorf("registry port = %+v, want 8765", hosts[0])
	}
	select {
	case ev := <-ch:
		if ev["type"] != "hosts_changed" {
			t.Errorf("event = %v, want hosts_changed", ev["type"])
		}
	case <-time.After(time.Second):
		t.Fatal("no hosts_changed on port flip")
	}
	if !h.UpdateHostStatus("h1", HostStatusPatch{Port: intPtr(0)}) {
		t.Fatal("UpdateHostStatus invalid port failed")
	}
	if hosts := h.ListHosts(); len(hosts) != 1 || hosts[0].Port != 8765 {
		t.Errorf("invalid port must leave registry untouched, got %+v", hosts[0])
	}

	// Version flip updates the registry and broadcasts; an empty version
	// from an older host must not erase the last known one.
	if !h.UpdateHostStatus("h1", HostStatusPatch{Version: strPtr("v0.5.0")}) {
		t.Fatal("UpdateHostStatus version flip failed")
	}
	if hosts := h.ListHosts(); len(hosts) != 1 || hosts[0].Version != "v0.5.0" {
		t.Errorf("registry version = %+v, want v0.5.0", hosts[0])
	}
	select {
	case ev := <-ch:
		if ev["type"] != "hosts_changed" {
			t.Errorf("event = %v, want hosts_changed", ev["type"])
		}
	case <-time.After(time.Second):
		t.Fatal("no hosts_changed on version flip")
	}
	if !h.UpdateHostStatus("h1", HostStatusPatch{Version: strPtr("")}) {
		t.Fatal("UpdateHostStatus empty version failed")
	}
	if hosts := h.ListHosts(); len(hosts) != 1 || hosts[0].Version != "v0.5.0" {
		t.Errorf("empty version must leave registry untouched, got %+v", hosts[0])
	}

	if h.UpdateHostStatus("nope", HostStatusPatch{Ready: boolPtr(true)}) {
		t.Error("UpdateHostStatus for unknown host should fail")
	}
}
