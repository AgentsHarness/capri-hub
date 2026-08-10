package hub

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// testPair pairs hostID and returns its token.
func testPair(t *testing.T, h *Hub, hostID, hostName string) string {
	t.Helper()
	code, _ := h.PairingCode()
	token, err := h.Pair(code, hostID, hostName)
	if err != nil {
		t.Fatalf("Pair(%s): %v", hostID, err)
	}
	return token
}

func TestPairingFlow(t *testing.T) {
	h := NewWithDir(t.TempDir())
	code, exp := h.PairingCode()
	if len(code) != 6 {
		t.Errorf("code length = %d, want 6", len(code))
	}
	if !exp.After(time.Now()) {
		t.Error("code should not be expired")
	}

	if _, err := h.Pair("WRONG", "h1", "H1"); !errors.Is(err, ErrCodeInvalid) {
		t.Errorf("wrong code err = %v, want ErrCodeInvalid", err)
	}
	// Code matching is case-insensitive.
	tok, err := h.Pair(strings.ToLower(code), "h1", "H1")
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	if hid, ok := h.HostIDForToken(tok); !ok || hid != "h1" {
		t.Errorf("HostIDForToken = %q,%v want h1,true", hid, ok)
	}
	if _, ok := h.HostIDForToken("bogus"); ok {
		t.Error("bogus token should not resolve")
	}

	// Re-pairing revokes the old token.
	tok2, err := h.Pair(code, "h1", "H1-renamed")
	if err != nil {
		t.Fatalf("re-pair: %v", err)
	}
	if _, ok := h.HostIDForToken(tok); ok {
		t.Error("old token should be revoked after re-pair")
	}
	if _, ok := h.HostIDForToken(tok2); !ok {
		t.Error("new token should resolve")
	}
}

func TestExpiredCode(t *testing.T) {
	h := NewWithDir(t.TempDir())
	h.mu.Lock()
	h.codeExpires = time.Now().Add(-time.Minute)
	h.mu.Unlock()
	if _, err := h.Pair(h.pairingCode, "h1", "H1"); !errors.Is(err, ErrCodeInvalid) {
		t.Errorf("expired code err = %v, want ErrCodeInvalid", err)
	}
}

func TestPairingPersistence(t *testing.T) {
	dir := t.TempDir()
	h1 := NewWithDir(dir)
	tok := testPair(t, h1, "h1", "H1")

	h2 := NewWithDir(dir) // "restart"
	if hid, ok := h2.HostIDForToken(tok); !ok || hid != "h1" {
		t.Errorf("token lost across restart: %q,%v", hid, ok)
	}
	hosts := h2.ListHosts()
	if len(hosts) != 1 || hosts[0].HostID != "h1" || hosts[0].HostName != "H1" {
		t.Errorf("hosts after restart = %+v", hosts)
	}
}

func TestStreamLifecycle(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	write := func(payload []byte) error { return nil }
	conn, stop, err := h.ConnectStream("h1", write)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	hosts := h.ListHosts()
	if len(hosts) != 1 || !hosts[0].Online {
		t.Fatalf("host should be online: %+v", hosts)
	}
	if h.DefaultHostID() != "h1" {
		t.Errorf("default host = %q, want h1", h.DefaultHostID())
	}

	stop()
	if h.ListHosts()[0].Online {
		t.Error("host should be offline after stop")
	}
	// Only known host stays the default (requests would 503 while offline).
	if h.DefaultHostID() != "h1" {
		t.Errorf("default host = %q, want h1", h.DefaultHostID())
	}

	// A stale stop (old conn) must not kill the new connection.
	conn2, stop2, err := h.ConnectStream("h1", write)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	_ = conn
	stop() // stale
	if !h.ListHosts()[0].Online {
		t.Error("stale stop must not mark host offline")
	}
	_ = conn2
	stop2()
	if h.ListHosts()[0].Online {
		t.Error("host should be offline after real stop")
	}

	if _, _, err := h.ConnectStream("nope", write); !errors.Is(err, ErrHostUnknown) {
		t.Errorf("connect unknown host err = %v", err)
	}
}

func TestDispatchAndRespond(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	type frame struct {
		ReqID  string          `json:"reqId"`
		Method string          `json:"method"`
		Path   string          `json:"path"`
		Body   json.RawMessage `json:"body"`
	}
	got := make(chan frame, 1)
	_, stop, err := h.ConnectStream("h1", func(payload []byte) error {
		var f frame
		if err := json.Unmarshal(payload, &f); err != nil {
			t.Errorf("bad relay frame: %v", err)
			return err
		}
		got <- f
		return nil
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer stop()

	body := json.RawMessage(`{"blocks":[{"type":"text","text":"hi"}]}`)
	type result struct {
		resp RelayResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := h.Dispatch("h1", "POST", "/api/prompt", body)
		done <- result{resp, err}
	}()

	f := <-got
	if f.ReqID == "" || f.Method != "POST" || f.Path != "/api/prompt" {
		t.Fatalf("relay frame = %+v", f)
	}
	if string(f.Body) != string(body) {
		t.Errorf("body = %s, want %s", f.Body, body)
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
	_, err := h.Dispatch("h1", "POST", "/api/prompt", nil)
	var re *RelayError
	if !errors.As(err, &re) || re.Status != 503 {
		t.Errorf("offline dispatch err = %v, want RelayError 503", err)
	}
	if _, err := h.Dispatch("nope", "POST", "/api/prompt", nil); !errors.As(err, &re) || re.Status != 404 {
		t.Errorf("unknown host dispatch err = %v, want 404", err)
	}
}

func TestDispatchFailsOnDisconnect(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	_, stop, err := h.ConnectStream("h1", func(payload []byte) error { return nil })
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	type result struct {
		resp RelayResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := h.Dispatch("h1", "GET", "/api/status", nil)
		done <- result{resp, err}
	}()
	time.Sleep(50 * time.Millisecond) // let the request register
	stop()                            // host drops mid-request

	select {
	case r := <-done:
		var re *RelayError
		if !errors.As(r.err, &re) || re.Status != 503 {
			t.Errorf("err = %v, want RelayError 503", r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dispatch did not fail fast on disconnect")
	}
}

func TestEventTaggingAndFanout(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	ch, unsub := h.Subscribe()
	defer unsub()

	if !h.RegisterEvent("h1", Event{"type": "chunk", "text": "hi"}) {
		t.Fatal("RegisterEvent failed for paired host")
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
	if h.RegisterEvent("nope", Event{"type": "chunk"}) {
		t.Error("RegisterEvent for unknown host should fail")
	}
}

func TestHostStatusReady(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	if !h.RegisterEvent("h1", Event{"type": "host_status", "ready": true}) {
		t.Fatal("RegisterEvent failed")
	}
	if hosts := h.ListHosts(); len(hosts) != 1 || !hosts[0].Ready {
		t.Errorf("ready not tracked: %+v", hosts)
	}
}

func TestHostsOrderingAndDefault(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	testPair(t, h, "h2", "H2")

	// h2 connects (online) → sorts first, becomes default.
	_, stop, err := h.ConnectStream("h2", func(payload []byte) error { return nil })
	if err != nil {
		t.Fatalf("connect h2: %v", err)
	}
	hosts := h.ListHosts()
	if len(hosts) != 2 || hosts[0].HostID != "h2" {
		t.Errorf("ordering = %+v, want h2 first", hosts)
	}
	if h.DefaultHostID() != "h2" {
		t.Errorf("default = %q, want h2", h.DefaultHostID())
	}

	// After h2 disconnects, default falls back to the most recently seen
	// host — h1, refreshed by a recent event.
	h.RegisterEvent("h1", Event{"type": "chunk", "text": "x"})
	stop()
	if h.DefaultHostID() != "h1" {
		t.Errorf("default after offline = %q, want h1", h.DefaultHostID())
	}
}

func TestHostsChangedBroadcast(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	ch, unsub := h.Subscribe()
	defer unsub()

	_, stop, err := h.ConnectStream("h1", func(payload []byte) error { return nil })
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	select {
	case ev := <-ch:
		if ev["type"] != "hosts_changed" {
			t.Errorf("event = %v, want hosts_changed", ev["type"])
		}
	case <-time.After(time.Second):
		t.Fatal("no hosts_changed on connect")
	}
	stop()
	select {
	case ev := <-ch:
		if ev["type"] != "hosts_changed" {
			t.Errorf("event = %v, want hosts_changed", ev["type"])
		}
	case <-time.After(time.Second):
		t.Fatal("no hosts_changed on disconnect")
	}
}

func TestNotifyHostsSubscribers(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	var (
		mu     sync.Mutex
		frames []map[string]any
	)
	_, stop, err := h.ConnectStream("h1", func(payload []byte) error {
		var m map[string]any
		if json.Unmarshal(payload, &m) != nil {
			return nil
		}
		mu.Lock()
		frames = append(frames, m)
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer stop()

	if h.SubscriberCount() != 0 {
		t.Fatalf("initial subscribers = %d, want 0", h.SubscriberCount())
	}

	_, unsub := h.Subscribe()
	// Subscribe notifies hosts with count=1.
	deadline := time.After(time.Second)
	for {
		mu.Lock()
		n := len(frames)
		last := map[string]any{}
		if n > 0 {
			last = frames[n-1]
		}
		mu.Unlock()
		if last["type"] == "subscribers" && last["count"] == float64(1) {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("no subscribers:1 frame, got %v", frames)
		case <-time.After(10 * time.Millisecond):
		}
	}

	unsub()
	deadline = time.After(time.Second)
	for {
		mu.Lock()
		var got0 bool
		for _, f := range frames {
			if f["type"] == "subscribers" && f["count"] == float64(0) {
				got0 = true
			}
		}
		mu.Unlock()
		if got0 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("no subscribers:0 frame after unsub, got %v", frames)
		case <-time.After(10 * time.Millisecond):
		}
	}
	if h.SubscriberCount() != 0 {
		t.Errorf("after unsub count = %d, want 0", h.SubscriberCount())
	}
}

// TestEventsAfterBothSeqTypes: hub-side (uint64, direct callers) and
// wire-decoded (float64) seqs must both be pullable via EventsAfter.
func TestEventsAfterBothSeqTypes(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	// Direct caller: seq stored as uint64.
	if !h.RegisterEvent("h1", Event{"type": "chunk", "text": "a", "seq": uint64(1)}) {
		t.Fatal("register 1")
	}
	// JSON-decoded style: float64.
	if !h.RegisterEvent("h1", Event{"type": "chunk", "text": "b", "seq": float64(2)}) {
		t.Fatal("register 2")
	}
	// Seq-less event: hub assigns its own (uint64, seq 3).
	if !h.RegisterEvent("h1", Event{"type": "chunk", "text": "c"}) {
		t.Fatal("register 3")
	}

	evs := h.EventsAfter("h1", 1)
	if len(evs) != 2 {
		t.Fatalf("EventsAfter(1) = %d events, want 2: %v", len(evs), evs)
	}
	if evSeq(evs[0]) != 2 || evSeq(evs[1]) != 3 {
		t.Errorf("seqs = %v, %v; want 2, 3", evSeq(evs[0]), evSeq(evs[1]))
	}
	if evSeq(evs[0]) != 2 {
		t.Errorf("first event text = %v", evs[0])
	}
}

// TestRegisterEventNilEvent: a nil event must be rejected, not panic.
func TestRegisterEventNilEvent(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	if h.RegisterEvent("h1", nil) {
		t.Error("nil event should be rejected")
	}
}

// TestRegisterEventDoesNotMutateCallerMap: RegisterEvent must never add
// injected keys (seq/hostId/hostName) to the caller's map — the injected
// copies are what get buffered and broadcast.
func TestRegisterEventDoesNotMutateCallerMap(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	ch, unsub := h.Subscribe()
	defer unsub()

	ev := Event{"type": "chunk", "text": "x"}
	if !h.RegisterEvent("h1", ev) {
		t.Fatal("RegisterEvent failed")
	}
	if _, ok := ev["seq"]; ok {
		t.Error("caller map mutated: seq injected")
	}
	if _, ok := ev["hostId"]; ok {
		t.Error("caller map mutated: hostId injected")
	}
	if _, ok := ev["hostName"]; ok {
		t.Error("caller map mutated: hostName injected")
	}
	// The buffered/broadcast copy must carry the injected tags.
	select {
	case got := <-ch:
		if got["type"] != "chunk" || got["text"] != "x" {
			t.Errorf("broadcast event = %v, want chunk/x", got)
		}
		if got["hostId"] != "h1" || got["hostName"] != "H1" {
			t.Errorf("broadcast event tags = %v/%v", got["hostId"], got["hostName"])
		}
		if _, ok := got["seq"]; !ok {
			t.Error("broadcast event missing hub-assigned seq")
		}
	case <-time.After(time.Second):
		t.Fatal("no event received")
	}
	// Mutating the broadcast copy must not leak into the replay buffer.
	evs := h.EventsAfter("h1", 0)
	if len(evs) != 1 || evs[0]["text"] != "x" {
		t.Fatalf("EventsAfter = %v, want the tagged copy", evs)
	}
}

// TestRegisterEventSeqRegression: a host replaying events with a stale
// (lower) seq must not move the per-host counter backwards — that would
// make the FE misjudge what it already saw — but the event itself must
// still be broadcast and buffered.
func TestRegisterEventSeqRegression(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	if !h.RegisterEvent("h1", Event{"type": "chunk", "text": "fresh", "seq": uint64(100)}) {
		t.Fatal("register 100")
	}
	if got := h.LastSeq("h1"); got != 100 {
		t.Fatalf("LastSeq = %d, want 100", got)
	}

	ch, unsub := h.Subscribe()
	defer unsub()

	// Regressed seq: still relayed, counter must stay at 100.
	if !h.RegisterEvent("h1", Event{"type": "chunk", "text": "stale", "seq": uint64(50)}) {
		t.Fatal("register 50")
	}
	if got := h.LastSeq("h1"); got != 100 {
		t.Errorf("LastSeq = %d, want 100 (counter must not regress)", got)
	}
	select {
	case ev := <-ch:
		if ev["text"] != "stale" {
			t.Errorf("regressed event not relayed as-is: %v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("regressed event should still be broadcast")
	}

	// Equal seq: fine, counter stays put.
	if !h.RegisterEvent("h1", Event{"type": "chunk", "text": "dup", "seq": uint64(100)}) {
		t.Fatal("register 100 again")
	}
	if got := h.LastSeq("h1"); got != 100 {
		t.Errorf("LastSeq = %d, want 100 after equal seq", got)
	}

	// A higher seq still advances.
	if !h.RegisterEvent("h1", Event{"type": "chunk", "text": "next", "seq": uint64(101)}) {
		t.Fatal("register 101")
	}
	if got := h.LastSeq("h1"); got != 101 {
		t.Errorf("LastSeq = %d, want 101", got)
	}
}

// TestSubscribeNotBlockedBySlowHost: subscriber-count notifications are
// written per host in the background, so a slow/half-open host (write
// timeouts of tens of seconds) must not stall subscribe/unsubscribe.
func TestSubscribeNotBlockedBySlowHost(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	release := make(chan struct{})
	_, stop, err := h.ConnectStream("h1", func([]byte) error {
		<-release // simulate a host whose write never completes in time
		return nil
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer stop()
	defer close(release)

	done := make(chan struct{})
	go func() {
		ch, unsub := h.Subscribe()
		defer unsub()
		_ = ch
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Subscribe blocked on a slow host notification write")
	}
}

// TestTrySubscribeCap: TrySubscribe must reject registration beyond the
// cap (resource guard for the open /ws/fe endpoint), free a slot on
// unsubscribe, and treat max=0 as unlimited (Subscribe keeps working).
func TestTrySubscribeCap(t *testing.T) {
	h := NewWithDir(t.TempDir())

	ch1, unsub1, ok := h.TrySubscribe(2)
	if !ok || ch1 == nil {
		t.Fatalf("first subscribe: ok=%v ch=%v", ok, ch1)
	}
	defer unsub1()
	ch2, unsub2, ok := h.TrySubscribe(2)
	if !ok || ch2 == nil {
		t.Fatalf("second subscribe: ok=%v ch=%v", ok, ch2)
	}
	defer unsub2()
	if h.SubscriberCount() != 2 {
		t.Errorf("count = %d, want 2", h.SubscriberCount())
	}

	if ch, unsub, ok := h.TrySubscribe(2); ok {
		unsub()
		t.Fatalf("third subscribe beyond cap must fail (ch=%v)", ch)
	}
	if h.SubscriberCount() != 2 {
		t.Errorf("count after rejected subscribe = %d, want 2", h.SubscriberCount())
	}

	// Unsubscribing frees a slot.
	unsub1()
	if _, _, ok := h.TrySubscribe(2); !ok {
		t.Error("subscribe after unsub must succeed")
	}
	if h.SubscriberCount() != 2 {
		t.Errorf("count after refill = %d, want 2", h.SubscriberCount())
	}

	// max=0 means unlimited.
	if _, unsub, ok := h.TrySubscribe(0); !ok {
		t.Error("TrySubscribe(0) must always succeed")
	} else {
		unsub()
	}
}
