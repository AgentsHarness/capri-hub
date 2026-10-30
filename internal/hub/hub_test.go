package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	old := h.pairingCode
	h.codeExpires = time.Now().Add(-time.Minute)
	h.mu.Unlock()
	// Pair with the expired code value must still fail (does not auto-accept).
	if _, err := h.Pair(old, "h1", "H1"); !errors.Is(err, ErrCodeInvalid) {
		t.Errorf("expired code err = %v, want ErrCodeInvalid", err)
	}
}

// PairingCode() must auto-rotate when the current code is past expiry so
// admins never see a dead code advertised as current.
func TestPairingCodeAutoRotateOnRead(t *testing.T) {
	h := NewWithDir(t.TempDir())
	h.mu.Lock()
	old := h.pairingCode
	h.codeExpires = time.Now().Add(-time.Minute)
	h.mu.Unlock()

	code, exp := h.PairingCode()
	if code == old {
		t.Error("PairingCode must rotate after expiry")
	}
	if !exp.After(time.Now()) {
		t.Error("new code must not be already expired")
	}
	// New code works for Pair.
	if _, err := h.Pair(code, "h1", "H1"); err != nil {
		t.Fatalf("pair with rotated code: %v", err)
	}
}

// After disconnect, gap-pull buffer is kept for EventBufGrace then cleared.
// Reconnect cancels the pending clear.
func TestEventBufGrace(t *testing.T) {
	prev := EventBufGrace
	EventBufGrace = 80 * time.Millisecond
	defer func() { EventBufGrace = prev }()

	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	_, stop, err := h.ConnectStream("h1", func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !hubRaw(h, "h1", Event{"type": "chunk", "seq": uint64(1)}) {
		t.Fatal("register")
	}
	stop()
	// Immediately after disconnect the buffer is still available.
	if n := len(h.EventsAfter("h1", 0)); n != 1 {
		t.Fatalf("evBuf right after disconnect = %d, want 1", n)
	}
	// After grace, cleared.
	time.Sleep(120 * time.Millisecond)
	if n := len(h.EventsAfter("h1", 0)); n != 0 {
		t.Fatalf("evBuf after grace = %d, want 0", n)
	}

	// Reconnect cancels clear: disconnect → re-register buffer → reconnect before grace.
	EventBufGrace = 200 * time.Millisecond
	_, stop2, err := h.ConnectStream("h1", func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !hubRaw(h, "h1", Event{"type": "chunk", "seq": uint64(2)}) {
		t.Fatal("register 2")
	}
	stop2()
	_, stop3, err := h.ConnectStream("h1", func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer stop3()
	time.Sleep(250 * time.Millisecond)
	if n := len(h.EventsAfter("h1", 0)); n != 1 {
		t.Fatalf("evBuf after reconnect within grace = %d, want 1 (clear cancelled)", n)
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

// Re-pair after a process restart must revoke the old token. load() has
// to restore hostState.token (and Pair must revoke by hostId) for this.
func TestRePairAfterRestartRevokesOldToken(t *testing.T) {
	dir := t.TempDir()
	h1 := NewWithDir(dir)
	tok1 := testPair(t, h1, "h1", "H1")

	h2 := NewWithDir(dir) // restart
	code, _ := h2.PairingCode()
	tok2, err := h2.Pair(code, "h1", "H1-new")
	if err != nil {
		t.Fatalf("re-pair: %v", err)
	}
	if _, ok := h2.HostIDForToken(tok1); ok {
		t.Error("old token must be revoked after re-pair post-restart")
	}
	if hid, ok := h2.HostIDForToken(tok2); !ok || hid != "h1" {
		t.Errorf("new token = %q,%v want h1,true", hid, ok)
	}
}

func TestPersistFileMode(t *testing.T) {
	dir := t.TempDir()
	h := NewWithDir(dir)
	_ = testPair(t, h, "h1", "H1")
	fi, err := os.Stat(filepath.Join(dir, "hub.json"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("hub.json mode %o must not be group/other readable", mode)
	}
}

// Concurrent Pair must not race on the shared tokens map during persist
// marshal (go test -race) and must leave a valid hub.json.
func TestConcurrentPairPersist(t *testing.T) {
	dir := t.TempDir()
	h := NewWithDir(dir)
	code, _ := h.PairingCode()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = h.Pair(code, fmt.Sprintf("h%d", i), "H")
		}(i)
	}
	wg.Wait()

	b, err := os.ReadFile(filepath.Join(dir, "hub.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pf persistFile
	if err := json.Unmarshal(b, &pf); err != nil {
		t.Fatalf("invalid hub.json after concurrent pairs: %v", err)
	}
	if len(pf.Hosts) == 0 || len(pf.Tokens) == 0 {
		t.Errorf("empty snapshot: hosts=%d tokens=%d", len(pf.Hosts), len(pf.Tokens))
	}
}

// ConnectStream superseding an existing connection must fail in-flight
// Dispatches immediately (not wait for RelayTimeout).
func TestConnectStreamSupersedeFailsPending(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")

	got := make(chan []byte, 4)
	_, stop1, err := h.ConnectStream("h1", func(p []byte) error {
		got <- append([]byte(nil), p...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := h.Dispatch(context.Background(), "h1", "GET", "/api/status", nil)
		done <- err
	}()
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("no request frame on first connection")
	}

	_, stop2, err := h.ConnectStream("h1", func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer stop2()
	// Stale stop must not mark the new connection offline.
	stop1()

	select {
	case err := <-done:
		var re *RelayError
		if !errors.As(err, &re) || re.Status != 503 {
			t.Errorf("dispatch err = %v, want RelayError 503", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending request not failed after host reconnect")
	}
	if !h.ListHosts()[0].Online {
		t.Error("host should stay online after stale stop")
	}
}

func TestUnpair(t *testing.T) {
	dir := t.TempDir()
	h := NewWithDir(dir)
	tok := testPair(t, h, "h1", "H1")

	// Online with a pending-ish stream: unpair should clear registry.
	_, stop, err := h.ConnectStream("h1", func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

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

func TestMaxHosts(t *testing.T) {
	h := NewWithDir("")
	code, _ := h.PairingCode()
	// Fill to the cap without going through full MaxHosts if huge —
	// temporarily not possible; exercise the limit by filling MaxHosts.
	for i := 0; i < MaxHosts; i++ {
		if _, err := h.Pair(code, fmt.Sprintf("host-%d", i), "H"); err != nil {
			t.Fatalf("pair %d: %v", i, err)
		}
	}
	if _, err := h.Pair(code, "overflow", "H"); !errors.Is(err, ErrHostLimit) {
		t.Errorf("pair beyond cap err = %v, want ErrHostLimit", err)
	}
	// Re-pair of an existing host must still work.
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

// TestSubscribersGenMonotonic guards the ordering stamp that keeps a host
// from acting on a stale subscriber count (see notifyHostsSubscribers): a
// browser refresh delivers count 0 and count 1 microseconds apart from two
// separate goroutines, and applying them out of order silently pauses the
// host's event upload while the page sits there looking connected.
func TestSubscribersGenMonotonic(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")

	var mu sync.Mutex
	var frames [][]byte
	_, stop, err := h.ConnectStream("h1", func(p []byte) error {
		mu.Lock()
		frames = append(frames, append([]byte(nil), p...))
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer stop()

	_, un1 := h.Subscribe()
	_, un2 := h.Subscribe()
	un2()
	un1()

	countSubs := func() int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, f := range frames {
			var m map[string]any
			if json.Unmarshal(f, &m) == nil && m["type"] == "subscribers" {
				n++
			}
		}
		return n
	}
	// Counts change 1→2→1→0, so four notifications are expected. Wait for
	// all of them: stopping early would leave the terminal count=0 frame in
	// flight and make the "highest gen wins" assertion below racy.
	const wantFrames = 4
	deadline := time.Now().Add(5 * time.Second)
	for countSubs() < wantFrames && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	// Frames are written from one goroutine per host, so they genuinely DO
	// arrive out of order — that is the bug `gen` exists for, so this test
	// must not assert write ordering. What must hold is that every frame is
	// stamped, stamps are unique, and the HIGHEST stamp carries the true
	// final count: a host that keeps the highest gen therefore converges to
	// the real state no matter how the frames were interleaved.
	seenGen := map[float64]bool{}
	var maxGen float64
	maxGenCount := -1.0
	for _, f := range frames {
		var m map[string]any
		if json.Unmarshal(f, &m) != nil || m["type"] != "subscribers" {
			continue
		}
		gen, ok := m["gen"].(float64)
		if !ok {
			t.Fatalf("subscribers frame missing gen: %s", f)
		}
		if seenGen[gen] {
			t.Fatalf("duplicate gen %v — stamps must be unique: %s", gen, f)
		}
		seenGen[gen] = true
		count, ok := m["count"].(float64)
		if !ok {
			t.Fatalf("subscribers frame missing count: %s", f)
		}
		if gen > maxGen {
			maxGen, maxGenCount = gen, count
		}
	}
	if len(seenGen) < wantFrames {
		t.Fatalf("expected %d subscribers frames for the 0→1→2→1→0 churn, got %d", wantFrames, len(seenGen))
	}
	if maxGenCount != 0 {
		t.Fatalf("highest gen (%v) carries count=%v, want 0 — a gen-gating host "+
			"would converge to the wrong subscriber state", maxGen, maxGenCount)
	}
	// SubscribersState (the ping re-assert path) shares the counter, so a
	// re-assert can never be mistaken for a stale frame.
	c, g1 := h.SubscribersState()
	if c != 0 {
		t.Errorf("count = %d, want 0 after all unsubscribes", c)
	}
	_, g2 := h.SubscribersState()
	if float64(g1) <= maxGen || g2 <= g1 {
		t.Errorf("SubscribersState gens must continue the sequence: %d, %d after %v", g1, g2, maxGen)
	}
}

// TestSubscribersNoRedundantNotify: an unchanged count is not re-broadcast
// (multi-tab churn would otherwise be a per-host write storm).
func TestSubscribersNoRedundantNotify(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	var mu sync.Mutex
	subsFrames := 0
	_, stop, err := h.ConnectStream("h1", func(p []byte) error {
		var m map[string]any
		if json.Unmarshal(p, &m) == nil && m["type"] == "subscribers" {
			mu.Lock()
			subsFrames++
			mu.Unlock()
		}
		return nil
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer stop()
	// Counts go 1,2,1,0 — four genuine changes, so at most four frames.
	_, un1 := h.Subscribe()
	_, un2 := h.Subscribe()
	un2()
	un1()
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	got := subsFrames
	mu.Unlock()
	if got > 4 {
		t.Errorf("got %d subscribers frames for 4 count changes — redundant notifies", got)
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
		HostID string          `json:"hostId"`
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
		resp, err := h.Dispatch(context.Background(), "h1", "POST", "/api/prompt", body)
		done <- result{resp, err}
	}()

	f := <-got
	if f.ReqID == "" || f.HostID != "h1" || f.Method != "POST" || f.Path != "/api/prompt" {
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
	_, err := h.Dispatch(context.Background(), "h1", "POST", "/api/prompt", nil)
	var re *RelayError
	if !errors.As(err, &re) || re.Status != 503 {
		t.Errorf("offline dispatch err = %v, want RelayError 503", err)
	}
	if _, err := h.Dispatch(context.Background(), "nope", "POST", "/api/prompt", nil); !errors.As(err, &re) || re.Status != 404 {
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
		resp, err := h.Dispatch(context.Background(), "h1", "GET", "/api/status", nil)
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

// A host_status frame is a control frame: it updates Ready without becoming
// an event. A host_status nested inside an events frame is no longer a
// supported shape.
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
	hubRaw(h, "h1", Event{"type": "chunk", "text": "x", "seq": uint64(1), "sessionId": "s1"})
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
	// Subscribe notifies hosts with count=1. The two host notifications
	// (subscribers + viewing) are written by independent goroutines, so scan
	// every frame rather than assuming which one landed last.
	deadline := time.After(time.Second)
	for {
		mu.Lock()
		var got1 bool
		for _, f := range frames {
			if f["type"] == "subscribers" && f["count"] == float64(1) {
				got1 = true
			}
		}
		mu.Unlock()
		if got1 {
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

// TestEventsAfterSeqTypes: a host seq may arrive as uint64 (in-process) or
// float64 (after the JSON frame is decoded); both must be pullable.
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
	if !h.RegisterRawEvents("h1", []json.RawMessage{[]byte("null")}) {
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
	if !h.RegisterRawEvents("h1", []json.RawMessage{body}) {
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
func TestRegisterEventSeqRegression(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	if !hubRaw(h, "h1", Event{"type": "chunk", "text": "fresh", "seq": uint64(100)}) {
		t.Fatal("register 100")
	}
	if got := h.LastSeq("h1"); got != 100 {
		t.Fatalf("LastSeq = %d, want 100", got)
	}
	if n := len(h.EventsAfter("h1", 0)); n != 1 {
		t.Fatalf("evBuf len = %d, want 1 after first event", n)
	}

	ch, unsub := h.Subscribe()
	defer unsub()
	// Fan-out is asynchronous (per-host queue, see hostState.fanout): the
	// seed event registered before this subscription can still be in flight.
	// Drain it first, then assert the stale/duplicate seqs stay silent.
	drainEvents(ch, 100*time.Millisecond)

	// Regressed seq: accepted (LastSeen) but no fan-out / no buffer append.
	if !hubRaw(h, "h1", Event{"type": "chunk", "text": "stale", "seq": uint64(50)}) {
		t.Fatal("register 50")
	}
	if got := h.LastSeq("h1"); got != 100 {
		t.Errorf("LastSeq = %d, want 100 (counter must not regress)", got)
	}
	select {
	case ev := <-ch:
		t.Fatalf("regressed seq must not fan out, got %v", ev)
	case <-time.After(50 * time.Millisecond):
		// expected: no broadcast
	}
	if n := len(h.EventsAfter("h1", 0)); n != 1 {
		t.Errorf("evBuf len = %d after stale, want 1 (no re-append)", n)
	}

	// Equal seq (duplicate): same — skip fan-out, counter stays put.
	if !hubRaw(h, "h1", Event{"type": "chunk", "text": "dup", "seq": uint64(100)}) {
		t.Fatal("register 100 again")
	}
	if got := h.LastSeq("h1"); got != 100 {
		t.Errorf("LastSeq = %d, want 100 after equal seq", got)
	}
	select {
	case ev := <-ch:
		t.Fatalf("duplicate seq must not fan out, got %v", ev)
	case <-time.After(50 * time.Millisecond):
		// expected
	}
	if n := len(h.EventsAfter("h1", 0)); n != 1 {
		t.Errorf("evBuf len = %d after dup, want 1", n)
	}

	// A higher seq still advances and fans out.
	if !hubRaw(h, "h1", Event{"type": "chunk", "text": "next", "seq": uint64(101)}) {
		t.Fatal("register 101")
	}
	if got := h.LastSeq("h1"); got != 101 {
		t.Errorf("LastSeq = %d, want 101", got)
	}
	select {
	case ev := <-ch:
		if ev["seq"] != float64(101) {
			t.Errorf("fresh event = %v, want seq 101", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("seq 101 should be broadcast")
	}
	if n := len(h.EventsAfter("h1", 0)); n != 2 {
		t.Errorf("evBuf len = %d after 101, want 2", n)
	}
}

// TestHostStatusControlFrame: control-plane host_status updates Ready +
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
		t.Fatal("host_status ready=true failed")
	}
	if hosts := h.ListHosts(); len(hosts) != 1 || !hosts[0].Ready {
		t.Errorf("ready not set: %+v", hosts)
	}
	if got := h.LastSeq("h1"); got != 7 {
		t.Errorf("LastSeq = %d after host_status, want 7 (must not advance)", got)
	}
	if n := len(h.EventsAfter("h1", 0)); n != 1 {
		t.Errorf("evBuf len = %d after host_status, want 1", n)
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
		t.Fatal("host_status ready=true (noop) failed")
	}
	select {
	case ev := <-ch:
		t.Fatalf("ready unchanged must not rebroadcast, got %v", ev)
	case <-time.After(50 * time.Millisecond):
		// expected
	}

	// Flip false → hosts_changed again.
	if !setReady(false) {
		t.Fatal("host_status ready=false failed")
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
		t.Error("host_status for unknown host should fail")
	}
}

// TestUpdateHostStatus: control-plane host_status carries the live
// registry fields (ready/busy/booting/pendingCount); hosts_changed fires
// on ANY flip, nil fields leave the current value untouched (older hosts
// send only ready), and identical frames stay silent.
func TestUpdateHostStatus(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	boolPtr := func(b bool) *bool { return &b }
	intPtr := func(n int) *int { return &n }

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

	if h.UpdateHostStatus("nope", HostStatusPatch{Ready: boolPtr(true)}) {
		t.Error("UpdateHostStatus for unknown host should fail")
	}
}

// TestPairPortAndPersist: optional Pair port is stored and survives restart.
func TestPairPortAndPersist(t *testing.T) {
	dir := t.TempDir()
	h1 := NewWithDir(dir)
	code, _ := h1.PairingCode()
	if _, err := h1.Pair(code, "h1", "H1", 8765); err != nil {
		t.Fatalf("Pair: %v", err)
	}
	if hosts := h1.ListHosts(); len(hosts) != 1 || hosts[0].Port != 8765 {
		t.Fatalf("after Pair port = %+v, want 8765", hosts)
	}
	h2 := NewWithDir(dir)
	if hosts := h2.ListHosts(); len(hosts) != 1 || hosts[0].Port != 8765 {
		t.Fatalf("after restart port = %+v, want 8765", hosts)
	}
}

// TestResetHostSeq: host process restart clears LastSeq + gap-pull buffer
// so new low seqs fan out instead of being skipped as stale.
func TestResetHostSeq(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	if !hubRaw(h, "h1", Event{"type": "chunk", "text": "old", "seq": uint64(100)}) {
		t.Fatal("register seed")
	}
	if got := h.LastSeq("h1"); got != 100 {
		t.Fatalf("LastSeq = %d, want 100", got)
	}
	if n := len(h.EventsAfter("h1", 0)); n != 1 {
		t.Fatalf("evBuf len = %d, want 1", n)
	}

	ch, unsub := h.Subscribe()
	defer unsub()
	// Asynchronous fan-out: drain the pre-subscription seed ("old") before
	// asserting that the post-reset seq 1 is the one that fans out.
	drainEvents(ch, 100*time.Millisecond)

	if !h.ResetHostSeq("h1") {
		t.Fatal("ResetHostSeq failed")
	}
	if got := h.LastSeq("h1"); got != 0 {
		t.Errorf("LastSeq after reset = %d, want 0", got)
	}
	if n := len(h.EventsAfter("h1", 0)); n != 0 {
		t.Errorf("evBuf after reset = %d, want 0", n)
	}

	// New process seq 1 must fan out (not skipped as s <= 100).
	if !hubRaw(h, "h1", Event{"type": "chunk", "text": "new", "seq": uint64(1)}) {
		t.Fatal("register seq 1 after reset")
	}
	select {
	case ev := <-ch:
		if ev["type"] != "chunk" {
			t.Errorf("fan-out = %v, want type=chunk", ev)
		}
		if s := evSeq(ev); s != 1 {
			t.Errorf("seq = %d, want 1", s)
		}
	case <-time.After(time.Second):
		t.Fatal("seq 1 after reset was not broadcast")
	}
	if got := h.LastSeq("h1"); got != 1 {
		t.Errorf("LastSeq = %d, want 1", got)
	}

	if h.ResetHostSeq("nope") {
		t.Error("ResetHostSeq for unknown host should fail")
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

// ── browser prefs (pins / todos) ──────────────────────────────────────

func TestPrefsRoundtripAndPersist(t *testing.T) {
	dir := t.TempDir()
	h := NewWithDir(dir)
	doc := BrowserPrefs{Entries: PrefsEntries{
		"ws:/home/u/a":          {V: "1", At: 1, Site: "A"},
		"ws:/home/u/b":          {V: "1", At: 1, Site: "A"},
		"se:s1":                 {V: "1", At: 1, Site: "A"},
		"todo:s1":               {V: "todo", At: 1, Site: "A"},
		"todo:s2":               {V: "completed", At: 1, Site: "A"},
		"fe:collapseToolGroups": {V: "false", At: 1, Site: "A"},
	}}
	if _, err := h.SetPrefs(doc); err != nil {
		t.Fatalf("SetPrefs: %v", err)
	}
	got, _ := h.Prefs()
	if len(got.PinnedWorkspaces) != 2 || got.PinnedSessions[0] != "s1" || got.Todos["s2"] != "completed" {
		t.Errorf("Prefs = %+v, want the stored doc", got)
	}
	if got.FePrefs["collapseToolGroups"] != false {
		t.Errorf("Prefs.FePrefs = %+v, want collapseToolGroups=false", got.FePrefs)
	}
	// Returned docs must be deep copies: mutating one cannot touch the store.
	got.PinnedWorkspaces[0] = "MUTATED"
	got.Todos["s1"] = "completed"
	got.FePrefs["collapseToolGroups"] = true
	again, _ := h.Prefs()
	if again.PinnedWorkspaces[0] != "/home/u/a" || again.Todos["s1"] != "todo" ||
		again.FePrefs["collapseToolGroups"] != false {
		t.Errorf("Prefs is not a deep copy: %+v", again)
	}
	// A fresh Hub on the same dir reloads the doc from prefs.json.
	h2 := NewWithDir(dir)
	reloaded, _ := h2.Prefs()
	if reloaded.PinnedWorkspaces[0] != "/home/u/a" || reloaded.Todos["s2"] != "completed" ||
		reloaded.FePrefs["collapseToolGroups"] != false {
		t.Errorf("reloaded Prefs = %+v, want the persisted doc", reloaded)
	}
	// A tombstone removes the item for every reader.
	if _, err := h.SetPrefs(docWith(PrefsEntries{"todo:s2": seDelete("s2", 2, "A")})); err != nil {
		t.Fatalf("SetPrefs tombstone: %v", err)
	}
	got, _ = h.Prefs()
	if _, ok := got.Todos["s2"]; ok {
		t.Errorf("Prefs after tombstone = %+v, want s2's todo gone", got.Todos)
	}
	if got.PinnedSessions[0] != "s1" {
		t.Errorf("unrelated entry moved: %+v", got.PinnedSessions)
	}
}

func TestPrefsEmptyDoc(t *testing.T) {
	h := NewWithDir(t.TempDir())
	p, version := h.Prefs()
	if p.PinnedWorkspaces == nil || p.PinnedSessions == nil || p.Todos == nil {
		t.Errorf("empty doc must have non-nil containers: %+v", p)
	}
	if version != 0 {
		t.Errorf("fresh hub version = %d, want 0", version)
	}
}

// TestPrefsVersion: every accepted write bumps the version and the version
// survives a hub restart via prefs.json.
func TestPrefsVersion(t *testing.T) {
	dir := t.TempDir()
	h := NewWithDir(dir)

	v1, err := h.SetPrefs(docWith(PrefsEntries{"se:s1": sePin("s1", 1, "A")}))
	if err != nil || v1 != 1 {
		t.Fatalf("write: v=%d err=%v, want v=1 nil", v1, err)
	}
	v2, err := h.SetPrefs(docWith(PrefsEntries{"se:s2": sePin("s2", 2, "A")}))
	if err != nil || v2 != 2 {
		t.Fatalf("second write: v=%d err=%v, want v=2 nil", v2, err)
	}
	doc, v := h.Prefs()
	if v != v2 || len(doc.PinnedSessions) != 2 {
		t.Errorf("doc=%+v v=%d, want both pins at v=%d", doc, v, v2)
	}

	// A subscriber sees prefs_changed carrying the new version.
	ch, unsub, ok := h.TrySubscribe(0)
	if !ok {
		t.Fatalf("TrySubscribe failed")
	}
	defer unsub()
	if _, err := h.SetPrefs(docWith(PrefsEntries{"se:s3": sePin("s3", 3, "A")})); err != nil {
		t.Fatalf("broadcast write: %v", err)
	}
	select {
	case ev := <-ch:
		params, _ := ev["params"].(map[string]any)
		if ver, _ := params["version"].(uint64); ver != v+1 {
			t.Errorf("broadcast version = %v, want %d", params["version"], v+1)
		}
	case <-time.After(time.Second):
		t.Fatalf("no prefs_changed broadcast received")
	}

	// Version persists with the doc: a fresh hub reloads both.
	h2 := NewWithDir(dir)
	if _, vr := h2.Prefs(); vr != v+1 {
		t.Errorf("reloaded version = %d, want %d", vr, v+1)
	}
}

// SetPrefs must broadcast prefs_changed to browser subscribers so other
// browsers apply the edit live (one-end sync).
func TestPrefsBroadcast(t *testing.T) {
	h := NewWithDir("") // no disk, still broadcasts
	ch, unsub := h.Subscribe()
	defer unsub()
	doc := BrowserPrefs{Entries: PrefsEntries{
		"se:s1":   {V: "1", At: 1, Site: "A"},
		"todo:s1": {V: "todo", At: 1, Site: "A"},
	}}
	if _, err := h.SetPrefs(doc); err != nil {
		t.Fatalf("SetPrefs: %v", err)
	}
	select {
	case ev := <-ch:
		if ev["type"] != "prefs_changed" {
			t.Errorf("broadcast type = %v, want prefs_changed", ev["type"])
		}
		params, _ := ev["params"].(map[string]any)
		prefs, ok := params["prefs"].(BrowserPrefs)
		if !ok {
			t.Fatalf("broadcast params.prefs = %T, want BrowserPrefs", params["prefs"])
		}
		if len(prefs.PinnedSessions) != 1 || prefs.PinnedSessions[0] != "s1" || prefs.Todos["s1"] != "todo" {
			t.Errorf("broadcast prefs = %+v, want the stored doc", prefs)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no prefs_changed broadcast received")
	}
}

// TestIsCurrentConn: IsCurrentConn must track the live stream — false for
// unknown hosts, disconnected conns, and superseded conns; a stale stop
// must not revive an old conn.
func TestIsCurrentConn(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")

	// Unknown host / no live conn.
	if h.IsCurrentConn("nope", &streamConn{}) {
		t.Error("unknown host must not have a current conn")
	}
	if h.IsCurrentConn("h1", &streamConn{}) {
		t.Error("host with no live conn must not have a current conn")
	}
	conn1, stop1, err := h.ConnectStream("h1", func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !h.IsCurrentConn("h1", conn1) {
		t.Error("live conn must be current")
	}
	if h.IsCurrentConn("h1", &streamConn{}) {
		t.Error("unregistered conn must not be current")
	}

	stop1()
	if h.IsCurrentConn("h1", conn1) {
		t.Error("disconnected conn must not be current")
	}

	conn2, stop2, err := h.ConnectStream("h1", func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer stop2()
	if !h.IsCurrentConn("h1", conn2) {
		t.Error("new conn must be current after supersede")
	}
	if h.IsCurrentConn("h1", conn1) {
		t.Error("superseded conn must not be current")
	}
	// Stale stop must not revive conn1 as current.
	stop1()
	if !h.IsCurrentConn("h1", conn2) {
		t.Error("stale stop must not affect the current conn")
	}
}

// TestDispatchAbandonedByBrowser: when the browser's request context is
// cancelled the relay must stop waiting AND free the pending slot. Before
// this, an abandoned request (closed tab, mobile network drop) pinned a
// goroutine, a pending entry and a RelayTimeout-long (45 min) timer, so a
// client retrying prompts steadily accumulated them.
func TestDispatchAbandonedByBrowser(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	// A host that accepts the request and never answers.
	_, stop, err := h.ConnectStream("h1", func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer stop()

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

// TestRegisterRawEvents: the raw (pre-encoded) path ingests event bodies
// without decoding them into maps — host seqs preserved / stale skipped /
// seq-less rejected, hostId/hostName tags appended, and the broadcast event
// serializing via MarshalEvent to the spliced original bytes.
func TestRegisterRawEvents(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	ch, unsub := h.Subscribe()
	defer unsub()

	raws := []json.RawMessage{
		json.RawMessage(`{"type":"chunk","text":"a","seq":10}`),
		json.RawMessage(`{"type":"chunk","text":"b","seq":11}`),
		json.RawMessage(`{"type":"chunk","text":"stale","seq":5}`), // skipped
		json.RawMessage(`{"type":"chunk","text":"no-seq"}`),        // rejected
	}
	if !h.RegisterRawEvents("h1", raws) {
		t.Fatal("RegisterRawEvents failed for paired host")
	}
	if got := h.LastSeq("h1"); got != 11 {
		t.Fatalf("LastSeq = %d, want 11", got)
	}
	// Two fan-outs (stale and seq-less skipped).
	var wires []map[string]any
	for len(wires) < 2 {
		select {
		case ev := <-ch:
			if ev["type"] != "chunk" {
				continue // hosts_changed noise
			}
			wire, err := MarshalEvent(ev)
			if err != nil {
				t.Fatalf("MarshalEvent: %v", err)
			}
			var m map[string]any
			if json.Unmarshal(wire, &m) != nil {
				t.Fatalf("spliced wire is not valid JSON: %s", wire)
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
	// Stale event not buffered.
	if evs := h.EventsAfter("h1", 0); len(evs) != 2 {
		t.Errorf("EventsAfter = %d events, want 2", len(evs))
	}
	// Non-object entries are skipped without consuming a seq.
	h.RegisterRawEvents("h1", []json.RawMessage{json.RawMessage(`null`)})
	if got := h.LastSeq("h1"); got != 11 {
		t.Errorf("LastSeq after null entry = %d, want 11", got)
	}
	if h.RegisterRawEvents("nope", nil) {
		t.Error("unknown host must return false")
	}
}

// TestRegisterRawEventsHostStatusIsNotAnEvent: host_status inside an events
// frame is no longer a supported shape. It is just an event body, so it must
// not flip the registry's Ready flag (the control frame does that).
func TestRegisterRawEventsHostStatusIsNotAnEvent(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	h.RegisterRawEvents("h1", []json.RawMessage{json.RawMessage(`{"type":"host_status","ready":true,"seq":1}`)})
	if hosts := h.ListHosts(); len(hosts) != 1 || hosts[0].Ready {
		t.Errorf("ready flipped by an events-frame host_status: %+v", hosts)
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
	h.RegisterRawEvents("h1", raws)

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

// TestSubscriberHostFilter: the /ws/fe host filter is the whole point of
// 分流 — a page watching h1 must not receive one byte of h2's stream (it
// used to receive everything and drop it client-side, which still cost the
// hub→browser bandwidth and made h2's seq/resync land on h1's watermark).
// Hub-level frames (no hostId) stay for everyone: the registry and prefs
// are per-hub, not per-host.
func TestSubscriberHostFilter(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	testPair(t, h, "h2", "H2")

	scopedCh, scopedUnsub, ok := h.TrySubscribeHost(0, "h1")
	if !ok {
		t.Fatal("TrySubscribeHost refused")
	}
	defer scopedUnsub()
	allCh, allUnsub := h.Subscribe()
	defer allUnsub()

	if !hubRaw(h, "h1", Event{"seq": uint64(1), "type": "chunk", "text": "a"}) {
		t.Fatal("register h1")
	}
	if !hubRaw(h, "h2", Event{"seq": uint64(1), "type": "chunk", "text": "b"}) {
		t.Fatal("register h2")
	}
	h.Broadcast(hostsChanged())

	scoped := drainEvents(scopedCh, 200*time.Millisecond)
	for _, ev := range scoped {
		if host, _ := ev["hostId"].(string); host == "h2" {
			t.Fatalf("h2 event leaked into the h1-filtered subscriber: %v", eventTypes(scoped))
		}
	}
	if !containsType(eventTypes(scoped), "chunk@h1") {
		t.Errorf("filtered subscriber missed its own host: %v", eventTypes(scoped))
	}
	if !containsType(eventTypes(scoped), "hosts_changed") {
		t.Errorf("filtered subscriber missed hub-level hosts_changed: %v", eventTypes(scoped))
	}

	all := drainEvents(allCh, 200*time.Millisecond)
	types := eventTypes(all)
	if !containsType(types, "chunk@h1") || !containsType(types, "chunk@h2") {
		t.Errorf("unfiltered subscriber must still get every host: %v", types)
	}

	// The per-host audience drives the uplink pause, not the raw count.
	if n := h.SubscriberCountFor("h1"); n != 2 {
		t.Errorf("SubscriberCountFor(h1) = %d, want 2 (filtered + watch-all)", n)
	}
	if n := h.SubscriberCountFor("h2"); n != 1 {
		t.Errorf("SubscriberCountFor(h2) = %d, want 1 (watch-all only)", n)
	}
	if n := h.SubscriberCount(); n != 2 {
		t.Errorf("SubscriberCount = %d, want 2 live clients", n)
	}

	// Retargeting mid-session (the page switched hosts without reconnecting).
	if !h.SetSubscriberHost(scopedCh, "h2") {
		t.Fatal("SetSubscriberHost rejected a live channel")
	}
	if !hubRaw(h, "h1", Event{"seq": uint64(2), "type": "chunk", "text": "c"}) {
		t.Fatal("register h1 c")
	}
	if !hubRaw(h, "h2", Event{"seq": uint64(2), "type": "chunk", "text": "d"}) {
		t.Fatal("register h2 d")
	}
	after := eventTypes(drainEvents(scopedCh, 200*time.Millisecond))
	if !containsType(after, "chunk@h2") || containsType(after, "chunk@h1") {
		t.Errorf("after retarget to h2 = %v, want h2 only", after)
	}
	if n := h.SubscriberCountFor("h1"); n != 1 {
		t.Errorf("SubscriberCountFor(h1) after retarget = %d, want 1", n)
	}
	if n := h.SubscriberCountFor("h2"); n != 2 {
		t.Errorf("SubscriberCountFor(h2) after retarget = %d, want 2", n)
	}

	// "" restores watch-all (old FE behaviour on the same connection).
	if !h.SetSubscriberHost(scopedCh, "") {
		t.Fatal("SetSubscriberHost rejected clearing the filter")
	}
	if !hubRaw(h, "h1", Event{"seq": uint64(3), "type": "chunk", "text": "e"}) {
		t.Fatal("register h1 e")
	}
	if !containsType(eventTypes(drainEvents(scopedCh, 200*time.Millisecond)), "chunk@h1") {
		t.Error("clearing the filter must restore the every-host stream")
	}
	if h.SetSubscriberHost(make(chan Event), "h1") {
		t.Error("SetSubscriberHost accepted a foreign channel")
	}
}

func containsType(types []string, want string) bool {
	for _, t := range types {
		if t == want {
			return true
		}
	}
	return false
}

// TestSubscriberCountsNotifyPerHost: the `subscribers` frame decides whether
// a host uploads bridge events at all. With per-subscriber filtering the
// frame must carry the PER-HOST audience, otherwise a page watching h1
// keeps h2 uploading a stream nobody reads — and the switch to h2 finds the
// hub with a stale buffer.
func TestSubscriberCountsNotifyPerHost(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	testPair(t, h, "h2", "H2")

	var mu sync.Mutex
	last := map[string]float64{}
	for _, id := range []string{"h1", "h2"} {
		hostID := id
		_, stop, err := h.ConnectStream(hostID, func(p []byte) error {
			var m map[string]any
			if json.Unmarshal(p, &m) != nil || m["type"] != "subscribers" {
				return nil
			}
			mu.Lock()
			if c, ok := m["count"].(float64); ok {
				if prev, seen := last[hostID]; !seen || c >= prev || m["gen"].(float64) > 0 {
					last[hostID] = c
				}
			}
			mu.Unlock()
			return nil
		})
		if err != nil {
			t.Fatalf("connect %s: %v", hostID, err)
		}
		defer stop()
	}
	waitFor := func(want map[string]float64) map[string]float64 {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			got := map[string]float64{}
			for k, v := range last {
				got[k] = v
			}
			mu.Unlock()
			ok := true
			for k, v := range want {
				if got[k] != v {
					ok = false
				}
			}
			if ok {
				return got
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("subscriber counts never became %v (got %v)", want, last)
		return nil
	}

	ch, unsub, ok := h.TrySubscribeHost(0, "h1")
	if !ok {
		t.Fatal("TrySubscribeHost refused")
	}
	defer unsub()
	// h1 has a viewer; h2 has none and must pause its uplink.
	waitFor(map[string]float64{"h1": 1, "h2": 0})

	if !h.SetSubscriberHost(ch, "h2") {
		t.Fatal("SetSubscriberHost rejected a live channel")
	}
	waitFor(map[string]float64{"h1": 0, "h2": 1})

	unsub()
	waitFor(map[string]float64{"h1": 0, "h2": 0})
}

// TestResyncCarriesHostId: seq counters are per-host, so an untagged resync
// tripped by h2's drop storm was applied to whichever host the FE happened
// to watch — jumping h1's watermark to h2's sequence silently dropped every
// h1 event below it (the page looked live but frozen).
func TestResyncCarriesHostId(t *testing.T) {
	ev := Event{"type": "chunk", "seq": uint64(9000), "hostId": "h2"}
	rf := resyncFrame(ev)
	if rf["type"] != "resync" {
		t.Errorf("type = %v, want resync", rf["type"])
	}
	if got, _ := rf["hostId"].(string); got != "h2" {
		t.Errorf("resync hostId = %q, want h2 — the FE cannot attribute it otherwise", got)
	}
	if got, _ := rf["fromSeq"].(uint64); got != 9000 {
		t.Errorf("resync fromSeq = %v, want 9000", rf["fromSeq"])
	}
	// Hub-level events carry no host: their resync stays untagged rather
	// than falsely attributed to some host.
	hostless := resyncFrame(Event{"seq": uint64(1), "type": "hosts_changed"})
	if _, has := hostless["hostId"]; has {
		t.Errorf("hostless resync must not carry a hostId: %v", hostless)
	}
	// The filtered subscriber only ever sees its own host's drops, so the
	// frame it receives can only be about that host.
	s := &feSubscriber{ch: make(chan Event, 1)}
	s.host.Store("h1")
	if s.watches("h2") {
		t.Error("h1-filtered subscriber must not watch h2")
	}
}

// TestUnwatchedHostStatusStillVisible: the host list's live status (online /
// ready / busy / pendingCount) comes from the host_status CONTROL plane and
// the hub-level hosts_changed frame, never from the data-plane event stream.
// A host nobody watches pauses its event upload, and it must still be
// correct in every browser's list — otherwise 分流 would silently freeze the
// picker on stale states for exactly the hosts the user is about to switch
// to.
func TestUnwatchedHostStatusStillVisible(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	testPair(t, h, "h2", "H2")

	ch, unsub, ok := h.TrySubscribeHost(0, "h1")
	if !ok {
		t.Fatal("TrySubscribeHost refused")
	}
	defer unsub()
	// Drain the frames emitted while pairing/hooking up so the assertions
	// below only see what the status changes produce.
	drainEvents(ch, 100*time.Millisecond)

	busy, pending := true, 3
	if !h.UpdateHostStatus("h2", HostStatusPatch{Busy: &busy, PendingCount: &pending}) {
		t.Fatal("UpdateHostStatus h2")
	}
	ready := true
	if !h.UpdateHostStatus("h2", HostStatusPatch{Ready: &ready}) {
		t.Fatal("host_status ready h2")
	}

	evs := drainEvents(ch, 200*time.Millisecond)
	nChanged := 0
	for _, ev := range evs {
		if ev["type"] == "hosts_changed" {
			nChanged++
		}
		if host, _ := ev["hostId"].(string); host == "h2" {
			t.Fatalf("h2 data-plane event reached the h1 page: %v", ev)
		}
	}
	if nChanged == 0 {
		t.Fatal("no hosts_changed for the h1-filtered subscriber — the host list " +
			"would go stale for every host the page is not watching")
	}

	var h2 *HostInfo
	hosts := h.ListHosts()
	for i := range hosts {
		if hosts[i].HostID == "h2" {
			h2 = &hosts[i]
		}
	}
	if h2 == nil {
		t.Fatal("h2 missing from the registry")
	}
	if !h2.Busy || h2.PendingCount != 3 || !h2.Ready {
		t.Errorf("unwatched h2 registry = busy:%v pending:%v ready:%v, want true/3/true",
			h2.Busy, h2.PendingCount, h2.Ready)
	}
}

// hubRaw ingests one event the way the host wire does: as raw JSON through
// RegisterRawEvents, which is the only ingest path production uses.
func hubRaw(h *Hub, hostID string, ev Event) bool {
	b, err := json.Marshal(ev)
	if err != nil {
		return false
	}
	return h.RegisterRawEvents(hostID, []json.RawMessage{b})
}
