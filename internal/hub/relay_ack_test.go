package hub

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/wire"
)

// respondFrame builds one wire respond frame for the ordered relay path.
func respondFrame(reqID string, seq uint64, status int, chunk []byte, more bool) wire.Frame {
	f := wire.Frame{
		V: wire.ProtocolVersion, Type: wire.TypeRespond,
		ReqID: reqID, ChunkSeq: seq, More: more,
	}
	f.SetRespondStatus(status)
	if chunk != nil {
		f.Chunk = base64.StdEncoding.EncodeToString(chunk)
		f.Encoding = "base64"
	}
	return f
}

// shortInteractiveAck shrinks the browser-facing ack window for one test.
func shortInteractiveAck(t *testing.T, d time.Duration) {
	t.Helper()
	prev := interactiveAckWindow
	interactiveAckWindow = d
	t.Cleanup(func() { interactiveAckWindow = prev })
}

func findRelayAck(acks []wire.RelayAck, reqID string) (wire.RelayAck, bool) {
	for _, a := range acks {
		if a.ReqID == reqID {
			return a, true
		}
	}
	return wire.RelayAck{}, false
}

// Chunks apply strictly in ChunkSeq order: a gap is parked, a duplicate is
// ignored, and filling the gap drains the parked run in order. The ack table
// tracks the contiguous prefix and turns into a done tombstone on the final
// chunk.
func TestAcceptRespondOrdersChunks(t *testing.T) {
	h := NewWithDir("")
	pr := addChunkPending(h, "h1", "r1")

	part1 := []byte(`{"ok":true,"text":"`)
	part2 := []byte(`fi`)
	part3 := []byte(`n"}`)
	missing := []byte(`x`)

	// Chunk 1 applies and advances the ack.
	if known, notify := h.acceptRespond("h1", respondFrame("r1", 1, 207, part1, true)); !known || !notify {
		t.Fatalf("chunk 1: known=%v notify=%v, want true/true", known, notify)
	}
	// Duplicate of 1: known but no progress.
	if known, notify := h.acceptRespond("h1", respondFrame("r1", 1, 207, missing, true)); !known || notify {
		t.Fatalf("duplicate chunk 1: known=%v notify=%v, want true/false", known, notify)
	}
	// Chunk 3 parks: 2 is missing.
	if known, notify := h.acceptRespond("h1", respondFrame("r1", 3, 207, part3, false)); !known || notify {
		t.Fatalf("parked chunk 3: known=%v notify=%v, want true/false", known, notify)
	}
	acks := h.relayAcks("h1")
	if a, ok := findRelayAck(acks, "r1"); !ok || a.Chunk != 1 || a.Done || a.Abort {
		t.Fatalf("ack after parking = %+v (found %v), want pending chunk 1", a, ok)
	}

	// Chunk 2 fills the gap and drains chunk 3, resolving the request.
	if known, notify := h.acceptRespond("h1", respondFrame("r1", 2, 207, part2, true)); !known || !notify {
		t.Fatalf("chunk 2: known=%v notify=%v, want true/true", known, notify)
	}
	select {
	case r := <-pr.resp:
		want := string(part1) + string(part2) + string(part3)
		if r.Status != 207 || string(r.Body) != want {
			t.Fatalf("assembled response = %d %q, want 207 %q", r.Status, r.Body, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("drained chunk 3 did not resolve the request")
	}

	h.mu.Lock()
	_, still := h.pending["h1"]["r1"]
	h.mu.Unlock()
	if still {
		t.Fatal("pending entry survived the final chunk")
	}
	if a, ok := findRelayAck(h.relayAcks("h1"), "r1"); !ok || !a.Done || a.Chunk != 3 || a.Abort {
		t.Fatalf("done tombstone = %+v (found %v), want chunk 3 done", a, ok)
	}

	// A late chunk for the resolved request never downgrades the done
	// tombstone to abort.
	base := h.Stats().LateRelayChunks
	if known, _ := h.acceptRespond("h1", respondFrame("r1", 4, 207, []byte("late"), false)); known {
		t.Fatal("late chunk for a resolved request reported a pending entry")
	}
	if got := h.Stats().LateRelayChunks; got != base+1 {
		t.Fatalf("LateRelayChunks = %d, want %d", got, base+1)
	}
	if a, _ := findRelayAck(h.relayAcks("h1"), "r1"); !a.Done || a.Abort {
		t.Fatalf("late chunk changed the terminal state: %+v", a)
	}
}

// An out-of-order burst beyond the host's parked bounds fails only that
// request: 502 to its caller, abort for the host, other requests untouched.
func TestAcceptRespondParkedOverflowFailsOneRequest(t *testing.T) {
	prevChunks, prevBytes := maxParkedRelayChunksPerHost, maxParkedRelayBytesPerHost
	maxParkedRelayChunksPerHost, maxParkedRelayBytesPerHost = 1, 1<<20
	t.Cleanup(func() {
		maxParkedRelayChunksPerHost, maxParkedRelayBytesPerHost = prevChunks, prevBytes
	})

	h := NewWithDir("")
	bad := addChunkPending(h, "h1", "bad")
	other := addChunkPending(h, "h1", "other")

	// Chunk 2 parks; chunk 3 exceeds the one-chunk bound.
	if known, _ := h.acceptRespond("h1", respondFrame("bad", 2, 200, []byte("x"), true)); !known {
		t.Fatal("first parked chunk rejected")
	}
	if known, _ := h.acceptRespond("h1", respondFrame("bad", 3, 200, []byte("y"), true)); !known {
		t.Fatal("over-limit chunk reported an unknown request")
	}
	select {
	case r := <-bad.resp:
		if r.Status != 502 {
			t.Fatalf("status = %d, want 502", r.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("over-limit chunk did not fail the request")
	}
	if a, _ := findRelayAck(h.relayAcks("h1"), "bad"); !a.Abort {
		t.Fatalf("bad request tombstone = %+v, want abort", a)
	}
	h.mu.Lock()
	_, otherPending := h.pending["h1"]["other"]
	h.mu.Unlock()
	if !otherPending {
		t.Fatal("an unrelated pending request was dropped")
	}
	select {
	case r := <-other.resp:
		t.Fatalf("unrelated request was answered: %+v", r)
	default:
	}
}

// A respond for a reqId with no pending entry produces an abort tombstone so
// the host stops working on an answer nobody is waiting for.
func TestAcceptRespondUnknownReqAborts(t *testing.T) {
	h := NewWithDir("")
	known, notify := h.acceptRespond("h1", respondFrame("ghost", 1, 200, []byte(`{}`), false))
	if known || notify {
		t.Fatalf("unknown respond = %v/%v, want false/false", known, notify)
	}
	a, ok := findRelayAck(h.relayAcks("h1"), "ghost")
	if !ok || !a.Abort || a.Done {
		t.Fatalf("unknown respond tombstone = %+v (found %v), want abort", a, ok)
	}
	if got := h.Stats().LateRelayChunks; got != 1 {
		t.Fatalf("LateRelayChunks = %d, want 1", got)
	}
}

// The ack table mixes pending, done and abort entries, and its tombstones
// expire after the TTL instead of growing forever.
func TestRelayAcksPendingDoneAbortAndTTL(t *testing.T) {
	h := NewWithDir("")
	pending := addChunkPending(h, "h1", "pending")
	h.mu.Lock()
	pending.nextChunk = 4
	h.mu.Unlock()
	addChunkPending(h, "h1", "done")
	if !h.Respond("h1", "done", RelayResponse{Status: 200, Body: json.RawMessage(`{"ok":true}`)}) {
		t.Fatal("Respond failed")
	}
	aborted := addChunkPending(h, "h1", "aborted")
	h.failRelayRequestLocked("h1", "aborted", "test abort")
	select {
	case <-aborted.resp:
	default:
		t.Fatal("aborted request got no 502")
	}

	acks := h.relayAcks("h1")
	if a, _ := findRelayAck(acks, "pending"); a.Chunk != 4 || a.Done || a.Abort {
		t.Fatalf("pending entry = %+v, want chunk 4", a)
	}
	if a, _ := findRelayAck(acks, "done"); !a.Done || a.Abort || a.Chunk != 1 {
		t.Fatalf("done entry = %+v, want chunk 1 done", a)
	}
	if a, _ := findRelayAck(acks, "aborted"); !a.Abort || a.Done {
		t.Fatalf("abort entry = %+v, want abort", a)
	}

	prevTTL := relayTombstoneTTL
	relayTombstoneTTL = -time.Second // everything is already expired
	t.Cleanup(func() { relayTombstoneTTL = prevTTL })
	acks = h.relayAcks("h1")
	if _, ok := findRelayAck(acks, "done"); ok {
		t.Fatal("expired done tombstone still reported")
	}
	if _, ok := findRelayAck(acks, "aborted"); ok {
		t.Fatal("expired abort tombstone still reported")
	}
	if a, ok := findRelayAck(acks, "pending"); !ok || a.Chunk != 4 {
		t.Fatalf("pending entry disappeared: %+v (found %v)", a, ok)
	}
}

// Registry departure paths (failRequest, failPendingLocked/dropPending) leave
// an abort tombstone where the pending entry used to be.
func TestRelayFailurePathsAddAbortTombstones(t *testing.T) {
	h := NewWithDir("")
	addChunkPending(h, "h1", "expired")
	h.failRequest("h1", "expired", 503, "host 未确认")
	if a, _ := findRelayAck(h.relayAcks("h1"), "expired"); !a.Abort {
		t.Fatalf("failRequest tombstone = %+v, want abort", a)
	}

	addChunkPending(h, "h1", "cancelled")
	h.dropPending("h1", "cancelled")
	if a, _ := findRelayAck(h.relayAcks("h1"), "cancelled"); !a.Abort {
		t.Fatalf("dropPending tombstone = %+v, want abort", a)
	}

	addChunkPending(h, "h1", "detached")
	h.mu.Lock()
	h.failPendingLocked("h1")
	h.mu.Unlock()
	if a, _ := findRelayAck(h.relayAcks("h1"), "detached"); !a.Abort {
		t.Fatalf("failPendingLocked tombstone = %+v, want abort", a)
	}
}

// A request that is resolved keeps its done tombstone even if a late answer
// path tries to abort it.
func TestDoneTombstoneNotDowngraded(t *testing.T) {
	h := NewWithDir("")
	addChunkPending(h, "h1", "r1")
	if !h.Respond("h1", "r1", RelayResponse{Status: 200, Body: json.RawMessage(`{"a":1}`)}) {
		t.Fatal("Respond failed")
	}
	h.mu.Lock()
	h.addAbortTombstoneLocked("h1", "r1")
	h.mu.Unlock()
	if a, _ := findRelayAck(h.relayAcks("h1"), "r1"); !a.Done || a.Abort {
		t.Fatalf("terminal state = %+v, want done", a)
	}
}

// hello_ack carries the ack table on a same-epoch reconnect, and a new epoch
// clears it.
func TestRelayAcksInHelloAckOnResume(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 7)

	done := make(chan RelayResponse, 1)
	go func() {
		r, _ := h.Dispatch(context.Background(), "h1", "GET", "/api/status", nil)
		done <- r
	}()
	req := fh.recvType(wire.TypeRequest, 2*time.Second)

	// Chunk 1 advances the ack; the session pushes an hb immediately.
	part1 := []byte(`{"ok":true,"text":"`)
	fh.send(respondFrame(req.ReqID, 1, 207, part1, true))
	waitForHbAck(t, fh, req.ReqID, 1, false)

	// The final chunk completes the answer and is acknowledged as done.
	part2 := []byte(`fin"}`)
	final := respondFrame(req.ReqID, 2, 207, part2, false)
	final.Ack = req.Seq // also release the down log entry
	fh.send(final)
	select {
	case r := <-done:
		if r.Status != 207 || string(r.Body) != string(part1)+string(part2) {
			t.Fatalf("assembled answer = %d %q", r.Status, r.Body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("chunked answer did not resolve the dispatch")
	}

	fh.ft.hangup()
	fh.waitReason(2 * time.Second)

	again := dialFakeHost(t, h, "h1", 7)
	a, ok := findRelayAck(again.ack.RelayAcks, req.ReqID)
	if !ok || !a.Done || a.Abort || a.Chunk != 2 {
		t.Fatalf("hello_ack tombsone for %s = %+v (found %v), want done chunk 2", req.ReqID, a, ok)
	}

	// A request in flight when the link drops is aborted in the same epoch.
	go func() {
		_, _ = h.Dispatch(context.Background(), "h1", "GET", "/api/other", nil)
	}()
	req2 := again.recvType(wire.TypeRequest, 2*time.Second)
	again.ft.hangup()
	again.waitReason(2 * time.Second)
	resumed := dialFakeHost(t, h, "h1", 7)
	a, ok = findRelayAck(resumed.ack.RelayAcks, req2.ReqID)
	if !ok || !a.Abort || a.Done {
		t.Fatalf("hello_ack tombstone for %s = %+v (found %v), want abort", req2.ReqID, a, ok)
	}

	// A new epoch starts with no relay memory at all.
	fresh := dialFakeHost(t, h, "h1", 8)
	if len(fresh.ack.RelayAcks) != 0 {
		t.Fatalf("new epoch hello_ack.RelayAcks = %+v, want empty", fresh.ack.RelayAcks)
	}
}

// waitForHbAck waits until an hb carries the request's ack entry at chunk and
// the wanted terminal flag.
func waitForHbAck(t *testing.T, fh *fakeHost, reqID string, chunk uint64, done bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			t.Fatalf("no hb carried relayAck %s chunk %d", reqID, chunk)
		}
		f := fh.recvType(wire.TypeHeartbeat, left)
		if a, ok := findRelayAck(f.RelayAcks, reqID); ok && a.Chunk == chunk && a.Done == done {
			return
		}
	}
}

// The ack table never exceeds its per-host tombstone bound.
func TestRelayTombstonesBounded(t *testing.T) {
	prev := maxRelayTombstonesPerHost
	maxRelayTombstonesPerHost = 4
	t.Cleanup(func() { maxRelayTombstonesPerHost = prev })

	h := NewWithDir("")
	for i := 0; i < 10; i++ {
		reqID := "r" + string(rune('0'+i))
		h.acceptRespond("h1", respondFrame(reqID, 1, 200, []byte(`{}`), false))
	}
	if got := len(h.relayAcks("h1")); got != maxRelayTombstonesPerHost {
		t.Fatalf("ack table size = %d, want the bound %d", got, maxRelayTombstonesPerHost)
	}
}

// A preflight probe that is never answered fails the dispatch with 503 and,
// crucially, never writes the request frame.
func TestDispatchPreflightFailureWritesNoRequest(t *testing.T) {
	prevWindow, prevTimeout := relayHealthWindow, relayProbeTimeout
	relayHealthWindow, relayProbeTimeout = 0, 250*time.Millisecond
	t.Cleanup(func() { relayHealthWindow, relayProbeTimeout = prevWindow, prevTimeout })

	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	done := make(chan error, 1)
	go func() {
		_, err := h.Dispatch(context.Background(), "h1", "POST", "/api/prompt", nil)
		done <- err
	}()
	probe := fh.recvType(wire.TypeHeartbeat, 2*time.Second)
	if probe.Probe == 0 {
		t.Fatalf("expected a preflight probe, got hb %+v", probe)
	}
	select {
	case err := <-done:
		var re *RelayError
		if !errors.As(err, &re) || re.Status != 503 || re.Message != "host 正在重连" {
			t.Fatalf("dispatch err = %v, want RelayError 503 host 正在重连", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dispatch did not fail on the unanswered probe")
	}
	// Only heartbeats may follow: a request frame would mean the preflight
	// failed to gate the dispatch.
	fh.noFrame(150 * time.Millisecond)
	h.mu.Lock()
	n := len(h.pending["h1"])
	h.mu.Unlock()
	if n != 0 {
		t.Fatalf("failed preflight left %d pending requests", n)
	}
	if acks := h.relayAcks("h1"); len(acks) != 0 {
		t.Fatalf("preflight failure left tombstones: %+v", acks)
	}
	if !h.ListHosts()[0].Online {
		t.Fatal("preflight failure closed the session")
	}
}

// A successful preflight dispatches the request normally.
func TestDispatchPreflightSuccessDispatches(t *testing.T) {
	prevWindow, prevTimeout := relayHealthWindow, relayProbeTimeout
	relayHealthWindow, relayProbeTimeout = 0, time.Second
	t.Cleanup(func() { relayHealthWindow, relayProbeTimeout = prevWindow, prevTimeout })

	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	done := make(chan RelayResponse, 1)
	go func() {
		r, _ := h.Dispatch(context.Background(), "h1", "GET", "/api/status", nil)
		done <- r
	}()
	probe := fh.recvType(wire.TypeHeartbeat, 2*time.Second)
	if probe.Probe == 0 {
		t.Fatalf("expected a preflight probe, got hb %+v", probe)
	}
	ack, err := wire.NewHeartbeatProbe(0, probe.Probe, wire.HeartbeatStatus{}, true)
	if err != nil {
		t.Fatal(err)
	}
	fh.send(ack)

	req := fh.recvType(wire.TypeRequest, 2*time.Second)
	fh.send(wire.Frame{
		V: wire.ProtocolVersion, Type: wire.TypeRespond, ReqID: req.ReqID, ChunkSeq: 1,
		Ack: req.Seq, Status: json.RawMessage(`200`), Body: json.RawMessage(`{"ok":true}`),
	})
	select {
	case r := <-done:
		if r.Status != 200 {
			t.Fatalf("status = %d", r.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dispatch did not resolve after a successful probe")
	}
}

// A fresh session (a frame within relayHealthWindow) skips the probe entirely.
func TestDispatchSkipsProbeWhenFresh(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	go func() { _, _ = h.Dispatch(context.Background(), "h1", "GET", "/api/status", nil) }()
	for {
		f := fh.recv(2 * time.Second)
		if f.Type == wire.TypeRequest {
			break
		}
		if f.Type == wire.TypeHeartbeat && f.Probe != 0 {
			t.Fatal("fresh session was probed before dispatch")
		}
	}
}

// Concurrent probes share one outstanding hb instead of each writing their
// own; a single probeAck releases every waiter.
func TestSessionProbeCoalesces(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	h.mu.Lock()
	sess := h.hosts["h1"].session
	h.mu.Unlock()
	if sess == nil {
		t.Fatal("host not attached")
	}

	const waiters = 4
	errs := make(chan error, waiters)
	for i := 0; i < waiters; i++ {
		go func() { errs <- sess.probe(context.Background(), time.Second) }()
	}
	probe := fh.recvType(wire.TypeHeartbeat, 2*time.Second)
	if probe.Probe == 0 {
		t.Fatalf("expected a probe, got %+v", probe)
	}
	// No second probe may appear while the first is outstanding.
	deadline := time.Now().Add(150 * time.Millisecond)
	for time.Now().Before(deadline) {
		select {
		case raw := <-fh.ft.outbox:
			f, err := wire.Decode(raw)
			if err != nil {
				t.Fatalf("decode downlink: %v", err)
			}
			if f.Type == wire.TypeHeartbeat && f.Probe != 0 && f.Probe != probe.Probe {
				t.Fatalf("second concurrent probe %d (first %d)", f.Probe, probe.Probe)
			}
		case <-time.After(20 * time.Millisecond):
		}
	}
	ack, err := wire.NewHeartbeatProbe(0, probe.Probe, wire.HeartbeatStatus{}, true)
	if err != nil {
		t.Fatal(err)
	}
	fh.send(ack)
	for i := 0; i < waiters; i++ {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatalf("waiter %d: %v", i, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("waiter %d did not observe the probeAck", i)
		}
	}
}

// An interactive request that is never acked fails alone with 503 + abort;
// the session and other traffic keep working.
func TestInteractiveAckDeadlineFailsOneRequest(t *testing.T) {
	prev := interactiveAckWindow
	interactiveAckWindow = 300 * time.Millisecond
	t.Cleanup(func() { interactiveAckWindow = prev })
	shortLiveness(t, 1, 10)

	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	start := time.Now()
	resp, err := h.Dispatch(context.Background(), "h1", "GET", "/api/status", nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if resp.Status != 503 {
		t.Fatalf("status = %d, want 503", resp.Status)
	}
	if elapsed < interactiveAckWindow {
		t.Fatalf("failed after %s, before the %s window", elapsed, interactiveAckWindow)
	}
	req := fh.recvType(wire.TypeRequest, 2*time.Second)
	if a, ok := findRelayAck(h.relayAcks("h1"), req.ReqID); !ok || !a.Abort {
		t.Fatalf("expired request tombstone = %+v (found %v), want abort", a, ok)
	}

	// The session survives: a later event is still applied.
	fh.events(1, 0, chunkEvent(1, "alive"))
	waitFor(t, func() bool { return h.LastSeq("h1") == 1 }, 2*time.Second)
	if !h.ListHosts()[0].Online {
		t.Fatal("ack expiry closed the session")
	}
}

// Browser cancellation aborts the request and leaves the session alive.
func TestDispatchCancelAddsAbortTombstone(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := h.Dispatch(ctx, "h1", "POST", "/api/prompt", nil)
		done <- err
	}()
	req := fh.recvType(wire.TypeRequest, 2*time.Second)
	cancel()
	select {
	case err := <-done:
		var re *RelayError
		if !errors.As(err, &re) || re.Status != 499 {
			t.Fatalf("dispatch err = %v, want 499", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dispatch did not return on cancellation")
	}
	if a, ok := findRelayAck(h.relayAcks("h1"), req.ReqID); !ok || !a.Abort {
		t.Fatalf("cancel tombstone = %+v (found %v), want abort", a, ok)
	}
	// The host may still finish; the session itself remains healthy.
	fh.events(1, 0, chunkEvent(1, "alive"))
	waitFor(t, func() bool { return h.LastSeq("h1") == 1 }, 2*time.Second)
}

// The default parked bounds must fit one maximum answer resumed after its
// first chunk was lost. A 28MiB answer at the host's 256KiB chunk size is
// ~112 chunks, so a 64-chunk cap (the original value) rejected a legitimate
// resume; the bound must cover that answer and leave room for another request.
func TestParkedRelayBoundsFitOneMaxAnswer(t *testing.T) {
	chunksPerAnswer := maxChunkedRelayBody/hostRelayChunkSize + 1
	if maxParkedRelayChunksPerHost < 256 {
		t.Fatalf("maxParkedRelayChunksPerHost = %d, want at least 256", maxParkedRelayChunksPerHost)
	}
	if maxParkedRelayChunksPerHost < 2*chunksPerAnswer {
		t.Fatalf("maxParkedRelayChunksPerHost = %d, want room for two %d-chunk answers",
			maxParkedRelayChunksPerHost, chunksPerAnswer)
	}
	if maxParkedRelayBytesPerHost < 32<<20 {
		t.Fatalf("maxParkedRelayBytesPerHost = %d, want at least 32MiB", maxParkedRelayBytesPerHost)
	}
	// Parked frames hold base64, so one encoded answer alone is 4/3 of the
	// decoded ceiling; the bound must exceed that before any headroom.
	encodedAnswer := maxChunkedRelayBody*4/3 + hostRelayChunkSize
	if maxParkedRelayBytesPerHost < encodedAnswer {
		t.Fatalf("maxParkedRelayBytesPerHost = %d, want at least one encoded answer (%d) to fit",
			maxParkedRelayBytesPerHost, encodedAnswer)
	}
}

// A lost first chunk must not fail a large answer: every later chunk parks,
// then the missing chunk drains the whole run in order. This uses a scaled-down
// answer with the real 112-chunk-to-256-cap ratio, so it does not allocate
// 28MiB just to prove the cap.
func TestAcceptRespondParksWholeLargeAnswer(t *testing.T) {
	const (
		chunks    = 112 // 28MiB / 256KiB at the host's chunk size
		chunkSize = 1024
	)
	body := make([]byte, chunks*chunkSize)
	const prefix = `{"data":"`
	copy(body, prefix)
	for i := len(prefix); i < len(body)-2; i++ {
		body[i] = 'x'
	}
	copy(body[len(body)-2:], `"}`)
	chunkAt := func(i int) []byte { return body[(i-1)*chunkSize : i*chunkSize] }

	h := NewWithDir("")
	pr := addChunkPending(h, "h1", "big")

	// Chunk 1 is lost; chunks 2..112 arrive first and park.
	for i := 2; i <= chunks; i++ {
		known, notify := h.acceptRespond("h1", respondFrame("big", uint64(i), 200, chunkAt(i), i != chunks))
		if !known || notify {
			t.Fatalf("parked chunk %d: known=%v notify=%v, want true/false", i, known, notify)
		}
	}
	h.mu.Lock()
	parked := len(pr.parked)
	h.mu.Unlock()
	if parked != chunks-1 {
		t.Fatalf("parked chunks = %d, want %d", parked, chunks-1)
	}
	select {
	case r := <-pr.resp:
		t.Fatalf("large answer failed before the lost chunk arrived: %+v", r)
	default:
	}
	if a, _ := findRelayAck(h.relayAcks("h1"), "big"); a.Chunk != 0 || a.Done || a.Abort {
		t.Fatalf("ack while the gap is open = %+v, want pending chunk 0", a)
	}

	// The missing first chunk arrives: the parked run drains in order.
	if known, notify := h.acceptRespond("h1", respondFrame("big", 1, 200, chunkAt(1), true)); !known || !notify {
		t.Fatalf("chunk 1: known=%v notify=%v, want true/true", known, notify)
	}
	select {
	case r := <-pr.resp:
		if r.Status != 200 {
			t.Fatalf("status = %d, want 200", r.Status)
		}
		if !bytes.Equal(r.Body, body) {
			t.Fatalf("assembled body = %d bytes, want %d", len(r.Body), len(body))
		}
		if !json.Valid(r.Body) {
			t.Fatal("assembled body is not valid JSON")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("large answer did not resolve after the missing chunk arrived")
	}
	if a, _ := findRelayAck(h.relayAcks("h1"), "big"); !a.Done || a.Chunk != chunks || a.Abort {
		t.Fatalf("done tombstone = %+v, want chunk %d done", a, chunks)
	}
}
