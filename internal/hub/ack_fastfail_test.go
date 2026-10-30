package hub

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// A prompt whose host goes silent right after dispatch must fail fast with
// 503 instead of waiting out RelayTimeout. This is the "message showed up
// but never ran" case: the frame reached the host's transport, the uplink
// died, and no ack will ever come.
func TestDispatchFailsFastWhenUplinkGoesSilent(t *testing.T) {
	prevAck, prevTick := RelayAckTimeout, AckCheckInterval
	RelayAckTimeout = 50 * time.Millisecond
	AckCheckInterval = 10 * time.Millisecond
	defer func() { RelayAckTimeout, AckCheckInterval = prevAck, prevTick }()

	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	frames := make(chan []byte, 4)
	_, stop, err := h.ConnectStream("h1", func(p []byte) error {
		frames <- p
		return nil
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer stop()

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := h.Dispatch(context.Background(), "h1", "POST", "/api/prompt", json.RawMessage(`{"blocks":[]}`))
		done <- err
	}()
	select {
	case <-frames:
	case <-time.After(time.Second):
		t.Fatal("request frame never reached the host")
	}
	// Never answer. The uplink is "silent" from dispatch onward.
	select {
	case err := <-done:
		var re *RelayError
		if !errors.As(err, &re) || re.Status != 503 {
			t.Errorf("err = %v, want RelayError 503", err)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("took %v, want fast-fail near the ack timeout", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("prompt did not fail fast on a silent uplink")
	}
}

// A host that keeps beating must NOT have its request failed: the request
// is slow, the link is fine.
func TestDispatchKeepsWaitingWhileHostStillBeats(t *testing.T) {
	prevAck, prevTick := RelayAckTimeout, AckCheckInterval
	RelayAckTimeout = 60 * time.Millisecond
	AckCheckInterval = 15 * time.Millisecond
	defer func() { RelayAckTimeout, AckCheckInterval = prevAck, prevTick }()

	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	_, stop, err := h.ConnectStream("h1", func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer stop()

	done := make(chan error, 1)
	go func() {
		_, err := h.Dispatch(context.Background(), "h1", "POST", "/api/prompt", json.RawMessage(`{"blocks":[]}`))
		done <- err
	}()

	// Keep the host alive across several check intervals.
	ready := true
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		h.UpdateHostStatus("h1", HostStatusPatch{Ready: &ready})
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case err := <-done:
		t.Fatalf("request failed although the host kept beating: %v", err)
	default:
	}
	if !h.ListHosts()[0].Online {
		t.Error("a beating host must stay online")
	}
}

// Long-running endpoints are exempt: their absence of a respond proves
// nothing, so the ack budget must never fail them.
func TestDispatchAckTimeoutExemptsLongEndpoints(t *testing.T) {
	if got := dispatchAckTimeout("/api/prompt"); got <= 0 {
		t.Error("/api/prompt must be subject to the ack budget")
	}
	// Queue operations answer without waiting on the agent, so an absent ack
	// means a dead uplink just as it does for a prompt. Missing one of these
	// would leave a queue action hanging for RelayTimeout while the UI shows
	// it as done.
	for _, p := range []string{
		"/api/queue/interject",
		"/api/queue/remove",
		"/api/queue/clear",
		"/api/queue/reorder",
		"/api/queue/edit",
		"/api/queue/hold-edit",
		"/api/queue/release-edit",
		// 审批 / 提问回执：agent 在等这个答案，丢了的观感是"点了没反应"。
		"/api/permission-response",
		"/api/client-response",
	} {
		if got := dispatchAckTimeout(p); got <= 0 {
			t.Errorf("%s exempt = %v, want the ack budget (host answers it directly)", p, got)
		}
	}
	for _, p := range []string{
		"/api/session-updates", "/api/memory-flush", "/api/memory-dream",
		// These block on a 30s agent RPC (or boot the agent first) on the
		// host: a slow-but-healthy call must not fast-fail unrelated work.
		"/api/cancel", "/api/set-mode", "/api/set-model", "/api/toggle-plan-mode",
	} {
		if got := dispatchAckTimeout(p); got != 0 {
			t.Errorf("%s exempt = %v, want 0 (host blocks on the agent; keep RelayTimeout)", p, got)
		}
	}
}

// TestSilentAckFailsOnlyOffendingRequest: one request going unanswered past
// its ack budget must not tear down the other pending requests of the same
// host. A model switch queued behind a turn can exceed the budget on a
// perfectly healthy host, and the in-flight prompt that would have
// succeeded must survive it.
func TestSilentAckFailsOnlyOffendingRequest(t *testing.T) {
	prevAck, prevTick := RelayAckTimeout, AckCheckInterval
	RelayAckTimeout = 50 * time.Millisecond
	AckCheckInterval = 10 * time.Millisecond
	defer func() { RelayAckTimeout, AckCheckInterval = prevAck, prevTick }()

	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	frames := make(chan []byte, 8)
	_, stop, err := h.ConnectStream("h1", func(p []byte) error {
		frames <- p
		return nil
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer stop()

	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()

	doneA := make(chan error, 1)
	doneB := make(chan error, 1)
	go func() {
		_, err := h.Dispatch(ctxA, "h1", "POST", "/api/prompt", json.RawMessage(`{"blocks":[]}`))
		doneA <- err
	}()
	go func() {
		_, err := h.Dispatch(ctxB, "h1", "POST", "/api/session-updates", json.RawMessage(`{}`))
		doneB <- err
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-frames:
		case <-time.After(time.Second):
			t.Fatal("request frames never reached the host")
		}
	}
	// The host never answers; only the prompt is subject to the ack budget.
	select {
	case err := <-doneA:
		var re *RelayError
		if !errors.As(err, &re) || re.Status != 503 {
			t.Errorf("prompt err = %v, want RelayError 503", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("prompt did not fail fast on a silent uplink")
	}
	select {
	case err := <-doneB:
		t.Fatalf("unrelated request was failed: %v", err)
	default:
	}
	h.mu.Lock()
	pending := len(h.pending["h1"])
	online := h.hosts["h1"].info.Online
	h.mu.Unlock()
	if pending != 1 {
		t.Errorf("pending requests = %d, want 1 (only the offending one failed)", pending)
	}
	if !online {
		t.Error("host must stay online: the ack fast-fail does not own the offline verdict")
	}

	// Clean up the surviving waiter.
	cancelB()
	select {
	case err := <-doneB:
		var re *RelayError
		if !errors.As(err, &re) || re.Status != 499 {
			t.Errorf("cancelled request err = %v, want RelayError 499", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending request did not return after its context was cancelled")
	}
}
