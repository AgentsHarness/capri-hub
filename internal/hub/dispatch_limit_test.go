package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// One host may have at most maxPendingRelayPerHost relayed requests in
// flight: each can buffer a 28MB answer while chunks assemble. Over the cap
// Dispatch refuses with 429 and leaves existing requests untouched; freeing a
// slot admits the next one normally.
func TestDispatchPendingLimitPerHost(t *testing.T) {
	prev := maxPendingRelayPerHost
	maxPendingRelayPerHost = 2
	t.Cleanup(func() { maxPendingRelayPerHost = prev })

	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	frames := make(chan string, 4)
	if _, stop, err := h.ConnectStream("h1", func(payload []byte) error {
		var f struct {
			Type  string `json:"type"`
			ReqID string `json:"reqId"`
		}
		if json.Unmarshal(payload, &f) == nil && f.Type == "request" {
			frames <- f.ReqID
		}
		return nil
	}); err != nil {
		t.Fatalf("connect: %v", err)
	} else {
		defer stop()
	}

	// Fill the table to the limit without dispatching.
	h.mu.Lock()
	if h.pending["h1"] == nil {
		h.pending["h1"] = make(map[string]*pendingReq)
	}
	for i := 0; i < maxPendingRelayPerHost; i++ {
		id := fmt.Sprintf("pre-%d", i)
		h.pending["h1"][id] = &pendingReq{
			resp: make(chan RelayResponse, 1),
			done: make(chan struct{}),
		}
	}
	h.mu.Unlock()

	_, err := h.Dispatch(context.Background(), "h1", http.MethodGet, "/api/status", nil)
	var re *RelayError
	if !errors.As(err, &re) || re.Status != 429 {
		t.Fatalf("dispatch over the pending cap = %v, want RelayError 429", err)
	}

	h.mu.Lock()
	_, kept := h.pending["h1"]["pre-1"]
	h.mu.Unlock()
	if !kept {
		t.Fatal("the refusal removed an existing pending request")
	}
	select {
	case id := <-frames:
		t.Fatalf("over-cap dispatch still wrote a request frame (%s)", id)
	default:
	}

	// Free one slot: the next request is admitted and resolves normally.
	h.mu.Lock()
	delete(h.pending["h1"], "pre-0")
	h.mu.Unlock()

	done := make(chan error, 1)
	go func() {
		_, err := h.Dispatch(context.Background(), "h1", http.MethodGet, "/api/status", nil)
		done <- err
	}()
	var reqID string
	select {
	case reqID = <-frames:
	case <-time.After(5 * time.Second):
		t.Fatal("freed slot did not admit the next request")
	}
	if !h.Respond("h1", reqID, RelayResponse{Status: 200, Body: json.RawMessage(`{"ok":true}`)}) {
		t.Fatal("Respond failed for the admitted request")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("dispatch after freeing a slot: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("admitted dispatch did not return")
	}
}
