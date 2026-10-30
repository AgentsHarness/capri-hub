package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-wire"
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

	fh := dialFakeHost(t, h, "h1", 1)

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
	fh.noFrame(100 * time.Millisecond)

	// Free one slot: the next request is admitted and resolves normally.
	h.mu.Lock()
	delete(h.pending["h1"], "pre-0")
	h.mu.Unlock()

	done := make(chan error, 1)
	go func() {
		_, err := h.Dispatch(context.Background(), "h1", http.MethodGet, "/api/status", nil)
		done <- err
	}()
	req := fh.recvType(wire.TypeRequest, 5*time.Second)
	reqID := req.ReqID
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
