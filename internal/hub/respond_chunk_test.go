package hub

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// addChunkPending registers one pending relay request the way Dispatch does,
// without needing a live host connection.
func addChunkPending(h *Hub, hostID, reqID string) *pendingReq {
	pr := &pendingReq{resp: make(chan RelayResponse, 1), done: make(chan struct{})}
	h.mu.Lock()
	if h.pending[hostID] == nil {
		h.pending[hostID] = make(map[string]*pendingReq)
	}
	h.pending[hostID][reqID] = pr
	h.mu.Unlock()
	return pr
}

func chunkB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// A body split across several `respond` frames must reach the waiting relay
// caller as one RelayResponse with the exact original bytes and the status
// of the first chunk. The pending entry disappears only on the final chunk.
func TestRespondChunkAssemblesBody(t *testing.T) {
	h := NewWithDir("")
	pr := addChunkPending(h, "h1", "r1")

	part1 := []byte(`{"ok":true,"text":"`)
	part2 := []byte(`fin`)
	part3 := []byte(`"}`)

	if !h.RespondChunk("h1", "r1", 207, "base64", chunkB64(part1), true) {
		t.Fatal("first chunk rejected")
	}
	if !h.RespondChunk("h1", "r1", 207, "base64", chunkB64(part2), true) {
		t.Fatal("second chunk rejected")
	}
	select {
	case r := <-pr.resp:
		t.Fatalf("request resolved before the final chunk: %+v", r)
	default:
	}
	h.mu.Lock()
	_, stillPending := h.pending["h1"]["r1"]
	h.mu.Unlock()
	if !stillPending {
		t.Fatal("pending entry dropped before the final chunk")
	}

	if !h.RespondChunk("h1", "r1", 207, "base64", chunkB64(part3), false) {
		t.Fatal("final chunk rejected")
	}
	select {
	case r := <-pr.resp:
		want := string(part1) + string(part2) + string(part3)
		if r.Status != 207 {
			t.Fatalf("status = %d, want 207 (first chunk's status)", r.Status)
		}
		if string(r.Body) != want {
			t.Fatalf("body = %q, want %q", r.Body, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("final chunk did not resolve the pending request")
	}

	h.mu.Lock()
	_, stillPending = h.pending["h1"]["r1"]
	h.mu.Unlock()
	if stillPending {
		t.Fatal("pending entry survived the final chunk")
	}

	// A chunk arriving after resolution is a late chunk: ignored, counted.
	if h.RespondChunk("h1", "r1", 207, "base64", chunkB64([]byte("late")), false) {
		t.Fatal("late chunk for a resolved request reported success")
	}
	if got := h.Stats().LateRelayChunks; got != 1 {
		t.Fatalf("LateRelayChunks = %d, want 1", got)
	}
}

// Over the assembled cap the hub must drop only that request, answer it with
// a 502 JSON error, and leave every other pending request untouched.
func TestRespondChunkOverLimitFailsOnlyThatRequest(t *testing.T) {
	prev := maxChunkedRelayBody
	maxChunkedRelayBody = 8
	t.Cleanup(func() { maxChunkedRelayBody = prev })

	h := NewWithDir("")
	bad := addChunkPending(h, "h1", "big")
	other := addChunkPending(h, "h1", "other")

	if !h.RespondChunk("h1", "big", 200, "base64", chunkB64([]byte("12345")), true) {
		t.Fatal("first chunk rejected")
	}
	// 5 + 5 > 8: the cap is hit on the second chunk.
	if !h.RespondChunk("h1", "big", 200, "base64", chunkB64([]byte("67890")), false) {
		t.Fatal("over-limit chunk reported unknown reqId; it must fail the request instead")
	}
	select {
	case r := <-bad.resp:
		if r.Status != 502 {
			t.Fatalf("status = %d, want 502", r.Status)
		}
		var body struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(r.Body, &body); err != nil || body.Error == "" {
			t.Fatalf("502 body = %s, want a JSON error object", r.Body)
		}
		if !strings.Contains(body.Error, "上限") {
			t.Fatalf("502 error = %q, want the size-limit explanation", body.Error)
		}
	default:
		t.Fatal("no 502 delivered for the oversized chunked body")
	}

	h.mu.Lock()
	_, badStill := h.pending["h1"]["big"]
	_, otherStill := h.pending["h1"]["other"]
	h.mu.Unlock()
	if badStill {
		t.Fatal("oversized request still pending")
	}
	if !otherStill {
		t.Fatal("an unrelated pending request was dropped; only the bad one may fail")
	}
	select {
	case r := <-other.resp:
		t.Fatalf("unrelated request was answered: %+v", r)
	default:
	}
}

// An unsupported (or missing) encoding is a protocol error for that one
// request, not a body-less answer and not a session failure.
func TestRespondChunkBadEncodingFailsRequest(t *testing.T) {
	for _, encoding := range []string{"", "hex"} {
		h := NewWithDir("")
		pr := addChunkPending(h, "h1", "r1")
		if !h.RespondChunk("h1", "r1", 200, encoding, chunkB64([]byte("abc")), false) {
			t.Fatalf("encoding %q: chunk reported unknown reqId", encoding)
		}
		select {
		case r := <-pr.resp:
			if r.Status != 502 {
				t.Fatalf("encoding %q: status = %d, want 502", encoding, r.Status)
			}
		default:
			t.Fatalf("encoding %q: no error response delivered", encoding)
		}
		h.mu.Lock()
		_, still := h.pending["h1"]["r1"]
		h.mu.Unlock()
		if still {
			t.Fatalf("encoding %q: pending entry survived a protocol error", encoding)
		}
	}
}

// A chunk for an unknown reqId (the browser already gave up) must be ignored
// and counted, never panic.
func TestRespondChunkUnknownReqIgnored(t *testing.T) {
	h := NewWithDir("")
	if h.RespondChunk("nobody", "r1", 200, "base64", chunkB64([]byte("x")), false) {
		t.Fatal("chunk for an unknown host reported success")
	}
	if got := h.Stats().LateRelayChunks; got != 1 {
		t.Fatalf("LateRelayChunks = %d, want 1", got)
	}
}

// A body that does not parse as JSON after assembly is a host bug: answer
// the request with 502 instead of handing invalid bytes to the FE writer.
func TestRespondChunkInvalidJSONFailsRequest(t *testing.T) {
	h := NewWithDir("")
	pr := addChunkPending(h, "h1", "r1")
	if !h.RespondChunk("h1", "r1", 200, "base64", chunkB64([]byte(`{"a":`)), false) {
		t.Fatal("chunk rejected")
	}
	select {
	case r := <-pr.resp:
		if r.Status != 502 {
			t.Fatalf("status = %d, want 502", r.Status)
		}
	default:
		t.Fatal("invalid assembled body did not fail the request")
	}
}

// Small answers keep the original single-frame path untouched.
func TestRespondSingleFrameStillResolves(t *testing.T) {
	h := NewWithDir("")
	pr := addChunkPending(h, "h1", "r1")
	if !h.Respond("h1", "r1", RelayResponse{Status: 200, Body: json.RawMessage(`{"ok":true}`)}) {
		t.Fatal("Respond rejected a pending request")
	}
	select {
	case r := <-pr.resp:
		if r.Status != 200 || string(r.Body) != `{"ok":true}` {
			t.Fatalf("response = %d %s", r.Status, r.Body)
		}
	default:
		t.Fatal("Respond did not deliver")
	}
}
