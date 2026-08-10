package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/benin/acp-hub/internal/hub"
)

func TestTokenEqual(t *testing.T) {
	if !tokenEqual("abc", "abc") {
		t.Error("equal tokens should match")
	}
	if tokenEqual("abc", "abd") {
		t.Error("different tokens must not match")
	}
	if tokenEqual("abc", "abcd") {
		t.Error("length mismatch must not match")
	}
	if tokenEqual("", "") {
		t.Error("empty must not match (treat as missing)")
	}
	if tokenEqual("x", "") {
		t.Error("empty expected side must not match")
	}
}

func TestCheckFETokenDisabled(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/events", nil)
	if !checkFEToken(r, "") {
		t.Error("empty expected should allow all requests")
	}
}

func TestCheckFETokenSources(t *testing.T) {
	const secret = "s3cret-fe-token"

	// Missing → deny
	r := httptest.NewRequest(http.MethodGet, "/events", nil)
	if checkFEToken(r, secret) {
		t.Error("missing token should deny")
	}

	// Authorization: Bearer
	r = httptest.NewRequest(http.MethodGet, "/api/hosts", nil)
	r.Header.Set("Authorization", "Bearer "+secret)
	if !checkFEToken(r, secret) {
		t.Error("Bearer token should allow")
	}

	// case-insensitive Bearer prefix
	r = httptest.NewRequest(http.MethodGet, "/api/hosts", nil)
	r.Header.Set("Authorization", "bearer "+secret)
	if !checkFEToken(r, secret) {
		t.Error("bearer (lowercase) should allow")
	}

	// Wrong bearer
	r = httptest.NewRequest(http.MethodGet, "/api/hosts", nil)
	r.Header.Set("Authorization", "Bearer wrong")
	if checkFEToken(r, secret) {
		t.Error("wrong Bearer should deny")
	}

	// X-Access-Token
	r = httptest.NewRequest(http.MethodGet, "/api/hosts", nil)
	r.Header.Set("X-Access-Token", secret)
	if !checkFEToken(r, secret) {
		t.Error("X-Access-Token should allow")
	}

	// Query param (EventSource)
	r = httptest.NewRequest(http.MethodGet, "/events?token="+secret, nil)
	if !checkFEToken(r, secret) {
		t.Error("?token= should allow")
	}

	// Wrong query
	r = httptest.NewRequest(http.MethodGet, "/events?token=nope", nil)
	if checkFEToken(r, secret) {
		t.Error("wrong ?token= should deny")
	}
}

func TestRequireFEToken(t *testing.T) {
	const secret = "hub-fe-token"
	called := false
	h := requireFEToken(secret, func(w http.ResponseWriter, r *http.Request) {
		called = true
		writeJSON(w, 200, map[string]any{"ok": true})
	})

	// No token → 401
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/hosts", nil))
	if rr.Code != 401 {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json: %v", err)
	}
	if body["ok"] != false {
		t.Errorf("body.ok = %v, want false", body["ok"])
	}
	if called {
		t.Error("handler must not run on auth failure")
	}

	// Valid token → 200
	called = false
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/hosts", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if !called {
		t.Error("handler must run when token is valid")
	}
}

func TestRequireFETokenDisabled(t *testing.T) {
	called := false
	h := requireFEToken("", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(204)
	})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/events", nil))
	if rr.Code != 204 || !called {
		t.Fatalf("disabled gate should pass through (code=%d called=%v)", rr.Code, called)
	}
}

func TestBearerToken(t *testing.T) {
	if got := bearerToken("Bearer abc"); got != "abc" {
		t.Errorf("got %q", got)
	}
	if got := bearerToken("bearer  abc  "); got != "abc" {
		t.Errorf("got %q", got)
	}
	if got := bearerToken("Basic abc"); got != "" {
		t.Errorf("non-Bearer should be empty, got %q", got)
	}
	if got := bearerToken(""); got != "" {
		t.Errorf("empty should be empty, got %q", got)
	}
}

// TestHandleHostFramePreservesHostSeq: events frames carry host-assigned
// seqs (seqStart = first event's seq); they must be preserved so the
// per-host counter tracks the host's sequence exactly. Renumbering would
// shift every event and trigger spurious FE gap-pulls / replays.
func TestHandleHostFramePreservesHostSeq(t *testing.T) {
	h := hub.NewWithDir("")
	code, _ := h.PairingCode()
	if _, err := h.Pair(code, "h1", "H1"); err != nil {
		t.Fatalf("pair: %v", err)
	}
	ch, unsub := h.Subscribe()
	defer unsub()

	handleHostFrame(h, "h1",
		[]byte(`{"v":1,"type":"events","seqStart":100,"events":[{"type":"chunk","text":"a","seq":100},{"type":"chunk","text":"b","seq":101}]}`),
		func([]byte) error { return nil })

	if got := h.LastSeq("h1"); got != 101 {
		t.Errorf("LastSeq = %d, want 101 (host seq preserved)", got)
	}
	var seen []float64
	for len(seen) < 2 {
		select {
		case ev := <-ch:
			if s, ok := ev["seq"].(float64); ok {
				seen = append(seen, s)
			}
		case <-time.After(time.Second):
			t.Fatalf("only got %v", seen)
		}
	}
	if seen[0] != 100 || seen[1] != 101 {
		t.Errorf("broadcast seqs = %v, want [100 101]", seen)
	}
}

// TestPairLimiter: the sliding window must allow pairRateLimit attempts
// per IP per minute, reject beyond that, not affect other IPs, and open
// up again after the window elapses.
func TestPairLimiter(t *testing.T) {
	l := newPairLimiter()
	for i := 0; i < pairRateLimit; i++ {
		if !l.allow("1.2.3.4") {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}
	if l.allow("1.2.3.4") {
		t.Error("attempt beyond the limit must be rejected")
	}
	if !l.allow("5.6.7.8") {
		t.Error("a different IP must not be affected")
	}

	// Age all recorded hits out of the window.
	l.mu.Lock()
	old := time.Now().Add(-pairRateWindow - time.Second)
	for ip, hs := range l.hits {
		for i := range hs {
			hs[i] = old
		}
		l.hits[ip] = hs
	}
	l.mu.Unlock()
	if !l.allow("1.2.3.4") {
		t.Error("IP must be allowed again after the window elapses")
	}
}

// TestHandleRelayRejectsOversizeBody: a relay body over the 5MB cap must
// be rejected with 413, not silently truncated and forwarded to the host
// as broken JSON.
func TestHandleRelayRejectsOversizeBody(t *testing.T) {
	h := hub.NewWithDir("")
	code, _ := h.PairingCode()
	if _, err := h.Pair(code, "h1", "H1"); err != nil {
		t.Fatalf("pair: %v", err)
	}
	handler := handleRelay(h)
	body := make([]byte, (5<<20)+1)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/prompt", bytes.NewReader(body)))
	if rr.Code != 413 {
		t.Fatalf("status = %d, want 413 (body %d bytes > 5MB)", rr.Code, len(body))
	}
}

// TestHandleHostFrameSeqLessAdvancesCounter: a seq-less events frame must
// ADVANCE the per-host counter (RegisterEvent fallback), not reset it to
// 1 — a reset would make the next reconnect replay the whole backlog.
func TestHandleHostFrameSeqLessAdvancesCounter(t *testing.T) {
	h := hub.NewWithDir("")
	code, _ := h.PairingCode()
	if _, err := h.Pair(code, "h1", "H1"); err != nil {
		t.Fatalf("pair: %v", err)
	}
	// A seq-carrying frame sets the counter to 42.
	handleHostFrame(h, "h1",
		[]byte(`{"v":1,"type":"events","seqStart":42,"events":[{"type":"chunk","text":"a","seq":42}]}`),
		func([]byte) error { return nil })
	if got := h.LastSeq("h1"); got != 42 {
		t.Fatalf("LastSeq after seq frame = %d, want 42", got)
	}
	// A seq-less frame must advance to 43 — not reset to 1.
	handleHostFrame(h, "h1",
		[]byte(`{"v":1,"type":"events","events":[{"type":"host_status","ready":true}]}`),
		func([]byte) error { return nil })
	if got := h.LastSeq("h1"); got != 43 {
		t.Errorf("LastSeq after seq-less frame = %d, want 43", got)
	}
}
