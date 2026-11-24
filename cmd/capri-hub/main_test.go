package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

	// Query param is not an auth channel any more: EventSource on the local
	// host uses its own ?token= route, but the hub's FE gate takes headers or
	// a single-use ticket.
	r = httptest.NewRequest(http.MethodGet, "/events?token="+secret, nil)
	if checkFEToken(r, secret) {
		t.Error("?token= must not authenticate")
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

func TestAuthLimiterBlocksThenResets(t *testing.T) {
	l := newAuthLimiter()
	for i := 0; i < authFailureLimit; i++ {
		if !l.allow("203.0.113.1") {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
		l.fail("203.0.113.1")
	}
	if l.allow("203.0.113.1") {
		t.Fatal("IP should be blocked after failure limit")
	}
	l.reset("203.0.113.1")
	if !l.allow("203.0.113.1") {
		t.Fatal("successful authentication must clear the bucket")
	}
	if !l.allow("203.0.113.2") {
		t.Fatal("other IPs must not be affected")
	}
}
