package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFETicketSingleUse(t *testing.T) {
	s := newFETicketStore()
	ticket, exp := s.issue("")
	if ticket == "" || !exp.After(time.Now()) {
		t.Fatalf("bad ticket %q exp %v", ticket, exp)
	}
	if _, ok := s.consume(ticket); !ok {
		t.Fatal("first consume should succeed")
	}
	if _, ok := s.consume(ticket); ok {
		t.Fatal("second consume must fail (single-use)")
	}
	if _, ok := s.consume("nope"); ok {
		t.Fatal("unknown ticket must fail")
	}
}

func TestFEAuthTicketAndLegacyToken(t *testing.T) {
	tickets := newFETicketStore()
	auth := feAuth{token: "secret", tickets: tickets}

	// Missing → deny
	r := httptest.NewRequest(http.MethodGet, "/ws/fe", nil)
	if auth.check(r) {
		t.Fatal("missing auth must deny")
	}

	// Ticket
	ticket, _ := tickets.issue("")
	r = httptest.NewRequest(http.MethodGet, "/ws/fe?ticket="+ticket, nil)
	if !auth.check(r) {
		t.Fatal("valid ticket must allow")
	}
	// Burned
	r = httptest.NewRequest(http.MethodGet, "/ws/fe?ticket="+ticket, nil)
	if auth.check(r) {
		t.Fatal("burned ticket must deny")
	}

	// ?token= is no longer an auth channel: long-lived secrets stay out of
	// access logs, so WS auth is the single-use ticket.
	r = httptest.NewRequest(http.MethodGet, "/ws/fe?token=secret", nil)
	if auth.check(r) {
		t.Fatal("?token= must not authenticate")
	}
}

func TestCORSOrigins(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	})
	h := withCORS(inner, []string{"https://app.example"})

	// Allowed origin reflected
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://app.example")
	h.ServeHTTP(rr, req)
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example" {
		t.Errorf("Allow-Origin = %q, want app.example", got)
	}
	// The FE sends Idempotency-Key on mutations; a preflight that does not
	// list it makes the browser drop the header.
	if got := rr.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Idempotency-Key") {
		t.Errorf("Allow-Headers = %q, want it to list Idempotency-Key", got)
	}

	// Disallowed origin not reflected
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://evil.example")
	h.ServeHTTP(rr, req)
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("disallowed origin leaked: %q", got)
	}

	// Open mode (*)
	h2 := withCORS(inner, nil)
	rr = httptest.NewRecorder()
	h2.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("open CORS = %q, want *", got)
	}
}

func TestQuicTLSConfigRequiresCertWhenNotAllowSelfSigned(t *testing.T) {
	t.Setenv("QUIC_CERT", "")
	t.Setenv("QUIC_KEY", "")
	if _, err := quicTLSConfig(false); err == nil {
		t.Fatal("expected error when self-signed disallowed and no cert files")
	}
	cfg, err := quicTLSConfig(true)
	if err != nil || cfg == nil {
		t.Fatalf("self-signed allow: %v cfg=%v", err, cfg)
	}
}

func TestParseCORSOrigins(t *testing.T) {
	if parseCORSOrigins("") != nil || parseCORSOrigins("*") != nil {
		t.Error("empty/* should mean open")
	}
	got := parseCORSOrigins(" https://a.com , https://b.com ")
	if len(got) != 2 || got[0] != "https://a.com" || got[1] != "https://b.com" {
		t.Errorf("got %v", got)
	}
}
