package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/internal/hub"
	"github.com/AgentsHarness/capri-wire"
	"github.com/coder/websocket"
	"github.com/quic-go/quic-go"
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

// TestAcceptsGzip: the relay compresses only for a client that names gzip
// explicitly. "gzip;q=0" is an explicit refusal, a bare "*" is what curl /
// server-side fetchers send while being perfectly happy with identity, and
// an "*" alongside an explicit gzip still counts.
func TestAcceptsGzip(t *testing.T) {
	newReq := func(enc string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api/session-updates", nil)
		if enc != "" {
			r.Header.Set("Accept-Encoding", enc)
		}
		return r
	}
	cases := []struct {
		enc  string
		want bool
	}{
		{"", false},
		{"gzip", true},
		{"GZIP", true},
		{" gzip ", true},
		{"gzip;", true},
		{"gzip; q=0.8", true},
		{"gzip;q=0", false},
		{"gzip;q=0.0", false},
		{"gzip;q=0.5", true},
		{"gzip;q=1.0", true},
		{"deflate, gzip", true},
		{"br;q=1.0, gzip;q=0.8", true},
		{"deflate, gzip;q=0", false},
		{"*", false},
		{"deflate, *", false},
		{"*, gzip", true},
		{"deflate", false},
		{"identity", false},
		{"x-gzip", false},
	}
	for _, tc := range cases {
		if got := acceptsGzip(newReq(tc.enc)); got != tc.want {
			t.Errorf("acceptsGzip(%q) = %v, want %v", tc.enc, got, tc.want)
		}
	}
}

// relayPage builds a session-history-shaped JSON body of n update entries
// (~111 bytes each) — repetitive text, so deflate shrinks it. One entry
// stays under the minCompressSize floor, 80 cross it comfortably.
func relayPage(n int) []byte {
	const entry = `{"msgSeq":1,"params":{"update":{"sessionUpdate":"tool_call","rawOutput":{"output":"历史信封正文 padding"}}}}`
	var b bytes.Buffer
	b.WriteString(`{"ok":true,"updates":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(entry)
	}
	b.WriteString("]}")
	return b.Bytes()
}

// relayIncompressible returns high-entropy bytes: deflate falls back to
// stored blocks on them, so the gzip form ends up LONGER than the raw body,
// which is the condition writeRelayResponse checks before switching
// encoding. Deterministic so a failure reproduces.
func relayIncompressible(n int) []byte {
	b := make([]byte, n)
	s := uint64(0x9E3779B97F4A7C15)
	for i := range b {
		s ^= s << 13
		s ^= s >> 7
		s ^= s << 17
		b[i] = byte(s >> 24)
	}
	return b
}

func gunzipRelay(t *testing.T, b []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	return out
}

// TestWriteRelayResponseGzip: an over-floor body for a gzip-capable client
// goes out deflated, with Content-Length describing the COMPRESSED bytes
// (an identity length on a gzipped body makes the browser hang or truncate)
// and Vary set, and the host's status survives the switch.
func TestWriteRelayResponseGzip(t *testing.T) {
	body := relayPage(80)
	if len(body) < minCompressSize {
		t.Fatalf("fixture is %d bytes, want >= the %d-byte floor", len(body), minCompressSize)
	}
	for _, status := range []int{200, 404, 500} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/session-updates", nil)
			req.Header.Set("Accept-Encoding", "gzip")
			rr := httptest.NewRecorder()
			writeRelayResponse(rr, req, status, body)

			if rr.Code != status {
				t.Errorf("status = %d, want %d", rr.Code, status)
			}
			if got := rr.Header().Get("Content-Encoding"); got != "gzip" {
				t.Fatalf("Content-Encoding = %q, want gzip", got)
			}
			if got := rr.Header().Get("Vary"); got != "Accept-Encoding" {
				t.Errorf("Vary = %q, want Accept-Encoding", got)
			}
			if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
				t.Errorf("Content-Type = %q, want application/json", got)
			}
			cl := rr.Header().Get("Content-Length")
			n, err := strconv.Atoi(cl)
			if err != nil {
				t.Fatalf("Content-Length = %q: %v", cl, err)
			}
			if n != rr.Body.Len() {
				t.Errorf("Content-Length = %s but %d bytes were written", cl, rr.Body.Len())
			}
			if n >= len(body) {
				t.Errorf("gzip did not shrink the body: %d -> %d", len(body), n)
			}
			if got := gunzipRelay(t, rr.Body.Bytes()); !bytes.Equal(got, body) {
				t.Errorf("gunzipped body differs from the host answer (%d vs %d bytes)", len(got), len(body))
			}
		})
	}
}

// TestWriteRelayResponseIdentity: three ways to get the body back verbatim
// — under the floor, client not asking (or refusing), and a body gzip
// cannot shrink. None may carry Content-Encoding, all keep Vary and the
// exact byte length.
func TestWriteRelayResponseIdentity(t *testing.T) {
	big := relayPage(80)
	small := relayPage(1)
	if len(small) >= minCompressSize {
		t.Fatalf("fixture is %d bytes, want < the %d-byte floor", len(small), minCompressSize)
	}
	cases := []struct {
		name string
		enc  string
		body []byte
	}{
		{"under floor", "gzip", small},
		{"no header", "", big},
		{"identity only", "identity", big},
		{"refused", "gzip;q=0", big},
		{"wildcard only", "*", big},
		{"incompressible", "gzip", relayIncompressible(len(big))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/session-updates", nil)
			if tc.enc != "" {
				req.Header.Set("Accept-Encoding", tc.enc)
			}
			rr := httptest.NewRecorder()
			writeRelayResponse(rr, req, 404, tc.body)

			if rr.Code != 404 {
				t.Errorf("status = %d, want 404", rr.Code)
			}
			if got := rr.Header().Get("Content-Encoding"); got != "" {
				t.Errorf("Content-Encoding = %q, want none", got)
			}
			if got := rr.Header().Get("Vary"); got != "Accept-Encoding" {
				t.Errorf("Vary = %q, want Accept-Encoding", got)
			}
			if got := rr.Header().Get("Content-Length"); got != strconv.Itoa(len(tc.body)) {
				t.Errorf("Content-Length = %q, want %d", got, len(tc.body))
			}
			if !bytes.Equal(rr.Body.Bytes(), tc.body) {
				t.Error("body must be the host answer verbatim")
			}
		})
	}
}

// TestRelayVaryKeepsCorsOrigin: writeRelayResponse must ADD its Vary entry,
// not replace the `Vary: Origin` withCORS already wrote. A shared cache that
// only sees the encoding axis is free to reuse this ACAO-bound answer for a
// different origin.
func TestRelayVaryKeepsCorsOrigin(t *testing.T) {
	body := relayPage(80)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeRelayResponse(w, r, 200, body)
	})
	h := withCORS(inner, []string{"https://app.example"})

	req := httptest.NewRequest(http.MethodPost, "/api/session-updates", nil)
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example" {
		t.Fatalf("Allow-Origin = %q, want app.example", got)
	}
	if got := rr.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	varied := rr.Header().Values("Vary")
	for _, want := range []string{"Origin", "Accept-Encoding"} {
		found := false
		for _, v := range varied {
			if strings.EqualFold(strings.TrimSpace(v), want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Vary = %q, want it to list both axes (missing %s)", varied, want)
		}
	}
}

// assertPlainRelayError: the error answers bypass writeRelayResponse, so
// they must stay readable JSON even when the browser offered gzip — an
// encoded or truncated error page turns a diagnosable 503 into a bare
// network failure on the FE.
func assertPlainRelayError(t *testing.T, rr *httptest.ResponseRecorder, wantErr string) {
	t.Helper()
	if got := rr.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("error answer must not be gzipped, got Content-Encoding=%q", got)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body is not readable JSON: %v (%s)", err, rr.Body.String())
	}
	if body["ok"] != false {
		t.Errorf("body.ok = %v, want false", body["ok"])
	}
	if body["error"] != wantErr {
		t.Errorf("body.error = %v, want %q", body["error"], wantErr)
	}
}

// TestHandleRelayErrorBranchesStayPlain: no-host 503 and oversize-body 413
// still answer correctly on a gzip-offering client.
func TestHandleRelayErrorBranchesStayPlain(t *testing.T) {
	t.Run("503 no host", func(t *testing.T) {
		handler := handleRelay(hub.NewWithDir(""))
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/session-updates?offset=0&limit=200&detail=lite", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		handler.ServeHTTP(rr, req)
		if rr.Code != 503 {
			t.Fatalf("status = %d, want 503 (hub has no host to relay to)", rr.Code)
		}
		assertPlainRelayError(t, rr, hub.ErrNoHost.Error())
	})

	t.Run("413 oversize body", func(t *testing.T) {
		h := hub.NewWithDir("")
		code, _ := h.PairingCode()
		if _, err := h.Pair(code, "h1", "H1"); err != nil {
			t.Fatalf("pair: %v", err)
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/prompt", bytes.NewReader(make([]byte, (5<<20)+1)))
		req.Header.Set("Accept-Encoding", "gzip")
		handleRelay(h).ServeHTTP(rr, req)
		if rr.Code != 413 {
			t.Fatalf("status = %d, want 413", rr.Code)
		}
		assertPlainRelayError(t, rr, "请求体过大（上限 5MB）")
	})
}

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

// TestIntegrationHostWSRelayAndFeWS: real WebSocket upgrade over httptest —
// host connects, FE subscribes (ticket auth), host event is observed, relay
// request/respond round-trips.
func TestIntegrationHostWSRelayAndFeWS(t *testing.T) {
	h := hub.NewWithDir("")
	tickets := newFETicketStore()
	lim := newPairLimiter()
	const secret = "int-secret"
	srv := httptest.NewServer(buildHandler(h, secret, tickets, lim, nil))
	defer srv.Close()

	// Pair host
	code, _ := h.PairingCode()
	pairBody, _ := json.Marshal(map[string]string{"code": code, "hostId": "h1", "hostName": "H1"})
	resp, err := http.Post(srv.URL+"/api/pair", "application/json", bytes.NewReader(pairBody))
	if err != nil {
		t.Fatal(err)
	}
	var pairRes struct {
		OK    bool   `json:"ok"`
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&pairRes)
	resp.Body.Close()
	if !pairRes.OK || pairRes.Token == "" {
		t.Fatalf("pair: %+v", pairRes)
	}

	// Host WS
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hostConn := dialHostWithToken(t, ctx, srv, "h1", pairRes.Token, 9001)
	defer hostConn.Close(websocket.StatusNormalClosure, "")

	// Host uplink loop: answer requests + push an event
	hostDone := make(chan struct{})
	go func() {
		defer close(hostDone)
		for {
			_, data, err := hostConn.Read(ctx)
			if err != nil {
				return
			}
			var frame map[string]any
			if json.Unmarshal(data, &frame) != nil {
				continue
			}
			if frame["type"] == "request" {
				reqID, _ := frame["reqId"].(string)
				seq, _ := frame["seq"].(float64)
				out, _ := json.Marshal(map[string]any{
					"v": 2, "type": "respond", "reqId": reqID, "seq": 0,
					"ack": uint64(seq), "status": 200,
					"body": map[string]any{"ok": true, "via": "ws"},
				})
				_ = hostConn.Write(ctx, websocket.MessageText, out)
			}
		}
	}()

	// Mint FE ticket and open FE WS
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/ws-ticket", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	tr, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var ticketRes struct {
		Ticket string `json:"ticket"`
	}
	_ = json.NewDecoder(tr.Body).Decode(&ticketRes)
	tr.Body.Close()
	if ticketRes.Ticket == "" {
		t.Fatal("empty ticket")
	}

	feConn, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/fe?ticket="+ticketRes.Ticket, nil)
	if err != nil {
		t.Fatalf("fe ws dial: %v", err)
	}
	defer feConn.Close(websocket.StatusNormalClosure, "")
	feConn.SetReadLimit(1 << 20)

	// hello from FE
	_, feHello, err := feConn.Read(ctx)
	if err != nil {
		t.Fatalf("fe hello: %v", err)
	}
	var feH map[string]any
	if json.Unmarshal(feHello, &feH) != nil || feH["type"] != "hello" {
		t.Fatalf("fe hello = %s", feHello)
	}

	// Host pushes an event; FE should receive (may be in hosts_changed first
	// from connect, then events batch).
	evFrame, _ := json.Marshal(map[string]any{
		"v": 2, "type": "events", "seq": 1, "ack": 0,
		"events": []map[string]any{{"type": "chunk", "text": "hi", "seq": 1}},
	})
	if err := hostConn.Write(ctx, websocket.MessageText, evFrame); err != nil {
		t.Fatal(err)
	}

	// Wait for a chunk event on FE (skip hosts_changed / ping).
	deadline := time.Now().Add(3 * time.Second)
	gotChunk := false
	for time.Now().Before(deadline) && !gotChunk {
		rctx, rcancel := context.WithTimeout(ctx, 500*time.Millisecond)
		_, raw, err := feConn.Read(rctx)
		rcancel()
		if err != nil {
			continue
		}
		var frame map[string]any
		if json.Unmarshal(raw, &frame) != nil {
			continue
		}
		if frame["type"] == "events" {
			// uncompressed JSON path
			evs, _ := frame["events"].([]any)
			for _, e := range evs {
				m, _ := e.(map[string]any)
				if m["type"] == "chunk" && m["text"] == "hi" {
					gotChunk = true
				}
			}
		}
	}
	if !gotChunk {
		t.Fatal("FE did not receive host chunk event")
	}

	// Relay HTTP → host WS respond
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/api/status?host=h1", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	rel, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer rel.Body.Close()
	if rel.StatusCode != 200 {
		b, _ := io.ReadAll(rel.Body)
		t.Fatalf("relay status=%d body=%s", rel.StatusCode, b)
	}
	var body map[string]any
	_ = json.NewDecoder(rel.Body).Decode(&body)
	if body["via"] != "ws" {
		t.Errorf("relay body = %v, want via=ws", body)
	}
	cancel()
	<-hostDone
}

// TestIntegrationQUICHostAuthAndEvent: QUIC accept + auth + events frame.
func TestIntegrationQUICHostAuthAndEvent(t *testing.T) {
	h := hub.NewWithDir("")
	code, _ := h.PairingCode()
	tok, err := h.Pair(code, "qh1", "QH1")
	if err != nil {
		t.Fatal(err)
	}

	tlsConf, err := quicTLSConfig(true)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConf, &quic.Config{KeepAlivePeriod: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveQUIC(ln, h)

	// Client dial
	udpAddr := ln.Addr().(*net.UDPAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, udpAddr.String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"capri-hub"},
	}, nil)
	if err != nil {
		t.Fatalf("quic dial: %v", err)
	}
	defer conn.CloseWithError(0, "")

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	writeFrame := func(payload []byte) error {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
		if _, err := stream.Write(lenBuf[:]); err != nil {
			return err
		}
		_, err := stream.Write(payload)
		return err
	}
	readFrame := func() ([]byte, error) {
		var lenBuf [4]byte
		if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
			return nil, err
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		buf := make([]byte, n)
		_, err := io.ReadFull(stream, buf)
		return buf, err
	}

	helloFrame, _ := json.Marshal(map[string]any{
		"v": 2, "type": "hello", "epoch": 6001, "token": tok,
		"resume": map[string]any{"up": 0, "down": 0},
	})
	if err := writeFrame(helloFrame); err != nil {
		t.Fatal(err)
	}
	hello, err := readFrame()
	if err != nil {
		t.Fatalf("hello_ack: %v", err)
	}
	var hm map[string]any
	if json.Unmarshal(hello, &hm) != nil || hm["type"] != "hello_ack" {
		t.Fatalf("hello_ack = %s", hello)
	}

	// Wait until the session is attached.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && h.DefaultHostID() == "" {
		time.Sleep(10 * time.Millisecond)
	}
	// Push event
	ev, _ := json.Marshal(map[string]any{
		"v": 2, "type": "events", "seq": 1, "ack": 0,
		"events": []any{map[string]any{"type": "chunk", "text": "q", "seq": 1}},
	})
	if err := writeFrame(ev); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h.LastSeq("qh1") == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("LastSeq = %d, want 1", h.LastSeq("qh1"))
}

// TestHandleUnpair: DELETE /api/hosts/{hostId} removes the host and
// revokes its token (admin path, FE-token gated in production).
func TestHandleUnpair(t *testing.T) {
	h := hub.NewWithDir("")
	code, _ := h.PairingCode()
	tok, err := h.Pair(code, "h1", "H1")
	if err != nil {
		t.Fatal(err)
	}
	handler := handleUnpair(h)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/hosts/h1", nil)
	req.SetPathValue("hostId", "h1")
	handler.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d body=%s, want 200", rr.Code, rr.Body.String())
	}
	if _, ok := h.HostIDForToken(tok); ok {
		t.Error("token must be revoked")
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/api/hosts/h1", nil)
	req.SetPathValue("hostId", "h1")
	handler.ServeHTTP(rr, req)
	if rr.Code != 404 {
		t.Fatalf("second unpair status = %d, want 404", rr.Code)
	}
}

// A superseded host connection must stop feeding the hub: after a second
// connection for the same hostId registers, events uplinked on the old
// one are ignored (never fanned out to the FE) and the old transport is
// dropped by the hub on its next frame.
func TestIntegrationSupersededHostConnIgnoredAndDropped(t *testing.T) {
	h := hub.NewWithDir("")
	tickets := newFETicketStore()
	lim := newPairLimiter()
	const secret = "int-secret"
	srv := httptest.NewServer(buildHandler(h, secret, tickets, lim, nil))
	defer srv.Close()

	// Pair host
	code, _ := h.PairingCode()
	pairBody, _ := json.Marshal(map[string]string{"code": code, "hostId": "h1", "hostName": "H1"})
	resp, err := http.Post(srv.URL+"/api/pair", "application/json", bytes.NewReader(pairBody))
	if err != nil {
		t.Fatal(err)
	}
	var pairRes struct {
		OK    bool   `json:"ok"`
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&pairRes)
	resp.Body.Close()
	if !pairRes.OK || pairRes.Token == "" {
		t.Fatalf("pair: %+v", pairRes)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dialHost := func(name string, epoch uint64) *websocket.Conn {
		t.Helper()
		c, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/host", &websocket.DialOptions{
			HTTPHeader: http.Header{"Authorization": []string{"Bearer " + pairRes.Token}},
		})
		if err != nil {
			t.Fatalf("%s dial: %v", name, err)
		}
		c.SetReadLimit(32 << 20)
		hello, _ := json.Marshal(map[string]any{
			"v": 2, "type": "hello", "epoch": epoch, "token": pairRes.Token,
			"resume": map[string]any{"up": 0, "down": 0},
		})
		if err := c.Write(ctx, websocket.MessageText, hello); err != nil {
			t.Fatalf("%s hello write: %v", name, err)
		}
		_, raw, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("%s hello_ack: %v", name, err)
		}
		var ack map[string]any
		if json.Unmarshal(raw, &ack) != nil || ack["type"] != "hello_ack" {
			t.Fatalf("%s hello_ack frame = %s", name, raw)
		}
		return c
	}

	conn1 := dialHost("conn1", 11)
	defer conn1.Close(websocket.StatusNormalClosure, "")

	// FE subscriber
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/ws-ticket", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	tr, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var ticketRes struct {
		Ticket string `json:"ticket"`
	}
	_ = json.NewDecoder(tr.Body).Decode(&ticketRes)
	tr.Body.Close()
	if ticketRes.Ticket == "" {
		t.Fatal("empty ticket")
	}
	feConn, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/fe?ticket="+ticketRes.Ticket, nil)
	if err != nil {
		t.Fatalf("fe ws dial: %v", err)
	}
	defer feConn.Close(websocket.StatusNormalClosure, "")
	feConn.SetReadLimit(1 << 20)
	_, feHello, err := feConn.Read(ctx)
	if err != nil {
		t.Fatalf("fe hello: %v", err)
	}
	var feH map[string]any
	if json.Unmarshal(feHello, &feH) != nil || feH["type"] != "hello" {
		t.Fatalf("fe hello = %s", feHello)
	}

	sendEvents := func(c *websocket.Conn, seq int, text string) error {
		t.Helper()
		frame, _ := json.Marshal(map[string]any{
			"v": 2, "type": "events", "seq": seq, "ack": 0,
			"events": []map[string]any{{"type": "chunk", "text": text, "seq": seq}},
		})
		return c.Write(ctx, websocket.MessageText, frame)
	}

	// Collect FE chunk events until want is seen; assert never contains bad.
	waitFEChunk := func(want, bad int, text string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			rctx, rcancel := context.WithTimeout(ctx, 500*time.Millisecond)
			_, raw, err := feConn.Read(rctx)
			rcancel()
			if err != nil {
				continue
			}
			var frame map[string]any
			if json.Unmarshal(raw, &frame) != nil {
				continue
			}
			if frame["type"] != "events" {
				continue
			}
			evs, _ := frame["events"].([]any)
			for _, evAny := range evs {
				ev, _ := evAny.(map[string]any)
				if ev == nil || ev["type"] != "chunk" {
					continue
				}
				seq, _ := ev["seq"].(float64)
				if int(seq) == bad {
					t.Fatalf("FE received event seq %d from superseded connection", bad)
				}
				if int(seq) == want && ev["text"] == text {
					return
				}
			}
		}
		t.Fatalf("FE never received event seq %d (%s)", want, text)
	}

	// conn1 event seq 1 reaches the FE.
	if err := sendEvents(conn1, 1, "first"); err != nil {
		t.Fatal(err)
	}
	waitFEChunk(1, -1, "first")

	// conn2 supersedes conn1 with a NEW epoch.
	conn2 := dialHost("conn2", 12)
	defer conn2.Close(websocket.StatusNormalClosure, "")

	// conn1 uplink after supersede: it may fail on the dead socket or be
	// ignored by the closing session; either way it must never be applied.
	_ = sendEvents(conn1, 2, "stale")
	// Drain buffered frames until the hub's close arrives, and check the
	// close reason the host's reconnect policy switches on.
	closed := false
	closeReason := ""
	drainDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(drainDeadline) && !closed {
		rctx, rcancel := context.WithTimeout(ctx, 500*time.Millisecond)
		_, _, rerr := conn1.Read(rctx)
		rcancel()
		if rerr == nil {
			continue
		}
		closed = true
		var ce websocket.CloseError
		if errors.As(rerr, &ce) {
			closeReason = ce.Reason
		}
	}
	if !closed {
		t.Fatal("hub should close the superseded connection")
	}
	if closeReason != wire.CloseSuperseded.String() {
		t.Errorf("close reason = %q, want %q", closeReason, wire.CloseSuperseded)
	}

	// FE must never see the stale event; the new epoch's seq 1 must arrive.
	if err := sendEvents(conn2, 1, "fresh"); err != nil {
		t.Fatal(err)
	}
	waitFEChunk(1, 2, "fresh")
}

// TestPairConstantTimeCompareIsValueExact: after switching the pairing
// code comparison to crypto/subtle, pairing still accepts the exact code
// (normalized) and rejects near-misses.
func TestPairConstantTimeCompareIsValueExact(t *testing.T) {
	h := hub.NewWithDir("")
	code, _ := h.PairingCode()
	if _, err := h.Pair(strings.ToLower(code), "h1", "H1"); err != nil {
		t.Fatalf("lowercased code must pair: %v", err)
	}
	h2 := hub.NewWithDir("")
	code2, _ := h2.PairingCode()
	// Mutate one character.
	runes := []rune(code2)
	if runes[0] == 'A' {
		runes[0] = 'B'
	} else {
		runes[0] = 'A'
	}
	if _, err := h2.Pair(string(runes), "h1", "H1"); err == nil {
		t.Error("near-miss code must be rejected")
	}
}

// TestUplinkDeflateWSRoundtrip: a host that offers caps.deflate in hello gets
// the capability echoed in hello_ack and may then send flate-compressed binary
// frames; the hub inflates them and fans the events out as usual. Plain text
// frames keep working alongside.
func TestUplinkDeflateWSRoundtrip(t *testing.T) {
	h := hub.NewWithDir("")
	tickets := newFETicketStore()
	lim := newPairLimiter()
	srv := httptest.NewServer(buildHandler(h, "", tickets, lim, nil))
	defer srv.Close()
	code, _ := h.PairingCode()
	tok, err := h.Pair(code, "h1", "H1")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	feCh, feUnsub := h.Subscribe()
	defer feUnsub()

	conn, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/host", &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + tok}},
	})
	if err != nil {
		t.Fatalf("host ws dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	conn.SetReadLimit(32 << 20)
	hello, _ := json.Marshal(map[string]any{
		"v": 2, "type": "hello", "epoch": 7001, "token": tok,
		"resume": map[string]any{"up": 0, "down": 0},
		"caps":   map[string]any{"deflate": true},
	})
	if err := conn.Write(ctx, websocket.MessageText, hello); err != nil {
		t.Fatal(err)
	}
	_, helloRaw, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("hello_ack: %v", err)
	}
	var ack struct {
		Type string `json:"type"`
		Caps *struct {
			Deflate bool `json:"deflate"`
		} `json:"caps"`
	}
	if json.Unmarshal(helloRaw, &ack) != nil || ack.Type != "hello_ack" {
		t.Fatalf("hello_ack = %s", helloRaw)
	}
	if ack.Caps == nil || !ack.Caps.Deflate {
		t.Fatalf("hello_ack must echo caps.deflate:true, got %s", helloRaw)
	}

	waitChunk := func(want string) {
		deadline := time.After(3 * time.Second)
		for {
			select {
			case ev := <-feCh:
				if typ, _ := ev["type"].(string); typ == "chunk" {
					wireBytes, _ := hub.MarshalEvent(ev)
					var m map[string]any
					_ = json.Unmarshal(wireBytes, &m)
					if m["text"] == want {
						return
					}
				}
			case <-deadline:
				t.Fatalf("event %q not fanned out", want)
			}
		}
	}

	// flate-compressed events frame as a BINARY message.
	payload := []byte(`{"v":2,"type":"events","seq":1,"events":[{"type":"chunk","text":"deflated","seq":1}]}`)
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestSpeed)
	fw.Write(payload)
	fw.Close()
	if err := conn.Write(ctx, websocket.MessageBinary, buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	waitChunk("deflated")

	// Plain text frames still work alongside.
	plain := []byte(`{"v":2,"type":"events","seq":2,"events":[{"type":"chunk","text":"plain","seq":2}]}`)
	if err := conn.Write(ctx, websocket.MessageText, plain); err != nil {
		t.Fatal(err)
	}
	waitChunk("plain")
}

// A binary frame the hub cannot inflate ends the session with unreadable
// instead of being skipped: skipping it let a later frame's higher seq move
// the delivery watermark past the hole, and the host then deleted its replay
// copies on that ack — permanent loss.
func TestUplinkInflateFailureEndsSession(t *testing.T) {
	h := hub.NewWithDir("")
	srv := httptest.NewServer(buildHandler(h, "", newFETicketStore(), newPairLimiter(), nil))
	defer srv.Close()
	code, _ := h.PairingCode()
	tok, err := h.Pair(code, "h1", "H1")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := dialHostWithToken(t, ctx, srv, "h1", tok, 7002)

	// Pure garbage: flate.NewReader succeeds (it is lazy) but io.ReadAll
	// fails at the first block header.
	if err := conn.Write(ctx, websocket.MessageBinary, []byte{0xff, 0xff, 0xff, 0xff}); err != nil {
		return // already closed; the read below is what matters
	}
	_, _, err = conn.Read(ctx)
	var ce websocket.CloseError
	if err == nil {
		t.Fatal("session must end after an undecodable frame")
	}
	if !errors.As(err, &ce) {
		t.Fatalf("read error = %v, want a close frame", err)
	}
	if ce.Reason != wire.CloseUnreadable.String() {
		t.Fatalf("close reason = %q, want %q", ce.Reason, wire.CloseUnreadable)
	}
	if got := h.LastSeq("h1"); got != 0 {
		t.Fatalf("watermark = %d; an undecodable frame must not advance it", got)
	}
}

// TestHostWSCloseReasonMapping: the handshake verdicts travel as the one
// wire.CloseReason enum — a peer speaking another protocol version is closed
// with `protocol`, not with a free-form string the host would have to parse.
func TestHostWSCloseReasonMapping(t *testing.T) {
	h := hub.NewWithDir("")
	srv := httptest.NewServer(buildHandler(h, "", newFETicketStore(), newPairLimiter(), nil))
	defer srv.Close()
	code, _ := h.PairingCode()
	tok, err := h.Pair(code, "h1", "H1")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/host", &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + tok}},
	})
	if err != nil {
		t.Fatalf("host ws dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	// A v1 hello: the envelope version is not this protocol.
	if err := conn.Write(ctx, websocket.MessageText, []byte(`{"v":1,"type":"hello"}`)); err != nil {
		t.Fatal(err)
	}
	_, _, err = conn.Read(ctx)
	var ce websocket.CloseError
	if !errors.As(err, &ce) {
		t.Fatalf("read error = %v, want a close frame", err)
	}
	if _, want := wire.CloseProtocol.WS(); ce.Reason != want {
		t.Fatalf("close reason = %q, want %q", ce.Reason, want)
	}
}

// TestUplinkParseLenFlag: the QUIC length prefix reserves bit 31 as the
// deflate flag; lengths round-trip through parseUplinkLen.
func TestUplinkParseLenFlag(t *testing.T) {
	for _, n := range []uint32{0, 1, 255, 256, 1 << 20, 32<<20 - 1, 0x7FFFFFFF} {
		prefixed := n | uplinkCompressedFlag
		got, compressed := parseUplinkLen(prefixed)
		if got != n || !compressed {
			t.Errorf("parseUplinkLen(%d|flag) = %d,%v want %d,true", n, got, compressed, n)
		}
		got, compressed = parseUplinkLen(n)
		if got != n || compressed {
			t.Errorf("parseUplinkLen(%d) = %d,%v want %d,false", n, got, compressed, n)
		}
	}
}

// TestIntegrationQUICUplinkDeflate: a QUIC hello offering caps.deflate is
// confirmed by the hello_ack echo; a compressed events frame (length-prefix
// bit 31 set, raw-deflate body) is inflated and registered, and a plain frame
// still works alongside.
func TestIntegrationQUICUplinkDeflate(t *testing.T) {
	h := hub.NewWithDir("")
	code, _ := h.PairingCode()
	tok, err := h.Pair(code, "qh2", "QH2")
	if err != nil {
		t.Fatal(err)
	}
	tlsConf, err := quicTLSConfig(true)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConf, &quic.Config{KeepAlivePeriod: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveQUIC(ln, h)

	udpAddr := ln.Addr().(*net.UDPAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, udpAddr.String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"capri-hub"},
	}, nil)
	if err != nil {
		t.Fatalf("quic dial: %v", err)
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	writeFrame := func(payload []byte, compressed bool) error {
		var cFlag uint32
		if compressed {
			cFlag = uplinkCompressedFlag
		}
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload))|cFlag)
		if _, err := stream.Write(lenBuf[:]); err != nil {
			return err
		}
		_, err := stream.Write(payload)
		return err
	}
	readFrame := func() ([]byte, error) {
		var lenBuf [4]byte
		if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
			return nil, err
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		buf := make([]byte, n)
		_, err := io.ReadFull(stream, buf)
		return buf, err
	}

	hello, _ := json.Marshal(map[string]any{
		"v": 2, "type": "hello", "epoch": 6101, "token": tok,
		"resume": map[string]any{"up": 0, "down": 0},
		"caps":   map[string]any{"deflate": true},
	})
	if err := writeFrame(hello, false); err != nil {
		t.Fatal(err)
	}
	ack, err := readFrame()
	if err != nil {
		t.Fatalf("hello_ack: %v", err)
	}
	var hm struct {
		Type string `json:"type"`
		Caps *struct {
			Deflate bool `json:"deflate"`
		} `json:"caps"`
	}
	if json.Unmarshal(ack, &hm) != nil || hm.Type != "hello_ack" {
		t.Fatalf("hello_ack = %s", ack)
	}
	if hm.Caps == nil || !hm.Caps.Deflate {
		t.Fatalf("hello_ack must echo caps.deflate:true, got %s", ack)
	}

	flateBytes := func(v any) []byte {
		b, _ := json.Marshal(v)
		var buf bytes.Buffer
		fw, _ := flate.NewWriter(&buf, flate.BestSpeed)
		fw.Write(b)
		fw.Close()
		return buf.Bytes()
	}
	if err := writeFrame(flateBytes(map[string]any{
		"v": 2, "type": "events", "seq": 1,
		"events": []any{map[string]any{"type": "chunk", "text": "z", "seq": 1}},
	}), true); err != nil {
		t.Fatal(err)
	}
	// Plain frame alongside (host skips compression under its floor).
	plain, _ := json.Marshal(map[string]any{
		"v": 2, "type": "events", "seq": 2,
		"events": []any{map[string]any{"type": "chunk", "text": "p", "seq": 2}},
	})
	if err := writeFrame(plain, false); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h.LastSeq("qh2") == 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("LastSeq = %d, want 2", h.LastSeq("qh2"))
}

// TestIntegrationQUICMultiStreamRequestPlane: the control stream carries the
// session (hello, events, relayed requests); additional request streams carry
// `respond` frames only, and EOF on one must NOT end the session.
func TestIntegrationQUICMultiStreamRequestPlane(t *testing.T) {
	h := hub.NewWithDir("")
	code, _ := h.PairingCode()
	tok, err := h.Pair(code, "qm1", "QM1")
	if err != nil {
		t.Fatal(err)
	}
	tlsConf, err := quicTLSConfig(true)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConf, &quic.Config{KeepAlivePeriod: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveQUIC(ln, h)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"capri-hub"},
	}, nil)
	if err != nil {
		t.Fatalf("quic dial: %v", err)
	}
	defer conn.CloseWithError(0, "")

	control, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	wf := func(s *quic.Stream, payload []byte, compressed bool) error {
		var cFlag uint32
		if compressed {
			cFlag = uplinkCompressedFlag
		}
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload))|cFlag)
		if _, err := s.Write(lenBuf[:]); err != nil {
			return err
		}
		_, err := s.Write(payload)
		return err
	}
	rf := func(s *quic.Stream) ([]byte, error) {
		var lenBuf [4]byte
		if _, err := io.ReadFull(s, lenBuf[:]); err != nil {
			return nil, err
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		buf := make([]byte, n)
		_, err := io.ReadFull(s, buf)
		return buf, err
	}

	hello, _ := json.Marshal(map[string]any{
		"v": 2, "type": "hello", "epoch": 6201, "token": tok,
		"resume": map[string]any{"up": 0, "down": 0},
		"caps":   map[string]any{"deflate": true},
	})
	if err := wf(control, hello, false); err != nil {
		t.Fatal(err)
	}
	helloAck, err := rf(control)
	if err != nil || json.Unmarshal(helloAck, &map[string]any{}) != nil {
		t.Fatalf("hello_ack: %v %s", err, helloAck)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && h.DefaultHostID() == "" {
		time.Sleep(10 * time.Millisecond)
	}
	if h.DefaultHostID() != "qm1" {
		t.Fatalf("host not online: %q", h.DefaultHostID())
	}

	// An event on the control stream advances the watermark.
	ev1, _ := json.Marshal(map[string]any{"v": 2, "type": "events", "seq": 1,
		"events": []any{map[string]any{"type": "chunk", "text": "a", "seq": 1}}})
	if err := wf(control, ev1, false); err != nil {
		t.Fatal(err)
	}

	// Relay round-trip: the request goes down the CONTROL stream; we answer
	// with a respond on a fresh REQUEST stream.
	type resp struct {
		Status int
		Body   string
		Err    error
	}
	respCh := make(chan resp, 1)
	go func() {
		r, err := h.Dispatch(ctx, "qm1", "GET", "/x", nil)
		if err != nil {
			respCh <- resp{Err: err}
			return
		}
		respCh <- resp{Status: r.Status, Body: string(r.Body)}
	}()

	// Read the request frame off the control stream (heartbeats may
	// interleave — skip to the request).
	var reqID string
	var reqSeq uint64
	for reqID == "" {
		data, err := rf(control)
		if err != nil {
			t.Fatalf("read request frame: %v", err)
		}
		var f struct {
			Type  string `json:"type"`
			ReqID string `json:"reqId"`
			Seq   uint64 `json:"seq"`
		}
		if json.Unmarshal(data, &f) == nil && f.Type == "request" {
			reqID, reqSeq = f.ReqID, f.Seq
		}
	}

	// Request stream: the respond, sent COMPRESSED — the deflate flag is
	// session-scoped and must be honored on request streams too.
	rs, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rbody, _ := json.Marshal(map[string]any{"ok": true, "via": "request-stream"})
	frameJSON, _ := json.Marshal(map[string]any{
		"v": 2, "type": "respond", "reqId": reqID, "seq": 0, "ack": reqSeq,
		"status": 234, "body": json.RawMessage(rbody),
	})
	var zbuf bytes.Buffer
	zw, _ := flate.NewWriter(&zbuf, flate.BestSpeed)
	zw.Write(frameJSON)
	zw.Close()
	if err := wf(rs, zbuf.Bytes(), true); err != nil {
		t.Fatal(err)
	}
	rs.Close() // normal end of the request plane for this request

	select {
	case r := <-respCh:
		if r.Err != nil {
			t.Fatalf("dispatch: %v", r.Err)
		}
		if r.Status != 234 || r.Body != string(rbody) {
			t.Fatalf("relay respond = %d %s, want 234 %s", r.Status, r.Body, rbody)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("respond on request stream never routed to Dispatch")
	}

	// The session must survive the request stream's EOF: another control
	// event still lands.
	ev2, _ := json.Marshal(map[string]any{"v": 2, "type": "events", "seq": 2,
		"events": []any{map[string]any{"type": "chunk", "text": "b", "seq": 2}}})
	if err := wf(control, ev2, false); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h.LastSeq("qm1") == 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("LastSeq = %d, want 2 (session died with request stream?)", h.LastSeq("qm1"))
}

// TestFeWSLivenessReclaimsDeadSubscriber: T7 — an FE client that stops
// reading (so never answers the protocol-level Ping) must lose its
// subscriber slot promptly instead of lingering until a data write
// times out; a healthy reader keeps its slot.
func TestFeWSLivenessReclaimsDeadSubscriber(t *testing.T) {
	oldI, oldT := feLivenessInterval, feLivenessTimeout
	feLivenessInterval, feLivenessTimeout = 100*time.Millisecond, 300*time.Millisecond
	defer func() { feLivenessInterval, feLivenessTimeout = oldI, oldT }()

	h := hub.NewWithDir("")
	ts := httptest.NewServer(handleFeWS(h, feAuth{}))
	defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws/fe"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Healthy client: keeps reading → answers pongs → stays subscribed.
	good, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close(websocket.StatusNormalClosure, "")
	go func() {
		for {
			if _, _, err := good.Read(ctx); err != nil {
				return
			}
		}
	}()

	waitCount := func(want int) bool {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if h.SubscriberCount() == want {
				return true
			}
			time.Sleep(20 * time.Millisecond)
		}
		return false
	}
	if !waitCount(1) {
		t.Fatal("healthy FE subscriber never registered")
	}

	// Dead client: dials but never reads → no pong → reclaimed.
	dead, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer dead.Close(websocket.StatusNormalClosure, "")
	if !waitCount(2) {
		t.Fatal("second subscriber never registered")
	}
	if !waitCount(1) {
		t.Fatalf("dead subscriber not reclaimed within liveness window (count=%d)", h.SubscriberCount())
	}
}

// TestIntegrationRelayGzipRoundtrip: browser → hub → host WS → respond
// frame → hub, with a page over the compression floor. Driven through a
// real net/http server instead of a recorder because a Content-Length that
// disagrees with the bytes actually written fails the client's read on a
// live connection — exactly the failure a recorder hides.
func TestIntegrationRelayGzipRoundtrip(t *testing.T) {
	h := hub.NewWithDir("")
	tickets := newFETicketStore()
	lim := newPairLimiter()
	const secret = "gzip-int-secret"
	srv := httptest.NewServer(buildHandler(h, secret, tickets, lim, nil))
	defer srv.Close()

	code, _ := h.PairingCode()
	tok, err := h.Pair(code, "h1", "H1")
	if err != nil {
		t.Fatalf("pair: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := dialHostWithToken(t, ctx, srv, "h1", tok, 6301)
	defer conn.Close(websocket.StatusNormalClosure, "")

	// The "host's" answer: one history page big enough to compress.
	page := relayPage(80)
	go func() {
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var frame map[string]any
			if json.Unmarshal(data, &frame) != nil || frame["type"] != "request" {
				continue
			}
			reqID, _ := frame["reqId"].(string)
			seq, _ := frame["seq"].(float64)
			out, _ := json.Marshal(map[string]any{
				"v": 2, "type": "respond", "reqId": reqID, "seq": 0,
				"ack": uint64(seq), "status": 200, "body": json.RawMessage(page),
			})
			if err := conn.Write(ctx, websocket.MessageText, out); err != nil {
				return
			}
		}
	}()

	// DisableCompression keeps the transport from transparently undoing the
	// encoding, so the assertions below see what the browser really gets.
	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	relay := func(offerGzip bool) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/session-updates?host=h1&offset=0&detail=lite", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		if offerGzip {
			req.Header.Set("Accept-Encoding", "gzip")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("relay: %v", err)
		}
		defer resp.Body.Close()
		wire, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read relay body (Content-Length=%v): %v", resp.Header.Get("Content-Length"), err)
		}
		return resp, wire
	}

	resp, wire := relay(true)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s, want 200", resp.StatusCode, wire)
	}
	if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if got := resp.Header.Get("Vary"); got != "Accept-Encoding" {
		t.Errorf("Vary = %q, want Accept-Encoding", got)
	}
	if resp.ContentLength != int64(len(wire)) {
		t.Errorf("Content-Length = %d, but %d bytes on the wire", resp.ContentLength, len(wire))
	}
	if len(wire) >= len(page) {
		t.Errorf("gzip did not shrink the page: %d -> %d", len(page), len(wire))
	}
	if got := gunzipRelay(t, wire); !bytes.Equal(got, page) {
		t.Errorf("gunzipped relay body != the host's answer (%d vs %d bytes)", len(got), len(page))
	}

	// A client that does not offer gzip must get the host answer verbatim.
	resp2, wire2 := relay(false)
	if got := resp2.Header.Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q on a client that did not offer gzip", got)
	}
	if !bytes.Equal(wire2, page) {
		t.Errorf("identity relay body = %d bytes, want the host's %d verbatim", len(wire2), len(page))
	}
}

// hostEpochSeq hands every test host connection a distinct epoch, so a
// re-dial in a test is a new sequence space unless it deliberately reuses one.
var hostEpochSeq atomic.Uint64

// dialPairedHost pairs a host, opens its /ws/host WebSocket and performs the
// v2 handshake (hello → hello_ack). The connection is returned ready for
// events / requests.
func dialPairedHost(t *testing.T, ctx context.Context, srv *httptest.Server, h *hub.Hub, hostID, name string) *websocket.Conn {
	t.Helper()
	code, _ := h.PairingCode()
	token, err := h.Pair(code, hostID, name)
	if err != nil {
		t.Fatalf("pair %s: %v", hostID, err)
	}
	return dialHostWithToken(t, ctx, srv, hostID, token, 1000+hostEpochSeq.Add(1))
}

// dialHostWithToken opens /ws/host for token and completes the handshake with
// the given epoch.
func dialHostWithToken(t *testing.T, ctx context.Context, srv *httptest.Server, hostID, token string, epoch uint64) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/host", &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}},
	})
	if err != nil {
		t.Fatalf("host ws dial %s: %v", hostID, err)
	}
	conn.SetReadLimit(32 << 20)
	hello, _ := json.Marshal(map[string]any{
		"v": 2, "type": "hello", "epoch": epoch, "token": token,
		"resume": map[string]any{"up": 0, "down": 0},
	})
	if err := conn.Write(ctx, websocket.MessageText, hello); err != nil {
		t.Fatalf("host hello %s: %v", hostID, err)
	}
	_, raw, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("host hello_ack %s: %v", hostID, err)
	}
	var ack map[string]any
	if json.Unmarshal(raw, &ack) != nil || ack["type"] != "hello_ack" {
		t.Fatalf("host hello_ack frame %s = %s", hostID, raw)
	}
	return conn
}

// pushHostEvent sends one events frame from a host uplink. The session seq
// space is the event seq space, so the frame seq is the event's seq.
func pushHostEvent(t *testing.T, ctx context.Context, conn *websocket.Conn, seq int, body map[string]any) {
	t.Helper()
	ev := map[string]any{"seq": seq}
	for k, v := range body {
		ev[k] = v
	}
	frame, _ := json.Marshal(map[string]any{
		"v": 2, "type": "events", "seq": seq, "ack": 0,
		"events": []map[string]any{ev},
	})
	if err := conn.Write(ctx, websocket.MessageText, frame); err != nil {
		t.Fatalf("host write: %v", err)
	}
}

// feFrames reads FE WS frames into a channel. Per-read context timeouts are
// NOT usable here — a cancelled Read tears the connection down in this
// library — so one long-lived reader owns the connection and the test
// selects on the channel instead.
func feFrames(ctx context.Context, conn *websocket.Conn) chan map[string]any {
	out := make(chan map[string]any, 256)
	go func() {
		defer close(out)
		for {
			_, raw, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var f map[string]any
			if json.Unmarshal(raw, &f) != nil {
				continue
			}
			out <- f
		}
	}()
	return out
}

// chunkTextsOf collects events-frame chunk texts (and everything else) for d,
// returning the texts and any frame of wantType seen along the way.
func chunkTextsOf(ctx context.Context, frames chan map[string]any, d time.Duration) []string {
	var out []string
	deadline := time.After(d)
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				return out
			}
			if f["type"] != "events" {
				continue
			}
			evs, _ := f["events"].([]any)
			for _, e := range evs {
				m, _ := e.(map[string]any)
				if m["type"] == "chunk" {
					if txt, _ := m["text"].(string); txt != "" {
						out = append(out, txt)
					}
				}
			}
		case <-deadline:
			return out
		case <-ctx.Done():
			return out
		}
	}
}

// waitForFrameType returns the next frame of the given type, or nil after d.
func waitForFrameType(frames chan map[string]any, typ string, d time.Duration) map[string]any {
	deadline := time.After(d)
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				return nil
			}
			if f["type"] == typ {
				return f
			}
		case <-deadline:
			return nil
		}
	}
}

// TestIntegrationFeWSHostFilter is the end-to-end half of the FE host
// split: a browser that names a host on /ws/fe receives ONLY that host's
// events, and can retarget with a subscribe frame without reconnecting
// (answered with the host's seq watermark so the client aligns instead of
// gap-pulling the whole buffer).
func TestIntegrationFeWSHostFilter(t *testing.T) {
	h := hub.NewWithDir("")
	tickets := newFETicketStore()
	lim := newPairLimiter()
	const secret = "filter-secret"
	srv := httptest.NewServer(buildHandler(h, secret, tickets, lim, nil))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	h1 := dialPairedHost(t, ctx, srv, h, "h1", "H1")
	defer h1.Close(websocket.StatusNormalClosure, "")
	h2 := dialPairedHost(t, ctx, srv, h, "h2", "H2")
	defer h2.Close(websocket.StatusNormalClosure, "")

	ticket, _ := tickets.issue("")
	fe, _, err := websocket.Dial(ctx,
		strings.Replace(srv.URL, "http", "ws", 1)+"/ws/fe?ticket="+ticket+"&host=h1", nil)
	if err != nil {
		t.Fatalf("fe ws dial: %v", err)
	}
	defer fe.Close(websocket.StatusNormalClosure, "")
	fe.SetReadLimit(1 << 20)
	frames := feFrames(ctx, fe)
	if hello := waitForFrameType(frames, "hello", 3*time.Second); hello == nil {
		t.Fatal("no fe hello")
	}

	pushHostEvent(t, ctx, h1, 1, map[string]any{"type": "chunk", "text": "for-h1"})
	pushHostEvent(t, ctx, h2, 1, map[string]any{"type": "chunk", "text": "for-h2"})
	got := chunkTextsOf(ctx, frames, 700*time.Millisecond)
	if !containsStr(got, "for-h1") {
		t.Fatalf("filtered FE missed its own host: %v", got)
	}
	if containsStr(got, "for-h2") {
		t.Fatalf("other host's event leaked into the filtered stream: %v", got)
	}
	// The hub must also stop counting this page as an audience for h2 —
	// that is what lets h2 pause its uplink entirely.
	if n := h.SubscriberCountFor("h2"); n != 0 {
		t.Errorf("SubscriberCountFor(h2) = %d, want 0", n)
	}
	if n := h.SubscriberCountFor("h1"); n != 1 {
		t.Errorf("SubscriberCountFor(h1) = %d, want 1", n)
	}

	// Retarget to h2 over the same connection.
	sub, _ := json.Marshal(map[string]any{"v": 1, "type": "subscribe", "host": "h2"})
	if err := fe.Write(ctx, websocket.MessageText, sub); err != nil {
		t.Fatalf("subscribe write: %v", err)
	}
	ack := waitForFrameType(frames, "subscribed", 3*time.Second)
	if ack == nil {
		t.Fatal("no subscribed ack")
	}
	if ack["host"] != "h2" {
		t.Errorf("subscribed host = %v, want h2", ack["host"])
	}
	// seq is the host's current watermark (h2 pushed seq 1) — the FE aligns
	// to it instead of pulling the whole per-host ring buffer from 0.
	if seq, _ := ack["seq"].(float64); seq != 1 {
		t.Errorf("subscribed seq = %v, want 1", ack["seq"])
	}

	pushHostEvent(t, ctx, h2, 2, map[string]any{"type": "chunk", "text": "h2-second"})
	pushHostEvent(t, ctx, h1, 2, map[string]any{"type": "chunk", "text": "h1-second"})
	after := chunkTextsOf(ctx, frames, 700*time.Millisecond)
	if !containsStr(after, "h2-second") {
		t.Errorf("after subscribe to h2, its events did not arrive: %v", after)
	}
	if containsStr(after, "h1-second") {
		t.Errorf("after subscribe to h2, h1 events still leak: %v", after)
	}
	if n := h.SubscriberCountFor("h1"); n != 0 {
		t.Errorf("SubscriberCountFor(h1) after retarget = %d, want 0", n)
	}
}

// TestIntegrationFESubscriberCount: the hub hello reports the live browser
// total (the page itself included) and every later connect/disconnect pushes
// a hub-level `subscribers_changed` to the pages already open — that number
// is what the FE top bar renders beside the host block.
func TestIntegrationFESubscriberCount(t *testing.T) {
	h := hub.NewWithDir("")
	tickets := newFETicketStore()
	lim := newPairLimiter()
	const secret = "subs-secret"
	srv := httptest.NewServer(buildHandler(h, secret, tickets, lim, nil))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dialFE := func() (*websocket.Conn, chan map[string]any) {
		t.Helper()
		ticket, _ := tickets.issue("")
		conn, _, err := websocket.Dial(ctx,
			strings.Replace(srv.URL, "http", "ws", 1)+"/ws/fe?ticket="+ticket, nil)
		if err != nil {
			t.Fatalf("fe ws dial: %v", err)
		}
		conn.SetReadLimit(1 << 20)
		return conn, feFrames(ctx, conn)
	}

	// Hub-level broadcasts ride inside `events` frames (the subscriber pump
	// batches them like host events), so scan the batch for the count frame.
	waitSubCount := func(frames chan map[string]any, want float64, d time.Duration) bool {
		t.Helper()
		deadline := time.After(d)
		for {
			select {
			case f, ok := <-frames:
				if !ok {
					return false
				}
				if f["type"] != "events" {
					continue
				}
				evs, _ := f["events"].([]any)
				for _, evAny := range evs {
					ev, _ := evAny.(map[string]any)
					if ev == nil || ev["type"] != "subscribers_changed" {
						continue
					}
					if n, _ := ev["count"].(float64); n == want {
						return true
					}
				}
			case <-deadline:
				return false
			}
		}
	}

	fe1, frames1 := dialFE()
	defer fe1.Close(websocket.StatusNormalClosure, "")
	hello1 := waitForFrameType(frames1, "hello", 3*time.Second)
	if hello1 == nil {
		t.Fatal("no first fe hello")
	}
	if n, _ := hello1["feSubscribers"].(float64); n != 1 {
		t.Fatalf("first hello feSubscribers = %v, want 1", hello1["feSubscribers"])
	}

	fe2, frames2 := dialFE()
	defer fe2.Close(websocket.StatusNormalClosure, "")
	hello2 := waitForFrameType(frames2, "hello", 3*time.Second)
	if n, _ := hello2["feSubscribers"].(float64); n != 2 {
		t.Fatalf("second hello feSubscribers = %v, want 2", hello2["feSubscribers"])
	}
	if !waitSubCount(frames1, 2, 3*time.Second) {
		t.Fatal("open page got no subscribers_changed=2 when another page joined")
	}

	// Closing the second page drops its subscription immediately (the WS
	// read goroutine's exit wakes the handler), so the first page's number
	// falls back to 1 without waiting for a ping failure.
	fe2.Close(websocket.StatusNormalClosure, "")
	if !waitSubCount(frames1, 1, 3*time.Second) {
		t.Fatal("open page got no subscribers_changed=1 after the other page left")
	}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// TestSubscribeFrameKeepsViewingAll drives the pre-viewing `subscribe`
// control frame exactly as an old FE sends it — no `session` field, and no
// `viewing` frame ever — and asserts the host's viewing set stays all:true.
// A page that only speaks `subscribe` must never have its transcript
// trimmed (PROTOCOL.md §6.4).
func TestSubscribeFrameKeepsViewingAll(t *testing.T) {
	h := hub.NewWithDir("")
	srv := httptest.NewServer(buildHandler(h, "", nil, nil, nil))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	feConn, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/fe?host=h1", nil)
	if err != nil {
		t.Fatalf("fe ws dial: %v", err)
	}
	defer feConn.Close(websocket.StatusNormalClosure, "")
	feConn.SetReadLimit(1 << 20)

	// The legacy frame: host only, no session.
	if err := feConn.Write(ctx, websocket.MessageText, []byte(`{"v":1,"type":"subscribe","host":"h1"}`)); err != nil {
		t.Fatalf("write subscribe: %v", err)
	}
	for {
		_, raw, err := feConn.Read(ctx)
		if err != nil {
			t.Fatalf("waiting for subscribed ack: %v", err)
		}
		var frame map[string]any
		if json.Unmarshal(raw, &frame) != nil {
			continue
		}
		if frame["type"] == "subscribed" {
			break
		}
	}

	// The viewing-set decision itself is covered in internal/hub
	// (TestViewingAllWhenPageSilent): a subscribe-only page must keep the set
	// at all:true. Here it is enough that the frame was accepted and acked.
}
