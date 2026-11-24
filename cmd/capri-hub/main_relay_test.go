package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/internal/hub"
	"github.com/AgentsHarness/capri-hub/wire"
	"github.com/coder/websocket"
)

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
// TestHandleRelayForwardsIdempotencyHeaders: the browser's Idempotency-Key
// reaches the host on the request frame, trimmed, with a hub-generated scope.
// A browser-supplied Idempotency-Scope is ignored.
func TestHandleRelayForwardsIdempotencyHeaders(t *testing.T) {
	h := hub.NewWithDir("")
	const secret = "admin-secret"
	srv := httptest.NewServer(buildHandler(h, secret, newFETicketStore(), newPairLimiter(), nil))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := dialPairedHost(t, ctx, srv, h, "h1", "H1")
	defer conn.Close(websocket.StatusNormalClosure, "")

	const key = "6f1e0c1e-7f5a-4c2b-9d3e-2a1b0c9d8e7f"
	type answer struct {
		status int
		body   string
		err    error
	}
	done := make(chan answer, 1)
	go func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/prompt?host=h1",
			strings.NewReader(`{"sessionId":"s1","prompt":"hi"}`))
		if err != nil {
			done <- answer{err: err}
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+secret)
		req.Header.Set("Idempotency-Key", " "+key+" ")
		req.Header.Set("Idempotency-Scope", "user:forged")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- answer{err: err}
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		done <- answer{status: resp.StatusCode, body: string(body)}
	}()

	var reqFrame map[string]any
	for reqFrame == nil {
		_, raw, err := conn.Read(ctx)
		if err != nil {
			t.Fatalf("read request frame: %v", err)
		}
		var f map[string]any
		if json.Unmarshal(raw, &f) != nil {
			continue
		}
		if answerRelayProbe(ctx, conn, f) {
			continue
		}
		if f["type"] == "request" {
			reqFrame = f
		}
	}
	if got := reqFrame["idemKey"]; got != key {
		t.Errorf("request idemKey = %v, want the trimmed %q", got, key)
	}
	if got := reqFrame["idemScope"]; got != "root" {
		t.Errorf("request idemScope = %v, want root (the browser scope must be ignored)", got)
	}

	respond, _ := json.Marshal(map[string]any{
		"v": 3, "type": "respond", "reqId": reqFrame["reqId"],
		"chunkSeq": 1, "ack": reqFrame["seq"], "status": 200,
		"body": map[string]any{"ok": true},
	})
	if err := conn.Write(ctx, websocket.MessageText, respond); err != nil {
		t.Fatalf("write respond: %v", err)
	}
	select {
	case a := <-done:
		if a.err != nil {
			t.Fatalf("relay request: %v", a.err)
		}
		if a.status != 200 || a.body != `{"ok":true}` {
			t.Fatalf("relay answer = %d %q", a.status, a.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay request did not resolve")
	}
}

// TestHandleRelayRejectsInvalidIdempotencyKey: a malformed key is a 400
// before any host work, not a relaying surprise.
func TestHandleRelayRejectsInvalidIdempotencyKey(t *testing.T) {
	cases := []struct {
		name string
		key  string
	}{
		{"too long", strings.Repeat("k", wire.IdemKeyMaxLen+1)},
		{"control byte", "a\tb"},
		{"non ascii", "clé"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/prompt", strings.NewReader(`{}`))
			req.Header.Set("Idempotency-Key", tc.key)
			handleRelay(hub.NewWithDir("")).ServeHTTP(rr, req)
			if rr.Code != 400 {
				t.Fatalf("status = %d, want 400", rr.Code)
			}
			assertPlainRelayError(t, rr, "invalid_idempotency_key")
		})
	}
}

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
