package main

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/internal/hub"
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
	// (Back-compat path: host_status still inside events frames.)
	handleHostFrame(h, "h1",
		[]byte(`{"v":1,"type":"events","events":[{"type":"host_status","ready":true}]}`),
		func([]byte) error { return nil })
	if got := h.LastSeq("h1"); got != 43 {
		t.Errorf("LastSeq after seq-less frame = %d, want 43", got)
	}
	if hosts := h.ListHosts(); len(hosts) != 1 || !hosts[0].Ready {
		t.Errorf("ready not set via events-frame host_status: %+v", hosts)
	}
}

// TestWriteHostPingCarriesSeqAck: the hub→host ping piggy-backs the
// per-host data-plane watermark (same meaning as hello.seq) so the host
// can anchor drop-repairs at what actually reached the hub. Absent field
// would silently strand old-host compatibility, so assert it explicitly.
func TestWriteHostPingCarriesSeqAck(t *testing.T) {
	h := hub.NewWithDir("")
	code, _ := h.PairingCode()
	if _, err := h.Pair(code, "h1", "H1"); err != nil {
		t.Fatalf("pair: %v", err)
	}
	for i := uint64(1); i <= 7; i++ {
		if !h.RegisterEvent("h1", hub.Event{"type": "chunk", "text": "x", "seq": i}) {
			t.Fatalf("RegisterEvent %d rejected", i)
		}
	}
	var frame []byte
	if err := writeHostPing(h, "h1", func(p []byte) error { frame = p; return nil }); err != nil {
		t.Fatalf("writeHostPing: %v", err)
	}
	var f struct {
		Type        string  `json:"type"`
		Seq         *uint64 `json:"seq"`
		Subscribers int     `json:"subscribers"`
	}
	if err := json.Unmarshal(frame, &f); err != nil {
		t.Fatalf("bad ping frame: %.60s (%v)", frame, err)
	}
	if f.Type != "ping" {
		t.Fatalf("frame type = %q, want ping", f.Type)
	}
	if f.Seq == nil || *f.Seq != 7 {
		t.Fatalf("ping seq = %v, want 7 (the host's data-plane watermark)", f.Seq)
	}
	// A host with no events yet acks 0 (field still present, not null).
	if err := writeHostPing(h, "ghost", func(p []byte) error { frame = p; return nil }); err != nil {
		t.Fatalf("writeHostPing(ghost): %v", err)
	}
	if err := json.Unmarshal(frame, &f); err != nil || f.Seq == nil || *f.Seq != 0 {
		t.Fatalf("unknown-host ping seq = %v, want 0", f.Seq)
	}
}

func TestFETicketSingleUse(t *testing.T) {
	s := newFETicketStore()
	ticket, exp := s.issue()
	if ticket == "" || !exp.After(time.Now()) {
		t.Fatalf("bad ticket %q exp %v", ticket, exp)
	}
	if !s.consume(ticket) {
		t.Fatal("first consume should succeed")
	}
	if s.consume(ticket) {
		t.Fatal("second consume must fail (single-use)")
	}
	if s.consume("nope") {
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
	ticket, _ := tickets.issue()
	r = httptest.NewRequest(http.MethodGet, "/ws/fe?ticket="+ticket, nil)
	if !auth.check(r) {
		t.Fatal("valid ticket must allow")
	}
	// Burned
	r = httptest.NewRequest(http.MethodGet, "/ws/fe?ticket="+ticket, nil)
	if auth.check(r) {
		t.Fatal("burned ticket must deny")
	}

	// Legacy ?token=
	r = httptest.NewRequest(http.MethodGet, "/ws/fe?token=secret", nil)
	if !auth.check(r) {
		t.Fatal("legacy ?token= must still allow")
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
	hostConn, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/host", &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + pairRes.Token}},
	})
	if err != nil {
		t.Fatalf("host ws dial: %v", err)
	}
	defer hostConn.Close(websocket.StatusNormalClosure, "")
	hostConn.SetReadLimit(1 << 20)

	// Read hello
	_, helloRaw, err := hostConn.Read(ctx)
	if err != nil {
		t.Fatalf("host hello: %v", err)
	}
	var hello map[string]any
	if json.Unmarshal(helloRaw, &hello) != nil || hello["type"] != "hello" {
		t.Fatalf("hello frame = %s", helloRaw)
	}

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
				out, _ := json.Marshal(map[string]any{
					"v": 1, "type": "respond", "reqId": reqID,
					"status": 200, "body": map[string]any{"ok": true, "via": "ws"},
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
		"v": 1, "type": "events", "seqStart": 1,
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

	auth, _ := json.Marshal(map[string]any{"type": "auth", "token": tok})
	if err := writeFrame(auth); err != nil {
		t.Fatal(err)
	}
	hello, err := readFrame()
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	var hm map[string]any
	if json.Unmarshal(hello, &hm) != nil || hm["type"] != "hello" {
		t.Fatalf("hello = %s", hello)
	}

	// Wait until host is online (ConnectStream after hello write on server).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && h.DefaultHostID() == "" {
		time.Sleep(10 * time.Millisecond)
	}
	// Push event
	ev, _ := json.Marshal(map[string]any{
		"v": 1, "type": "events",
		"events": []map[string]any{{"type": "chunk", "text": "q", "seq": float64(1)}},
	})
	// seq as number in JSON becomes float64 on decode — fine.
	ev, _ = json.Marshal(map[string]any{
		"v": 1, "type": "events",
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

// TestHandleHostFrameRespondAfterSupersede: a respond for a request that
// was stranded on a superseded connection must not panic; the hub drops
// unknown reqIds cleanly.
func TestHandleHostFrameRespondUnknown(t *testing.T) {
	h := hub.NewWithDir("")
	code, _ := h.PairingCode()
	if _, err := h.Pair(code, "h1", "H1"); err != nil {
		t.Fatal(err)
	}
	// No pending request — respond is a no-op log path.
	handleHostFrame(h, "h1",
		[]byte(`{"v":1,"type":"respond","reqId":"missing","status":200,"body":{"ok":true}}`),
		func([]byte) error { return nil })
}

// TestHandleHostFrameHostStatusControl: control-plane host_status frames
// update Ready without advancing LastSeq or appearing as sequenced events.
func TestHandleHostFrameHostStatusControl(t *testing.T) {
	h := hub.NewWithDir("")
	code, _ := h.PairingCode()
	if _, err := h.Pair(code, "h1", "H1"); err != nil {
		t.Fatalf("pair: %v", err)
	}
	handleHostFrame(h, "h1",
		[]byte(`{"v":1,"type":"events","seqStart":10,"events":[{"type":"chunk","text":"a","seq":10}]}`),
		func([]byte) error { return nil })
	if got := h.LastSeq("h1"); got != 10 {
		t.Fatalf("LastSeq = %d, want 10", got)
	}

	ch, unsub := h.Subscribe()
	defer unsub()

	handleHostFrame(h, "h1",
		[]byte(`{"v":1,"type":"host_status","ready":true}`),
		func([]byte) error { return nil })

	if got := h.LastSeq("h1"); got != 10 {
		t.Errorf("LastSeq after control host_status = %d, want 10", got)
	}
	if hosts := h.ListHosts(); len(hosts) != 1 || !hosts[0].Ready {
		t.Errorf("ready not set: %+v", hosts)
	}
	select {
	case ev := <-ch:
		if ev["type"] != "hosts_changed" {
			t.Errorf("event = %v, want hosts_changed", ev["type"])
		}
	case <-time.After(time.Second):
		t.Fatal("no hosts_changed from control host_status")
	}
}

// TestHandleHostFrameHostStatusLive: host_status frames carrying the
// transient registry fields (busy/booting/pendingCount) apply them to the
// registry and broadcast hosts_changed; older ready-only frames leave
// them untouched.
func TestHandleHostFrameHostStatusLive(t *testing.T) {
	h := hub.NewWithDir("")
	code, _ := h.PairingCode()
	if _, err := h.Pair(code, "h1", "H1"); err != nil {
		t.Fatalf("pair: %v", err)
	}

	ch, unsub := h.Subscribe()
	defer unsub()

	handleHostFrame(h, "h1",
		[]byte(`{"v":1,"type":"host_status","ready":true,"busy":true,"booting":false,"pendingCount":3}`),
		func([]byte) error { return nil })
	if hosts := h.ListHosts(); len(hosts) != 1 {
		t.Fatalf("hosts len = %d", len(hosts))
	} else {
		got := hosts[0]
		if !got.Ready || !got.Busy || got.Booting || got.PendingCount != 3 {
			t.Errorf("registry = %+v, want ready+busy, booting=false, pending=3", got)
		}
	}
	select {
	case ev := <-ch:
		if ev["type"] != "hosts_changed" {
			t.Errorf("event = %v, want hosts_changed", ev["type"])
		}
	case <-time.After(time.Second):
		t.Fatal("no hosts_changed from live host_status")
	}

	// Older host shape (ready only): transient fields must survive.
	handleHostFrame(h, "h1",
		[]byte(`{"v":1,"type":"host_status","ready":true}`),
		func([]byte) error { return nil })
	if hosts := h.ListHosts(); len(hosts) != 1 {
		t.Fatalf("hosts len = %d", len(hosts))
	} else if hosts[0].Busy != true || hosts[0].PendingCount != 3 {
		t.Errorf("registry = %+v, want busy/pending kept by ready-only frame", hosts[0])
	}
}

// TestHandleHostFrameSeqReset: host process restart control frame clears
// LastSeq so subsequent low seqs fan out instead of being skipped.
func TestHandleHostFrameSeqReset(t *testing.T) {
	h := hub.NewWithDir("")
	code, _ := h.PairingCode()
	if _, err := h.Pair(code, "h1", "H1"); err != nil {
		t.Fatalf("pair: %v", err)
	}
	handleHostFrame(h, "h1",
		[]byte(`{"v":1,"type":"events","seqStart":100,"events":[{"type":"chunk","text":"old","seq":100}]}`),
		func([]byte) error { return nil })
	if got := h.LastSeq("h1"); got != 100 {
		t.Fatalf("LastSeq = %d, want 100", got)
	}

	ch, unsub := h.Subscribe()
	defer unsub()

	handleHostFrame(h, "h1",
		[]byte(`{"v":1,"type":"seq_reset"}`),
		func([]byte) error { return nil })
	if got := h.LastSeq("h1"); got != 0 {
		t.Errorf("LastSeq after seq_reset = %d, want 0", got)
	}

	// Drain any residual hosts_changed from pair/connect noise, then
	// assert seq=1 fans out.
	handleHostFrame(h, "h1",
		[]byte(`{"v":1,"type":"events","seqStart":1,"events":[{"type":"chunk","text":"fresh","seq":1}]}`),
		func([]byte) error { return nil })
	deadline := time.After(time.Second)
	for {
		select {
		case ev := <-ch:
			// Raw-path events carry the body as pre-encoded wire bytes
			// (hub.MarshalEvent); "type"/"seq" are the shallow fields.
			if ev["type"] != "chunk" {
				continue
			}
			wire, err := hub.MarshalEvent(ev)
			if err != nil {
				t.Fatalf("MarshalEvent: %v", err)
			}
			var m map[string]any
			if json.Unmarshal(wire, &m) != nil || m["text"] == "fresh" {
				return
			}
		case <-deadline:
			t.Fatal("seq 1 after seq_reset was not broadcast")
		}
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

	dialHost := func(name string) *websocket.Conn {
		t.Helper()
		c, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/host", &websocket.DialOptions{
			HTTPHeader: http.Header{"Authorization": []string{"Bearer " + pairRes.Token}},
		})
		if err != nil {
			t.Fatalf("%s dial: %v", name, err)
		}
		c.SetReadLimit(1 << 20)
		_, raw, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("%s hello: %v", name, err)
		}
		var hello map[string]any
		if json.Unmarshal(raw, &hello) != nil || hello["type"] != "hello" {
			t.Fatalf("%s hello frame = %s", name, raw)
		}
		return c
	}

	conn1 := dialHost("conn1")
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

	sendEvents := func(c *websocket.Conn, seq int, text string) {
		t.Helper()
		frame, _ := json.Marshal(map[string]any{
			"v": 1, "type": "events", "seqStart": seq,
			"events": []map[string]any{{"type": "chunk", "text": text, "seq": seq}},
		})
		if err := c.Write(ctx, websocket.MessageText, frame); err != nil {
			t.Fatalf("write seq %d: %v", seq, err)
		}
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
	sendEvents(conn1, 1, "first")
	waitFEChunk(1, -1, "first")

	// conn2 supersedes conn1.
	conn2 := dialHost("conn2")
	defer conn2.Close(websocket.StatusNormalClosure, "")

	// conn1 uplink after supersede: ignored, and the hub drops conn1.
	sendEvents(conn1, 2, "stale")
	// Drain buffered frames (e.g. a subscribers frame) until the hub's
	// close arrives.
	closed := false
	drainDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(drainDeadline) && !closed {
		rctx, rcancel := context.WithTimeout(ctx, 500*time.Millisecond)
		_, _, rerr := conn1.Read(rctx)
		rcancel()
		closed = rerr != nil
	}
	if !closed {
		t.Error("hub should close the superseded connection")
	}

	// FE must never see seq 2; conn2's seq 3 must arrive.
	sendEvents(conn2, 3, "fresh")
	waitFEChunk(3, 2, "fresh")
}

// TestHandleHostFrameSeqStartMismatchRejected: a frame whose seqStart
// disagrees with the first event's seq is corrupted / mis-assembled and
// must be rejected whole — neither its events nor the per-host watermark
// may advance.
func TestHandleHostFrameSeqStartMismatchRejected(t *testing.T) {
	h := hub.NewWithDir("")
	code, _ := h.PairingCode()
	if _, err := h.Pair(code, "h1", "H1"); err != nil {
		t.Fatalf("pair: %v", err)
	}
	ch, unsub := h.Subscribe()
	defer unsub()

	// seqStart claims 100 but the first event carries 200.
	handleHostFrame(h, "h1",
		[]byte(`{"v":1,"type":"events","seqStart":100,"events":[{"type":"chunk","text":"a","seq":200},{"type":"chunk","text":"b","seq":201}]}`),
		func([]byte) error { return nil })
	if got := h.LastSeq("h1"); got != 0 {
		t.Errorf("LastSeq = %d, want 0 (mismatched frame must be rejected)", got)
	}
	select {
	case ev := <-ch:
		t.Fatalf("rejected frame must not fan out, got %v", ev)
	case <-time.After(50 * time.Millisecond):
	}

	// A matching frame still passes through unchanged.
	handleHostFrame(h, "h1",
		[]byte(`{"v":1,"type":"events","seqStart":200,"events":[{"type":"chunk","text":"a","seq":200}]}`),
		func([]byte) error { return nil })
	if got := h.LastSeq("h1"); got != 200 {
		t.Errorf("LastSeq = %d, want 200 (valid frame accepted)", got)
	}
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

// TestUplinkDeflateWSRoundtrip: a host that negotiates uplink deflate
// (X-Hub-Deflate: 1) gets "deflate":true echoed in hello and may send
// flate-compressed binary frames; the hub inflates them and fans the
// events out as usual. Without negotiation, binary frames are dropped.
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
	dial := func(header http.Header) *websocket.Conn {
		conn, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/host", &websocket.DialOptions{HTTPHeader: header})
		if err != nil {
			t.Fatalf("host ws dial: %v", err)
		}
		conn.SetReadLimit(1 << 20)
		return conn
	}

	feCh, feUnsub := h.Subscribe()
	defer feUnsub()

	// Negotiated connection.
	conn := dial(http.Header{
		"Authorization": []string{"Bearer " + tok},
		"X-Hub-Deflate": []string{"1"},
	})
	defer conn.Close(websocket.StatusNormalClosure, "")
	_, helloRaw, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var hello map[string]any
	if json.Unmarshal(helloRaw, &hello) != nil {
		t.Fatalf("hello = %s", helloRaw)
	}
	if hello["deflate"] != true {
		t.Fatalf("hello must echo deflate:true, got %s", helloRaw)
	}
	waitChunk := func(want string) {
		deadline := time.After(3 * time.Second)
		for {
			select {
			case ev := <-feCh:
				if typ, _ := ev["type"].(string); typ == "chunk" {
					wire, _ := hub.MarshalEvent(ev)
					var m map[string]any
					_ = json.Unmarshal(wire, &m)
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
	payload := []byte(`{"v":1,"type":"events","seqStart":1,"events":[{"type":"chunk","text":"deflated","seq":1}]}`)
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestSpeed)
	fw.Write(payload)
	fw.Close()
	if err := conn.Write(ctx, websocket.MessageBinary, buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	waitChunk("deflated")

	// Below-threshold / plain text frames still work alongside.
	plain := []byte(`{"v":1,"type":"events","seqStart":2,"events":[{"type":"chunk","text":"plain","seq":2}]}`)
	if err := conn.Write(ctx, websocket.MessageText, plain); err != nil {
		t.Fatal(err)
	}
	waitChunk("plain")

	// Un-negotiated connection: hello must NOT echo deflate, and binary
	// frames are dropped (backward compat: bare JSON only).
	conn2 := dial(http.Header{"Authorization": []string{"Bearer " + tok}})
	defer conn2.Close(websocket.StatusNormalClosure, "")
	_, hello2Raw, err := conn2.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(hello2Raw, []byte(`"deflate"`)) {
		t.Fatalf("un-negotiated hello must not mention deflate: %s", hello2Raw)
	}
	var buf2 bytes.Buffer
	fw2, _ := flate.NewWriter(&buf2, flate.BestSpeed)
	fw2.Write([]byte(`{"v":1,"type":"events","seqStart":3,"events":[{"type":"chunk","text":"sneaky","seq":3}]}`))
	fw2.Close()
	if err := conn2.Write(ctx, websocket.MessageBinary, buf2.Bytes()); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-feCh:
		if typ, _ := ev["type"].(string); typ == "chunk" {
			wire, _ := hub.MarshalEvent(ev)
			if bytes.Contains(wire, []byte("sneaky")) {
				t.Fatal("un-negotiated compressed frame must be dropped")
			}
		}
	case <-time.After(300 * time.Millisecond):
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

// TestIntegrationQUICUplinkDeflate: QUIC auth with "deflate":true is
// confirmed by the hello echo; a compressed events frame (length-prefix
// bit 31 set, raw-deflate body) is inflated and registered, and a plain
// frame still works alongside.
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

	auth, _ := json.Marshal(map[string]any{"type": "auth", "token": tok, "deflate": true})
	if err := writeFrame(auth, false); err != nil {
		t.Fatal(err)
	}
	hello, err := readFrame()
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	var hm map[string]any
	if json.Unmarshal(hello, &hm) != nil || hm["type"] != "hello" || hm["deflate"] != true {
		t.Fatalf("hello must echo deflate:true, got %s", hello)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && h.DefaultHostID() == "" {
		time.Sleep(10 * time.Millisecond)
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
		"v": 1, "type": "events", "seqStart": 1,
		"events": []any{map[string]any{"type": "chunk", "text": "z", "seq": 1}},
	}), true); err != nil {
		t.Fatal(err)
	}
	// Plain frame alongside (host skips compression under 256 bytes).
	plain, _ := json.Marshal(map[string]any{
		"v": 1, "type": "events", "seqStart": 2,
		"events": []any{map[string]any{"type": "chunk", "text": "p", "seq": 2}},
	})
	if err := writeFrame(plain, false); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h.LastSeq("qh2") == 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("LastSeq = %d, want 2", h.LastSeq("qh2"))
}

// TestIntegrationQUICMultiStreamRequestPlane: T1 multi-stream sessions.
// Control stream (first accepted) carries auth + events and receives the
// relayed request; additional request-plane streams carry respond frames
// (plus the no-op pong that materializes a freshly opened stream). EOF on
// a request stream must NOT end the session.
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

	auth, _ := json.Marshal(map[string]any{"type": "auth", "token": tok, "deflate": true})
	if err := wf(control, auth, false); err != nil {
		t.Fatal(err)
	}
	hello, err := rf(control)
	if err != nil || json.Unmarshal(hello, &map[string]any{}) != nil {
		t.Fatalf("hello: %v %s", err, hello)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && h.DefaultHostID() == "" {
		time.Sleep(10 * time.Millisecond)
	}
	if h.DefaultHostID() != "qm1" {
		t.Fatalf("host not online: %q", h.DefaultHostID())
	}

	// An event on the control stream advances the watermark.
	ev1, _ := json.Marshal(map[string]any{"v": 1, "type": "events", "seqStart": 1,
		"events": []any{map[string]any{"type": "chunk", "text": "a", "seq": 1}}})
	if err := wf(control, ev1, false); err != nil {
		t.Fatal(err)
	}

	// Relay round-trip: Dispatch pushes a request down the CONTROL stream;
	// we answer with a respond on a fresh REQUEST stream.
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

	// Read the request frame off the control stream (hello already
	// consumed; ping frames may interleave — skip to the request).
	var reqID string
	for reqID == "" {
		data, err := rf(control)
		if err != nil {
			t.Fatalf("read request frame: %v", err)
		}
		var f struct {
			Type  string `json:"type"`
			ReqID string `json:"reqId"`
		}
		if json.Unmarshal(data, &f) == nil && f.Type == "request" {
			reqID = f.ReqID
		}
	}

	// Request stream: no-op pong materializes it, then the respond. Send
	// the respond COMPRESSED — the deflate flag is session-scoped and
	// must be honored on request streams too (PROTOCOL.md §4).
	rs, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pong, _ := json.Marshal(map[string]any{"v": 1, "type": "pong"})
	if err := wf(rs, pong, false); err != nil {
		t.Fatal(err)
	}
	rbody, _ := json.Marshal(map[string]any{"ok": true, "via": "request-stream"})
	var rbuf bytes.Buffer
	fw, _ := flate.NewWriter(&rbuf, flate.BestSpeed)
	fw.Write(rbody)
	fw.Close()
	frameJSON, _ := json.Marshal(map[string]any{"v": 1, "type": "respond", "reqId": reqID, "status": 234, "body": json.RawMessage(rbody)})
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
	ev2, _ := json.Marshal(map[string]any{"v": 1, "type": "events", "seqStart": 2,
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
