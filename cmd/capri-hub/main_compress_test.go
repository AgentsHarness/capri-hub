package main

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/internal/hub"
	"github.com/AgentsHarness/capri-hub/wire"
	"github.com/coder/websocket"
	"github.com/quic-go/quic-go"
)

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
		"v": 3, "type": "hello", "epoch": 7001, "token": tok,
		"resume": map[string]any{"up": 0, "down": 0},
		"caps":   map[string]any{"deflate": true, "transportUnits": true},
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

	// flate-compressed events frame as one compressed BINARY unit.
	payload := []byte(`{"v":3,"type":"events","seq":1,"events":[{"type":"chunk","text":"deflated","seq":1}]}`)
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestSpeed)
	fw.Write(payload)
	fw.Close()
	units, err := wire.SplitFrame(buf.Bytes(), true, 1, 0)
	if err != nil || len(units) != 1 {
		t.Fatalf("split compressed frame: %v (%d units)", err, len(units))
	}
	if err := conn.Write(ctx, websocket.MessageBinary, units[0]); err != nil {
		t.Fatal(err)
	}
	waitChunk("deflated")

	// Plain text frames still work alongside.
	plain := []byte(`{"v":3,"type":"events","seq":2,"events":[{"type":"chunk","text":"plain","seq":2}]}`)
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
		return writeControlUnit(stream, payload, compressed, 1)
	}
	readFrame := func() ([]byte, error) { return readControlUnit(stream) }

	hello, _ := json.Marshal(map[string]any{
		"v": 3, "type": "hello", "epoch": 6101, "token": tok,
		"resume": map[string]any{"up": 0, "down": 0},
		"caps":   map[string]any{"deflate": true, "transportUnits": true},
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

	compressedEvents, _ := json.Marshal(map[string]any{
		"v": 3, "type": "events", "seq": 1,
		"events": []any{map[string]any{"type": "chunk", "text": "z", "seq": 1}},
	})
	if err := writeFrame(compressedEvents, true); err != nil {
		t.Fatal(err)
	}
	// Plain frame alongside (host skips compression under its floor).
	plain, _ := json.Marshal(map[string]any{
		"v": 3, "type": "events", "seq": 2,
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
	// Control stream: transport units. Request streams: complete frames.
	wf := func(s *quic.Stream, payload []byte, compressed bool) error {
		return writeControlUnit(s, payload, compressed, 1)
	}
	wfFrame := func(s *quic.Stream, payload []byte, compressed bool) error {
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
	rf := func(s *quic.Stream) ([]byte, error) { return readControlUnit(s) }

	hello, _ := json.Marshal(map[string]any{
		"v": 3, "type": "hello", "epoch": 6201, "token": tok,
		"resume": map[string]any{"up": 0, "down": 0},
		"caps":   map[string]any{"deflate": true, "transportUnits": true},
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
	ev1, _ := json.Marshal(map[string]any{"v": 3, "type": "events", "seq": 1,
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
		"v": 3, "type": "respond", "reqId": reqID, "seq": 0, "ack": reqSeq,
		"chunkSeq": 1, "status": 234, "body": json.RawMessage(rbody),
	})
	var zbuf bytes.Buffer
	zw, _ := flate.NewWriter(&zbuf, flate.BestSpeed)
	zw.Write(frameJSON)
	zw.Close()
	if err := wfFrame(rs, zbuf.Bytes(), true); err != nil {
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
	ev2, _ := json.Marshal(map[string]any{"v": 3, "type": "events", "seq": 2,
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
			if json.Unmarshal(data, &frame) != nil {
				continue
			}
			if answerRelayProbe(ctx, conn, frame) {
				continue
			}
			if frame["type"] != "request" {
				continue
			}
			reqID, _ := frame["reqId"].(string)
			seq, _ := frame["seq"].(float64)
			out, _ := json.Marshal(map[string]any{
				"v": 3, "type": "respond", "reqId": reqID, "seq": 0,
				"ack": uint64(seq), "chunkSeq": 1, "status": 200, "body": json.RawMessage(page),
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
