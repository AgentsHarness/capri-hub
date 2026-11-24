package main

import (
	"bytes"
	"context"
	"crypto/tls"
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
			if answerRelayProbe(ctx, hostConn, frame) {
				continue
			}
			if frame["type"] == "request" {
				reqID, _ := frame["reqId"].(string)
				seq, _ := frame["seq"].(float64)
				out, _ := json.Marshal(map[string]any{
					"v": 3, "type": "respond", "reqId": reqID, "seq": 0,
					"ack": uint64(seq), "chunkSeq": 1, "status": 200,
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
		"v": 3, "type": "events", "seq": 1, "ack": 0,
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
		return writeControlUnit(stream, payload, false, 1)
	}
	readFrame := func() ([]byte, error) { return readControlUnit(stream) }

	helloFrame, _ := json.Marshal(map[string]any{
		"v": 3, "type": "hello", "epoch": 6001, "token": tok,
		"resume": map[string]any{"up": 0, "down": 0},
		"caps":   map[string]any{"transportUnits": true},
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
		"v": 3, "type": "events", "seq": 1, "ack": 0,
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

// TestHandlePrefsPutReturnsMergedDoc: the FE treats the presence of
// `prefs.entries` in the PUT response as proof its write was folded in and
// keeps its retry marker otherwise. The handler must therefore return the
// merged authoritative doc, including the projection fields.
func TestHandlePrefsPutReturnsMergedDoc(t *testing.T) {
	h := hub.NewWithDir("")
	body := `{"prefs":{"entries":{"ws:/w":{"v":"1","at":10,"site":"me"}}}}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/prefs", strings.NewReader(body))
	handlePrefsPut(h).ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		OK      bool             `json:"ok"`
		Version uint64           `json:"version"`
		Prefs   hub.BrowserPrefs `json:"prefs"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if !resp.OK || resp.Version == 0 {
		t.Fatalf("resp = %+v, want ok with a bumped version", resp)
	}
	if got := resp.Prefs.Entries["ws:/w"]; got.V != "1" || got.Site != "me" {
		t.Fatalf("entries = %+v, want the merged write", resp.Prefs.Entries)
	}
	if len(resp.Prefs.PinnedWorkspaces) != 1 || resp.Prefs.PinnedWorkspaces[0] != "/w" {
		t.Fatalf("projection = %v, want [/w]", resp.Prefs.PinnedWorkspaces)
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
			"v": 3, "type": "hello", "epoch": epoch, "token": pairRes.Token,
			"resume": map[string]any{"up": 0, "down": 0},
			"caps":   map[string]any{"transportUnits": true},
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
			"v": 3, "type": "events", "seq": seq, "ack": 0,
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
