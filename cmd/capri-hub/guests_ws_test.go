package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// ── helpers ───────────────────────────────────────────────────────────

// TestGuestWSFiltersAndSubscribe: a guest WS only receives whitelisted
// events, an out-of-scope subscribe is ignored, and hello only lists the
// whitelisted hosts.
func TestGuestWSFiltersAndSubscribe(t *testing.T) {
	f := newGuestFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dial := func(host string) *websocket.Conn {
		conn, _, err := websocket.Dial(ctx, f.guestWSURL(t, host), nil)
		if err != nil {
			t.Fatalf("guest ws dial: %v", err)
		}
		conn.SetReadLimit(1 << 20)
		return conn
	}
	conn := dial("h1")
	defer conn.Close(websocket.StatusNormalClosure, "")
	frames := feFrames(ctx, conn)
	hello := waitForFrameType(frames, "hello", 3*time.Second)
	if hello == nil {
		t.Fatal("no guest hello")
	}
	hosts, _ := hello["hosts"].([]any)
	if len(hosts) != 2 {
		t.Fatalf("hello hosts = %v", hosts)
	}
	if seqs, _ := hello["seqs"].(map[string]any); len(seqs) != 0 {
		t.Errorf("guest hello seqs should be empty: %v", seqs)
	}
	if hello["role"] != "guest" {
		t.Errorf("hello role = %v", hello["role"])
	}

	pushHostEvent(t, ctx, f.host1.conn, 1, map[string]any{"type": "chunk", "text": "mine", "sessionId": "s1"})
	pushHostEvent(t, ctx, f.host1.conn, 2, map[string]any{"type": "chunk", "text": "other", "sessionId": "sX"})
	pushHostEvent(t, ctx, f.host2.conn, 1, map[string]any{"type": "chunk", "text": "h2", "sessionId": "s2"})
	got := chunkTextsOf(ctx, frames, 700*time.Millisecond)
	if !containsStr(got, "mine") {
		t.Fatalf("guest missed its own session: %v", got)
	}
	if containsStr(got, "other") || containsStr(got, "h2") {
		t.Fatalf("guest saw out-of-scope events: %v", got)
	}

	// Out-of-scope subscribe (h3) is ignored: no ack, and the stream keeps
	// delivering the current host.
	badSub, _ := json.Marshal(map[string]any{"v": 1, "type": "subscribe", "host": "h3", "session": "s1"})
	if err := conn.Write(ctx, websocket.MessageText, badSub); err != nil {
		t.Fatal(err)
	}
	if ack := waitForFrameType(frames, "subscribed", 300*time.Millisecond); ack != nil {
		t.Fatalf("out-of-scope subscribe was acked: %v", ack)
	}
	// In-scope retarget (h2/s2) is acked and remembered.
	go func() {
		time.Sleep(50 * time.Millisecond)
		pushHostEvent(t, ctx, f.host2.conn, 2, map[string]any{"type": "chunk", "text": "now-h2", "sessionId": "s2"})
	}()
	goodSub, _ := json.Marshal(map[string]any{"v": 1, "type": "subscribe", "host": "h2", "session": "s2"})
	if err := conn.Write(ctx, websocket.MessageText, goodSub); err != nil {
		t.Fatal(err)
	}
	ack := waitForFrameType(frames, "subscribed", 3*time.Second)
	if ack == nil {
		t.Fatal("in-scope subscribe was not acked")
	}
	if ack["host"] != "h2" || ack["session"] != "s2" {
		t.Errorf("ack = %v", ack)
	}
	after := chunkTextsOf(ctx, frames, 800*time.Millisecond)
	if !containsStr(after, "now-h2") {
		t.Errorf("h2 event missing after retarget: %v", after)
	}
}

// TestGuestRevokeClosesWS: revoking a token closes its live WS.
func TestGuestRevokeClosesWS(t *testing.T) {
	f := newGuestFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, f.guestWSURL(t, "h1"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	frames := feFrames(ctx, conn)
	if waitForFrameType(frames, "hello", 3*time.Second) == nil {
		t.Fatal("no hello")
	}
	if _, err := f.h.UpdateGuestToken(f.guest.ID, nil, nil, guestBoolPtr(true)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	deadline := time.After(3 * time.Second)
	for {
		select {
		case _, ok := <-frames:
			if !ok {
				return // socket closed: pass
			}
		case <-deadline:
			t.Fatal("revoked guest WS stayed open")
		}
	}
}

// TestGuestTicketCarriesIdentity: ws-ticket for a guest reconnects as the
// same guest (the ticket is the only credential in the query string).
func TestGuestTicketCarriesIdentity(t *testing.T) {
	f := newGuestFixture(t)
	res, body := f.do(t, f.guest.Token, http.MethodPost, "/api/ws-ticket", nil)
	if res.StatusCode != 200 || body["role"] != "guest" {
		t.Fatalf("guest ticket = %d %v", res.StatusCode, body)
	}
	ticket, _ := body["ticket"].(string)
	if ticket == "" {
		t.Fatal("empty ticket")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx,
		strings.Replace(f.srv.URL, "http", "ws", 1)+"/ws/fe?ticket="+ticket, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	frames := feFrames(ctx, conn)
	hello := waitForFrameType(frames, "hello", 3*time.Second)
	if hello == nil || hello["role"] != "guest" {
		t.Fatalf("ticket hello = %v", hello)
	}
	hosts, _ := hello["hosts"].([]any)
	if len(hosts) != 2 {
		t.Fatalf("ticket hello hosts = %v", hosts)
	}
}

// TestGuestTicketIsSingleUse: a guest ticket burns on first use and cannot
// be replayed (the WS handshake is the only consumer).
func TestGuestTicketIsSingleUse(t *testing.T) {
	f := newGuestFixture(t)
	_, body := f.do(t, f.guest.Token, http.MethodPost, "/api/ws-ticket", nil)
	ticket, _ := body["ticket"].(string)
	if ticket == "" {
		t.Fatal("empty ticket")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx,
		strings.Replace(f.srv.URL, "http", "ws", 1)+"/ws/fe?ticket="+ticket, nil)
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	frames := feFrames(ctx, conn)
	if waitForFrameType(frames, "hello", 3*time.Second) == nil {
		t.Fatal("no hello with fresh ticket")
	}
	conn.Close(websocket.StatusNormalClosure, "")

	// Replay: the ticket is burned, so the hub must reject the upgrade.
	_, resp, err := websocket.Dial(ctx,
		strings.Replace(f.srv.URL, "http", "ws", 1)+"/ws/fe?ticket="+ticket, nil)
	if err == nil {
		t.Fatal("replayed ticket was accepted")
	}
	if resp == nil || resp.StatusCode != 401 {
		t.Fatalf("replay status = %v, want 401", resp)
	}
}

// TestGuestTicketDiesWithToken: a ticket minted before revocation must not
// open a socket afterwards.
func TestGuestTicketDiesWithToken(t *testing.T) {
	f := newGuestFixture(t)
	_, body := f.do(t, f.guest.Token, http.MethodPost, "/api/ws-ticket", nil)
	ticket, _ := body["ticket"].(string)
	if _, err := f.h.UpdateGuestToken(f.guest.ID, nil, nil, guestBoolPtr(true)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, resp, err := websocket.Dial(ctx,
		strings.Replace(f.srv.URL, "http", "ws", 1)+"/ws/fe?ticket="+ticket, nil)
	if err == nil {
		t.Fatal("ticket of a revoked token was accepted")
	}
	if resp == nil || resp.StatusCode != 401 {
		t.Fatalf("status = %v, want 401", resp)
	}
}

// TestGuestTokenBearerUpgradeToAdminTickets: a guest's ws-ticket names the
// guest, so a page can reconnect after switching sessions with no extra
// credentials.
func TestGuestTokenBearerUpgradeToAdminTickets(t *testing.T) {
	f := newGuestFixture(t)
	// Admin ticket still works as before (regression guard).
	res, body := f.do(t, f.admin, http.MethodPost, "/api/ws-ticket", nil)
	if res.StatusCode != 200 || body["role"] != "admin" {
		t.Fatalf("admin ticket = %d %v", res.StatusCode, body)
	}
	ticket, _ := body["ticket"].(string)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx,
		strings.Replace(f.srv.URL, "http", "ws", 1)+"/ws/fe?ticket="+ticket, nil)
	if err != nil {
		t.Fatalf("admin ticket dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	frames := feFrames(ctx, conn)
	hello := waitForFrameType(frames, "hello", 3*time.Second)
	if hello == nil || hello["role"] != "admin" {
		t.Fatalf("admin hello = %v", hello)
	}
	// Admin hello keeps the full registry + seq map.
	if hosts, _ := hello["hosts"].([]any); len(hosts) != 2 {
		t.Errorf("admin hello hosts = %v", hosts)
	}
	if _, ok := hello["seqs"].(map[string]any); !ok {
		t.Errorf("admin hello lost seqs: %v", hello["seqs"])
	}
}
