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

// TestSubscribersEndpoint: GET /api/subscribers is the roster behind the
// top-bar count. Admins see live rows with the identity captured at
// connect time; guests get 403 (they must not learn who else is watching).
func TestSubscribersEndpoint(t *testing.T) {
	f := newGuestFixture(t)

	// Guest is refused before any socket exists — the endpoint is
	// admin-only regardless of the roster being empty.
	res, _ := f.do(t, f.guest.Token, http.MethodGet, "/api/subscribers", nil)
	if res.StatusCode != 403 {
		t.Fatalf("guest list status = %d, want 403", res.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, feTicket := f.do(t, f.admin, http.MethodPost, "/api/ws-ticket", nil)
	raw, _ := feTicket["ticket"].(string)
	conn, _, err := websocket.Dial(ctx,
		strings.Replace(f.srv.URL, "http", "ws", 1)+"/ws/fe?ticket="+raw+"&host=h1",
		&websocket.DialOptions{HTTPHeader: http.Header{"User-Agent": []string{"CapriTest/1.0"}}})
	if err != nil {
		t.Fatalf("fe ws dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	frames := feFrames(ctx, conn)
	hello := waitForFrameType(frames, "hello", 3*time.Second)
	if hello == nil {
		t.Fatal("no admin hello")
	}
	if id, _ := hello["subscriberId"].(float64); id <= 0 {
		t.Errorf("hello subscriberId = %v, want a positive row id", hello["subscriberId"])
	}

	// Declare a session, then read the roster back.
	frame, _ := json.Marshal(map[string]any{"v": 1, "type": "subscribe", "host": "h1", "session": "s-admin"})
	if err := conn.Write(ctx, websocket.MessageText, frame); err != nil {
		t.Fatalf("subscribe write: %v", err)
	}
	if ack := waitForFrameType(frames, "subscribed", 3*time.Second); ack == nil {
		t.Fatal("no subscribed ack")
	}

	res, body := f.do(t, f.admin, http.MethodGet, "/api/subscribers", nil)
	if res.StatusCode != 200 {
		t.Fatalf("list status = %d", res.StatusCode)
	}
	rows, _ := body["subscribers"].([]any)
	if len(rows) != 1 {
		t.Fatalf("rows = %v, want the one open page", body["subscribers"])
	}
	row, _ := rows[0].(map[string]any)
	if row["role"] != "admin" {
		t.Errorf("role = %v, want admin", row["role"])
	}
	if row["userAgent"] != "CapriTest/1.0" {
		t.Errorf("userAgent = %v", row["userAgent"])
	}
	if row["hostId"] != "h1" || row["sessionId"] != "s-admin" {
		t.Errorf("host/session = %v/%v, want h1/s-admin", row["hostId"], row["sessionId"])
	}
	if row["ip"] == "" {
		t.Errorf("ip missing on a loopback connection: %v", row)
	}
	if count, _ := body["count"].(float64); count != 1 {
		t.Errorf("count = %v, want 1", body["count"])
	}

	// A guest socket shows up too, but under its record id/label — the
	// token itself never leaves the hub.
	_, guestTicket := f.do(t, f.guest.Token, http.MethodPost, "/api/ws-ticket", nil)
	guestRaw, _ := guestTicket["ticket"].(string)
	gconn, _, err := websocket.Dial(ctx,
		strings.Replace(f.srv.URL, "http", "ws", 1)+"/ws/fe?ticket="+guestRaw, nil)
	if err != nil {
		t.Fatalf("guest ws dial: %v", err)
	}
	defer gconn.Close(websocket.StatusNormalClosure, "")
	if hello := waitForFrameType(feFrames(ctx, gconn), "hello", 3*time.Second); hello == nil {
		t.Fatal("no guest hello")
	}

	res, body = f.do(t, f.admin, http.MethodGet, "/api/subscribers", nil)
	if res.StatusCode != 200 {
		t.Fatalf("list status after guest = %d", res.StatusCode)
	}
	rows, _ = body["subscribers"].([]any)
	if len(rows) != 2 {
		t.Fatalf("rows = %v, want admin + guest", body["subscribers"])
	}
	var sawGuest bool
	for _, raw := range rows {
		row, _ := raw.(map[string]any)
		if row["role"] != "guest" {
			continue
		}
		sawGuest = true
		if row["guestId"] != f.guest.ID || row["guestLabel"] != f.guest.Label {
			t.Errorf("guest row identity = %v/%v", row["guestId"], row["guestLabel"])
		}
		if _, leaked := row["token"]; leaked {
			t.Errorf("guest row leaked the token: %v", row)
		}
	}
	if !sawGuest {
		t.Fatalf("no guest row in %v", rows)
	}
}

// TestRequestIP: the subscriber panel must not fill up with 127.0.0.1 when
// the hub sits behind a loopback reverse proxy — but a direct dial must not
// be able to spoof its address with a header.
func TestRequestIP(t *testing.T) {
	req := func(remote string, hdr map[string]string) *http.Request {
		r := &http.Request{RemoteAddr: remote, Header: http.Header{}}
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return r
	}

	if got := requestIP(req("203.0.113.9:5555", nil)); got != "203.0.113.9" {
		t.Errorf("direct peer = %q, want the address without the port", got)
	}
	// Headers from a non-loopback peer are ignored (spoofing guard).
	if got := requestIP(req("203.0.113.9:5555", map[string]string{"X-Real-IP": "1.2.3.4"})); got != "203.0.113.9" {
		t.Errorf("forwarded header from a remote peer was trusted: %q", got)
	}
	if got := requestIP(req("127.0.0.1:5555", map[string]string{"X-Real-IP": "198.51.100.4"})); got != "198.51.100.4" {
		t.Errorf("loopback peer did not use X-Real-IP: %q", got)
	}
	if got := requestIP(req("[::1]:5555", map[string]string{"X-Forwarded-For": "198.51.100.5, 10.0.0.1"})); got != "198.51.100.5" {
		t.Errorf("X-Forwarded-For first hop = %q", got)
	}
	// Deployed site: Cloudflare in front of nginx. nginx's X-Real-IP is a CF
	// edge address, so the real client must win.
	if got := requestIP(req("127.0.0.1:5555", map[string]string{
		"CF-Connecting-IP": "203.0.113.77",
		"X-Real-IP":        "104.22.72.39",
		"X-Forwarded-For":  "203.0.113.77, 104.22.72.39",
	})); got != "203.0.113.77" {
		t.Errorf("CF client address = %q, want 203.0.113.77", got)
	}
	if got := requestIP(req("127.0.0.1:5555", map[string]string{
		"X-Forwarded-For": "203.0.113.78, 104.22.72.39",
		"X-Real-IP":       "104.22.72.39",
	})); got != "203.0.113.78" {
		t.Errorf("X-Forwarded-For first hop must beat X-Real-IP: %q", got)
	}
	// Loopback with no headers keeps the peer address (dev / same box).
	if got := requestIP(req("127.0.0.1:5555", nil)); got != "127.0.0.1" {
		t.Errorf("bare loopback peer = %q", got)
	}
}

func TestRateLimitIP(t *testing.T) {
	req := func(remote string, hdr map[string]string) *http.Request {
		r := &http.Request{RemoteAddr: remote, Header: http.Header{}}
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return r
	}
	// A loopback peer is the nginx hop; the real client comes from the
	// proxy-set header. This is what keeps the pair quota per-client.
	if got := rateLimitIP(req("127.0.0.1:5555", map[string]string{"CF-Connecting-IP": "203.0.113.20"})); got != "203.0.113.20" {
		t.Errorf("CF client rate-limit IP = %q", got)
	}
	if got := rateLimitIP(req("127.0.0.1:5555", map[string]string{"X-Real-IP": "198.51.100.8"})); got != "198.51.100.8" {
		t.Errorf("X-Real-IP rate-limit IP = %q", got)
	}
	// Direct peers cannot spoof the key.
	if got := rateLimitIP(req("203.0.113.9:5555", map[string]string{"X-Real-IP": "1.2.3.4"})); got != "203.0.113.9" {
		t.Errorf("direct peer rate-limit IP = %q", got)
	}
	// A malformed forwarding value must not create a fresh bucket key.
	if got := rateLimitIP(req("127.0.0.1:5555", map[string]string{"CF-Connecting-IP": "not-an-ip"})); got != "127.0.0.1" {
		t.Errorf("malformed forwarded IP = %q", got)
	}
}

// TestSubscribersViewingFrame: an admin page declares the session it reads
// with a `viewing` control frame (no ack), and the roster follows it —
// including a clear when the page returns to no session.
func TestSubscribersViewingFrame(t *testing.T) {
	f := newGuestFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, tick := f.do(t, f.admin, http.MethodPost, "/api/ws-ticket", nil)
	raw, _ := tick["ticket"].(string)
	conn, _, err := websocket.Dial(ctx,
		strings.Replace(f.srv.URL, "http", "ws", 1)+"/ws/fe?ticket="+raw+"&host=h1", nil)
	if err != nil {
		t.Fatalf("fe ws dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	frames := feFrames(ctx, conn)
	if hello := waitForFrameType(frames, "hello", 3*time.Second); hello == nil {
		t.Fatal("no hello")
	}

	read := func() string {
		t.Helper()
		_, body := f.do(t, f.admin, http.MethodGet, "/api/subscribers", nil)
		rows, _ := body["subscribers"].([]any)
		if len(rows) != 1 {
			t.Fatalf("rows = %v, want 1", rows)
		}
		row, _ := rows[0].(map[string]any)
		sid, _ := row["sessionId"].(string)
		return sid
	}

	vf, _ := json.Marshal(map[string]any{"v": 1, "type": "viewing", "host": "h1", "session": "s-read"})
	if err := conn.Write(ctx, websocket.MessageText, vf); err != nil {
		t.Fatalf("viewing write: %v", err)
	}
	// No ack by design: poll the roster until the frame lands.
	deadline := time.Now().Add(3 * time.Second)
	for read() != "s-read" {
		if time.Now().After(deadline) {
			t.Fatal("viewing frame never reached the roster")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Empty session clears the row (new session / back to empty state).
	clearFrame, _ := json.Marshal(map[string]any{"v": 1, "type": "viewing", "host": "h1", "session": ""})
	if err := conn.Write(ctx, websocket.MessageText, clearFrame); err != nil {
		t.Fatalf("viewing clear write: %v", err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for read() != "" {
		if time.Now().After(deadline) {
			t.Fatal("empty viewing frame did not clear the session")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestSubscribersConnectSession: a guest names its session in the /ws/fe URL
// (?session=) and only sends another frame when it switches — the roster
// must carry that from the very first poll, not show an empty row.
func TestSubscribersConnectSession(t *testing.T) {
	f := newGuestFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, tick := f.do(t, f.guest.Token, http.MethodPost, "/api/ws-ticket", nil)
	raw, _ := tick["ticket"].(string)
	conn, _, err := websocket.Dial(ctx,
		strings.Replace(f.srv.URL, "http", "ws", 1)+"/ws/fe?ticket="+raw+"&host=h2&session=s2", nil)
	if err != nil {
		t.Fatalf("guest ws dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	if hello := waitForFrameType(feFrames(ctx, conn), "hello", 3*time.Second); hello == nil {
		t.Fatal("no guest hello")
	}

	_, body := f.do(t, f.admin, http.MethodGet, "/api/subscribers", nil)
	rows, _ := body["subscribers"].([]any)
	if len(rows) != 1 {
		t.Fatalf("rows = %v, want 1", rows)
	}
	row, _ := rows[0].(map[string]any)
	if row["sessionId"] != "s2" || row["hostId"] != "h2" {
		t.Errorf("connect-time session = %v/%v, want h2/s2", row["hostId"], row["sessionId"])
	}
	if row["guestLabel"] != f.guest.Label {
		t.Errorf("guestLabel = %v", row["guestLabel"])
	}
}
