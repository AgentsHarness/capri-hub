package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/internal/hub"
	"github.com/coder/websocket"
)

// ── helpers ───────────────────────────────────────────────────────────

// relayedRequest is what the fake host observed for one relayed request.
type relayedRequest struct {
	Path string
	Body map[string]any
}

// fakeHost is a host uplink that answers every relayed request itself. The
// answer carries `echo` (path + parsed body) so tests can assert what the
// hub actually forwarded (host/session rewriting), and lets a test install
// per-path canned bodies (e.g. /api/sessions for refresh).
type fakeHost struct {
	conn   *websocket.Conn
	mu     sync.Mutex
	seen   []relayedRequest
	canned map[string]any
}

func dialFakeHost(t *testing.T, ctx context.Context, srv *httptest.Server, h *hub.Hub, hostID, name string) *fakeHost {
	t.Helper()
	code, _ := h.PairingCode()
	token, err := h.Pair(code, hostID, name)
	if err != nil {
		t.Fatalf("pair %s: %v", hostID, err)
	}
	conn := dialHostWithToken(t, ctx, srv, hostID, token, 500+hostEpochSeq.Add(1))
	f := &fakeHost{conn: conn, canned: map[string]any{}}
	go f.serve(ctx)
	return f
}

// respond installs a canned body for one path (e.g. /api/sessions).
func (f *fakeHost) respond(path string, body any) {
	f.mu.Lock()
	f.canned[path] = body
	f.mu.Unlock()
}

func (f *fakeHost) serve(ctx context.Context) {
	for {
		_, data, err := f.conn.Read(ctx)
		if err != nil {
			return
		}
		var frame struct {
			Type   string          `json:"type"`
			ReqID  string          `json:"reqId"`
			Seq    uint64          `json:"seq"`
			Probe  uint64          `json:"probe"`
			Path   string          `json:"path"`
			Body   json.RawMessage `json:"body"`
			Method string          `json:"method"`
		}
		if json.Unmarshal(data, &frame) != nil {
			continue
		}
		if frame.Type == "hb" && frame.Probe != 0 {
			ack, _ := json.Marshal(map[string]any{
				"v": 3, "type": "hb", "probeAck": frame.Probe, "status": map[string]any{},
			})
			_ = f.conn.Write(ctx, websocket.MessageText, ack)
			continue
		}
		if frame.Type != "request" {
			continue
		}
		var body map[string]any
		if len(frame.Body) > 0 {
			_ = json.Unmarshal(frame.Body, &body)
		}
		f.mu.Lock()
		f.seen = append(f.seen, relayedRequest{Path: frame.Path, Body: body})
		canned, hasCanned := f.canned[frame.Path]
		f.mu.Unlock()

		var out any
		if hasCanned {
			out = canned
		} else if frame.Path == "/api/status" {
			out = map[string]any{
				"ok": true, "ready": true, "busy": false, "sessionId": "s1", "cwd": "/w",
				"hostId": "h1", "hostName": "H1", "homeDir": "/home/x",
				"models": []any{}, "modes": map[string]any{}, "configOptions": map[string]any{},
				"roster":          []any{map[string]any{"sessionId": "secret"}},
				"pendingRequests": []any{map[string]any{"requestId": "p"}},
				"authMeta":        map[string]any{"token": "leak"},
			}
		} else {
			out = map[string]any{"ok": true, "echo": map[string]any{"path": frame.Path, "body": body}}
		}
		resp, _ := json.Marshal(map[string]any{
			"v": 3, "type": "respond", "reqId": frame.ReqID, "seq": 0,
			"ack": frame.Seq, "chunkSeq": 1, "status": 200, "body": out,
		})
		_ = f.conn.Write(ctx, websocket.MessageText, resp)
	}
}

// guestFixture boots a handler with two paired fake hosts and one guest
// token whose whitelist spans (h1,s1) and (h2,s2).
type guestFixture struct {
	srv     *httptest.Server
	h       *hub.Hub
	admin   string
	guest   hub.GuestToken
	tickets *feTicketStore
	host1   *fakeHost
	host2   *fakeHost
}

func newGuestFixture(t *testing.T) *guestFixture {
	t.Helper()
	h := hub.NewWithDir(t.TempDir())
	tickets := newFETicketStore()
	lim := newPairLimiter()
	const secret = "admin-secret"
	srv := httptest.NewServer(buildHandler(h, secret, tickets, lim, nil))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	g, err := h.CreateGuestToken("给小王", 0, []hub.GuestSession{
		{HostID: "h1", HostName: "H1", SessionID: "s1", Cwd: "/w1", Title: "one"},
		{HostID: "h2", HostName: "H2", SessionID: "s2", Cwd: "/w2", Title: "two"},
	})
	if err != nil {
		t.Fatalf("create guest: %v", err)
	}
	f := &guestFixture{srv: srv, h: h, admin: secret, guest: g, tickets: tickets}
	f.host1 = dialFakeHost(t, ctx, srv, h, "h1", "H1")
	f.host2 = dialFakeHost(t, ctx, srv, h, "h2", "H2")
	t.Cleanup(func() {
		f.host1.conn.Close(websocket.StatusNormalClosure, "")
		f.host2.conn.Close(websocket.StatusNormalClosure, "")
	})
	return f
}

// guestWSURL builds a /ws/fe URL carrying a single-use ticket for the
// fixture's guest token (the WS gate no longer accepts ?token=).
func (f *guestFixture) guestWSURL(t *testing.T, host string) string {
	t.Helper()
	ticket, _ := f.tickets.issue(f.guest.ID)
	u := strings.Replace(f.srv.URL, "http", "ws", 1) + "/ws/fe?ticket=" + ticket
	if host != "" {
		u += "&host=" + host
	}
	return u
}

func (f *guestFixture) do(t *testing.T, token, method, path string, body any) (*http.Response, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, f.srv.URL+path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return res, out
}

func guestBoolPtr(b bool) *bool { return &b }

// ── tests ─────────────────────────────────────────────────────────────
