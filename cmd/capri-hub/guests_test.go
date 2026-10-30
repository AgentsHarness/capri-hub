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
	conn, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/host", &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization":   []string{"Bearer " + token},
			"X-Hub-Deflate":   []string{"1"},
			"X-Hub-State-Ack": []string{"1"},
		},
	})
	if err != nil {
		t.Fatalf("host ws dial %s: %v", hostID, err)
	}
	conn.SetReadLimit(1 << 20)
	if _, _, err := conn.Read(ctx); err != nil { // hello
		t.Fatalf("host hello %s: %v", hostID, err)
	}
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

func (f *fakeHost) lastRequest() (relayedRequest, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.seen) == 0 {
		return relayedRequest{}, false
	}
	return f.seen[len(f.seen)-1], true
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
			Path   string          `json:"path"`
			Body   json.RawMessage `json:"body"`
			Method string          `json:"method"`
		}
		if json.Unmarshal(data, &frame) != nil || frame.Type != "request" {
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
			"v": 1, "type": "respond", "reqId": frame.ReqID, "status": 200, "body": out,
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

// TestGuestTokenAdminEndpoints: admin CRUD works; every management endpoint
// is 403 for a guest (not 401 — the FE shows "not allowed", not "log in").
func TestGuestTokenAdminEndpoints(t *testing.T) {
	f := newGuestFixture(t)

	res, body := f.do(t, f.admin, http.MethodGet, "/api/guest-tokens", nil)
	if res.StatusCode != 200 {
		t.Fatalf("list status = %d", res.StatusCode)
	}
	tokens, _ := body["tokens"].([]any)
	if len(tokens) != 1 {
		t.Fatalf("tokens = %v", body["tokens"])
	}

	// Create with a session.
	res, body = f.do(t, f.admin, http.MethodPost, "/api/guest-tokens/create", map[string]any{
		"label": "new", "expiresAt": 0,
		"sessions": []map[string]any{{"hostId": "h1", "sessionId": "s1", "cwd": "/w1"}},
	})
	if res.StatusCode != 200 {
		t.Fatalf("create status = %d body=%v", res.StatusCode, body)
	}
	created, _ := body["token"].(map[string]any)
	id, _ := created["id"].(string)
	if id == "" || created["token"] == "" {
		t.Fatalf("created = %v", created)
	}

	// Update label.
	res, body = f.do(t, f.admin, http.MethodPost, "/api/guest-tokens/update", map[string]any{
		"id": id, "label": "renamed",
	})
	if res.StatusCode != 200 {
		t.Fatalf("update = %d %v", res.StatusCode, body)
	}
	if tok, _ := body["token"].(map[string]any); tok["label"] != "renamed" {
		t.Fatalf("label not updated: %v", tok)
	}

	// Sessions add dedupes, remove is exact.
	f.do(t, f.admin, http.MethodPost, "/api/guest-tokens/sessions/add", map[string]any{
		"id": id, "items": []map[string]any{
			{"hostId": "h1", "sessionId": "s1"},
			{"hostId": "h1", "sessionId": "s1"},
			{"hostId": "h2", "sessionId": "s2"},
		},
	})
	_, body = f.do(t, f.admin, http.MethodGet, "/api/guest-tokens", nil)
	tokens, _ = body["tokens"].([]any)
	var sessions []any
	for _, tv := range tokens {
		tm, _ := tv.(map[string]any)
		if tm["id"] == id {
			sessions, _ = tm["sessions"].([]any)
		}
	}
	if len(sessions) != 2 {
		t.Fatalf("dedupe failed: %v", sessions)
	}
	f.do(t, f.admin, http.MethodPost, "/api/guest-tokens/sessions/remove", map[string]any{
		"id": id, "items": []map[string]any{{"hostId": "h1", "sessionId": "s1"}},
	})
	_, body = f.do(t, f.admin, http.MethodGet, "/api/guest-tokens", nil)
	tokens, _ = body["tokens"].([]any)
	for _, tv := range tokens {
		tm, _ := tv.(map[string]any)
		if tm["id"] != id {
			continue
		}
		got, _ := tm["sessions"].([]any)
		if len(got) != 1 {
			t.Fatalf("remove left %v", got)
		}
		row, _ := got[0].(map[string]any)
		if row["hostId"] != "h2" || row["sessionId"] != "s2" {
			t.Fatalf("removed the wrong entry: %v", row)
		}
	}

	// Delete.
	res, _ = f.do(t, f.admin, http.MethodPost, "/api/guest-tokens/delete", map[string]any{"id": id})
	if res.StatusCode != 200 {
		t.Fatalf("delete = %d", res.StatusCode)
	}
	if _, ok := f.h.GuestByID(id); ok {
		t.Error("deleted token still present")
	}

	// Guest: every management endpoint is 403.
	for _, path := range []string{
		"/api/guest-tokens",
		"/api/guest-tokens/create",
		"/api/guest-tokens/update",
		"/api/guest-tokens/delete",
		"/api/guest-tokens/sessions/add",
		"/api/guest-tokens/sessions/remove",
		"/api/guest-tokens/refresh",
	} {
		method := http.MethodGet
		if strings.HasSuffix(path, "create") || strings.HasSuffix(path, "update") ||
			strings.HasSuffix(path, "delete") || strings.HasSuffix(path, "add") ||
			strings.HasSuffix(path, "remove") || strings.HasSuffix(path, "refresh") {
			method = http.MethodPost
		}
		res, _ := f.do(t, f.guest.Token, method, path, map[string]any{"id": f.guest.ID})
		if res.StatusCode != 403 {
			t.Errorf("guest %s %s = %d, want 403", method, path, res.StatusCode)
		}
	}
	// Guest also cannot write prefs / pairing / hosts or read the event ring.
	for _, tr := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/prefs"},
		{http.MethodPut, "/api/prefs"},
		{http.MethodGet, "/api/pairing"},
		{http.MethodPost, "/api/pairing/rotate"},
		{http.MethodDelete, "/api/hosts/h1"},
		{http.MethodPost, "/api/hosts/h1/rename"},
		{http.MethodGet, "/api/events?host=h1&after=0"},
	} {
		res, _ := f.do(t, f.guest.Token, tr.method, tr.path, map[string]any{})
		if res.StatusCode != 403 {
			t.Errorf("guest %s %s = %d, want 403", tr.method, tr.path, res.StatusCode)
		}
	}
}

// TestAccessRole: admin sees {role:admin}; a guest sees its identity and
// whitelist; an unknown token is 401.
func TestAccessRole(t *testing.T) {
	f := newGuestFixture(t)

	_, body := f.do(t, f.admin, http.MethodGet, "/api/access-role", nil)
	if body["role"] != "admin" {
		t.Fatalf("admin role = %v", body["role"])
	}

	res, body := f.do(t, f.guest.Token, http.MethodGet, "/api/access-role", nil)
	if res.StatusCode != 200 || body["role"] != "guest" {
		t.Fatalf("guest access-role = %d %v", res.StatusCode, body)
	}
	guest, _ := body["guest"].(map[string]any)
	if guest["id"] != f.guest.ID || guest["label"] != "给小王" {
		t.Errorf("guest identity = %v", guest)
	}
	sessions, _ := body["sessions"].([]any)
	if len(sessions) != 2 {
		t.Fatalf("guest sessions = %v", sessions)
	}
	row, _ := sessions[0].(map[string]any)
	for _, key := range []string{"hostId", "sessionId", "cwd", "title", "hostName"} {
		if row[key] == nil {
			t.Errorf("session row missing %s: %v", key, row)
		}
	}

	res, _ = f.do(t, "g_bogus", http.MethodGet, "/api/access-role", nil)
	if res.StatusCode != 401 {
		t.Errorf("unknown token = %d, want 401", res.StatusCode)
	}
}

// TestGuestHostsFiltered: /api/hosts only returns the hosts the whitelist
// touches, and the default is a whitelisted host.
func TestGuestHostsFiltered(t *testing.T) {
	f := newGuestFixture(t)
	_, body := f.do(t, f.guest.Token, http.MethodGet, "/api/hosts", nil)
	hosts, _ := body["hosts"].([]any)
	if len(hosts) != 2 {
		t.Fatalf("hosts = %v", hosts)
	}
	for _, hv := range hosts {
		hm, _ := hv.(map[string]any)
		if hm["hostId"] != "h1" && hm["hostId"] != "h2" {
			t.Errorf("unexpected host leaked: %v", hm)
		}
	}
	if body["defaultHostId"] != "h1" {
		t.Errorf("defaultHostId = %v, want h1", body["defaultHostId"])
	}

	// Admin still sees the full registry shape.
	_, body = f.do(t, f.admin, http.MethodGet, "/api/hosts", nil)
	if _, ok := body["role"]; ok {
		t.Error("admin /api/hosts should not carry a guest role marker")
	}
}

// TestGuestRelayEnforcement: host outside the whitelist → 403; a path
// outside the read whitelist → 403; a sessionId outside the whitelist is
// rewritten to the host's first whitelisted session.
func TestGuestRelayEnforcement(t *testing.T) {
	f := newGuestFixture(t)

	res, _ := f.do(t, f.guest.Token, http.MethodPost, "/api/session-updates?host=h3",
		map[string]any{"sessionId": "s1"})
	if res.StatusCode != 403 {
		t.Errorf("foreign host = %d, want 403", res.StatusCode)
	}

	// Non-whitelisted endpoint (a write) is rejected even on a good host.
	res, _ = f.do(t, f.guest.Token, http.MethodPost, "/api/session-delete?host=h1",
		map[string]any{"sessionId": "s1", "cwd": "/w1"})
	if res.StatusCode != 403 {
		t.Errorf("write path = %d, want 403", res.StatusCode)
	}

	// Whitelisted session passes through unchanged.
	res, body := f.do(t, f.guest.Token, http.MethodPost, "/api/session-updates?host=h1",
		map[string]any{"sessionId": "s1", "cwd": "/w1"})
	if res.StatusCode != 200 {
		t.Fatalf("session-updates = %d %v", res.StatusCode, body)
	}
	echo, _ := body["echo"].(map[string]any)
	echoBody, _ := echo["body"].(map[string]any)
	if echoBody["sessionId"] != "s1" {
		t.Errorf("sessionId not forwarded: %v", echoBody)
	}

	// Out-of-scope session id on a whitelisted host falls back to the
	// host's first whitelisted session, and cwd follows it.
	res, body = f.do(t, f.guest.Token, http.MethodPost, "/api/session-updates?host=h1",
		map[string]any{"sessionId": "someone-else", "cwd": "/secret"})
	if res.StatusCode != 200 {
		t.Fatalf("fallback = %d %v", res.StatusCode, body)
	}
	echo, _ = body["echo"].(map[string]any)
	echoBody, _ = echo["body"].(map[string]any)
	if echoBody["sessionId"] != "s1" {
		t.Errorf("out-of-scope sessionId was not rewritten: %v", echoBody)
	}
	if echoBody["cwd"] != "/w1" {
		t.Errorf("cwd was not rewritten: %v", echoBody)
	}

	// No ?host= at all → the token's first whitelisted host.
	res, body = f.do(t, f.guest.Token, http.MethodPost, "/api/session-stats",
		map[string]any{"sessionId": "s2", "cwd": "/w2"})
	if res.StatusCode != 200 {
		t.Fatalf("default host relay = %d %v", res.StatusCode, body)
	}
	if _, ok := body["echo"]; !ok {
		t.Fatalf("default host did not reach h1: %v", body)
	}

	// Admin is not constrained.
	res, _ = f.do(t, f.admin, http.MethodPost, "/api/session-updates?host=h2",
		map[string]any{"sessionId": "anything"})
	if res.StatusCode != 200 {
		t.Errorf("admin relay = %d", res.StatusCode)
	}
}

// TestGuestRelayChildSession: a subagent child of a whitelisted session may
// be read through the relay (the subagent timeline pages /api/session-updates
// under the child id), with cwd still pinned to the whitelisted parent so the
// guest cannot steer the host's path join.
func TestGuestRelayChildSession(t *testing.T) {
	f := newGuestFixture(t)
	// The host announces the child on the parent's stream.
	f.h.RegisterRawEvents("h1", []json.RawMessage{
		json.RawMessage(`{"type":"subagent_spawned","seq":1,"sessionId":"s1","update":{"child_session_id":"child-1","subagent_id":"child-1"}}`),
	})

	res, body := f.do(t, f.guest.Token, http.MethodPost, "/api/session-updates?host=h1",
		map[string]any{"sessionId": "child-1", "cwd": "/tmp/child", "offset": -10})
	if res.StatusCode != 200 {
		t.Fatalf("child relay = %d %v", res.StatusCode, body)
	}
	echo, _ := body["echo"].(map[string]any)
	echoBody, _ := echo["body"].(map[string]any)
	if echoBody["sessionId"] != "child-1" {
		t.Errorf("child sessionId was rewritten: %v", echoBody)
	}
	if echoBody["cwd"] != "/w1" {
		t.Errorf("child cwd must be pinned to the whitelisted parent: %v", echoBody)
	}

	// A session with no recorded parent still falls back to the whitelist.
	res, body = f.do(t, f.guest.Token, http.MethodPost, "/api/session-updates?host=h1",
		map[string]any{"sessionId": "child-unknown", "cwd": "/tmp/x"})
	if res.StatusCode != 200 {
		t.Fatalf("fallback relay = %d %v", res.StatusCode, body)
	}
	echo, _ = body["echo"].(map[string]any)
	echoBody, _ = echo["body"].(map[string]any)
	if echoBody["sessionId"] != "s1" || echoBody["cwd"] != "/w1" {
		t.Errorf("unknown session was not rewritten to the whitelist: %v", echoBody)
	}
}

// TestGuestStatusRedacted: only the allowlisted fields survive, and a host
// active session outside the whitelist is pinned to a whitelisted one.
func TestGuestStatusRedacted(t *testing.T) {
	f := newGuestFixture(t)
	f.host1.respond("/api/status", map[string]any{
		"ok": true, "ready": true, "busy": false,
		// The host's active session belongs to someone else.
		"sessionId": "someone-else", "cwd": "/secret",
		"hostId": "h1", "hostName": "H1", "homeDir": "/home/x",
		"models": []any{}, "modes": map[string]any{}, "configOptions": map[string]any{},
		"roster":          []any{map[string]any{"sessionId": "secret"}},
		"pendingRequests": []any{map[string]any{"requestId": "p"}},
		"authMeta":        map[string]any{"token": "leak"},
	})
	res, body := f.do(t, f.guest.Token, http.MethodGet, "/api/status?host=h1", nil)
	if res.StatusCode != 200 {
		t.Fatalf("status = %d", res.StatusCode)
	}
	for _, gone := range []string{"roster", "pendingRequests", "authMeta"} {
		if _, ok := body[gone]; ok {
			t.Errorf("%s leaked to a guest: %v", gone, body[gone])
		}
	}
	for _, kept := range []string{"ready", "busy", "sessionId", "cwd", "hostId", "hostName", "homeDir", "models", "modes", "configOptions"} {
		if _, ok := body[kept]; !ok {
			t.Errorf("status lost %s: %v", kept, body)
		}
	}
	if body["sessionId"] != "s1" || body["cwd"] != "/w1" {
		t.Errorf("status session not pinned to the whitelist: %v", body)
	}

	// A whitelisted active session keeps the host's live cwd (it is the
	// same session, so the snapshot has no reason to win).
	f.host1.respond("/api/status", map[string]any{
		"ok": true, "ready": true, "sessionId": "s1", "cwd": "/w1-live",
		"hostId": "h1", "hostName": "H1",
	})
	_, body = f.do(t, f.guest.Token, http.MethodGet, "/api/status?host=h1", nil)
	if body["sessionId"] != "s1" || body["cwd"] != "/w1-live" {
		t.Errorf("whitelisted live session lost its cwd: %v", body)
	}
}

// TestGuestStatusCarriesOwnSessionState: the guest learns the state of the
// session it is watching (busy / awaiting + a pending summary) without
// seeing other sessions' requests, request ids, methods, or params. The flat
// host-wide `busy` must not leak through — only the scoped flag counts.
func TestGuestStatusCarriesOwnSessionState(t *testing.T) {
	f := newGuestFixture(t)
	f.host1.respond("/api/status", map[string]any{
		"ok": true, "ready": true,
		// Host-wide busy: a background session is running, the guest's is idle.
		"busy": true, "sessionId": "s1", "cwd": "/w1",
		"hostId": "h1", "hostName": "H1",
		"roster": []any{
			map[string]any{"sessionId": "s1", "busy": false, "awaitingInput": false},
			map[string]any{"sessionId": "other", "busy": true, "awaitingInput": true},
		},
		"pendingRequests": []any{
			map[string]any{
				"requestId": "acp_cr_9", "method": "session/request_permission",
				"sessionId": "other", "receivedAt": float64(1),
				"params": map[string]any{"toolCall": map[string]any{"title": "rm -rf /"}},
			},
		},
	})
	_, body := f.do(t, f.guest.Token, http.MethodGet, "/api/status?host=h1&session=s1", nil)
	if body["busy"] != false {
		t.Errorf("host-wide busy leaked to a guest watching an idle session: %v", body["busy"])
	}
	if body["sessionState"] != "idle" {
		t.Errorf("sessionState = %v, want idle", body["sessionState"])
	}
	if _, ok := body["pendingInput"]; ok {
		t.Errorf("another session's request surfaced: %v", body["pendingInput"])
	}

	// The guest's own session is blocked on a question; an older permission
	// request from a sibling is newer/older independent — only this session's
	// rows count, and only the count/kind/receivedAt come back.
	f.host1.respond("/api/status", map[string]any{
		"ok": true, "ready": true, "busy": true, "sessionId": "s1", "cwd": "/w1",
		"hostId": "h1", "hostName": "H1",
		"roster": []any{
			map[string]any{"sessionId": "s1", "busy": true, "awaitingInput": true},
		},
		"pendingRequests": []any{
			map[string]any{
				"requestId": "acp_cr_2", "method": "session/request_permission",
				"sessionId": "s1", "receivedAt": float64(2_000),
			},
			map[string]any{
				"requestId": "acp_cr_3", "method": "x.ai/ask_user_question",
				"sessionId": "s1", "receivedAt": float64(1_000),
			},
			map[string]any{
				"requestId": "acp_cr_4", "method": "x.ai/ask_user_question",
				"sessionId": "other", "receivedAt": float64(500),
			},
		},
	})
	_, body = f.do(t, f.guest.Token, http.MethodGet, "/api/status?host=h1&session=s1", nil)
	if body["sessionState"] != "awaiting" || body["awaitingInput"] != true {
		t.Errorf("blocked session not reported as awaiting: %v", body)
	}
	pi, _ := body["pendingInput"].(map[string]any)
	if pi["kind"] != "question" || pi["count"] != float64(2) || pi["receivedAt"] != float64(1_000) {
		t.Errorf("pendingInput = %v, want question/2/1000 (oldest of THIS session)", pi)
	}
	for _, leak := range []string{"requestId", "acp_cr_2", "acp_cr_3", "ask_user_question", "toolCall"} {
		raw, _ := json.Marshal(body)
		if strings.Contains(string(raw), leak) {
			t.Errorf("guest status leaked %q: %s", leak, raw)
		}
	}

	// No roster (old host): the flat busy describes the host's ACTIVE session
	// only. Watching a different whitelisted session must not inherit it.
	f.host1.respond("/api/status", map[string]any{
		"ok": true, "ready": true, "busy": true, "sessionId": "s-other", "cwd": "/w1",
		"hostId": "h1", "hostName": "H1",
	})
	_, body = f.do(t, f.guest.Token, http.MethodGet, "/api/status?host=h1&session=s1", nil)
	if body["sessionState"] != "idle" || body["busy"] != false {
		t.Errorf("host-wide busy leaked onto an unroster'd session: %v", body)
	}

	// A pending request is itself proof of awaiting — report it even when the
	// host's busy flag has not caught up.
	f.host1.respond("/api/status", map[string]any{
		"ok": true, "ready": true, "busy": false, "sessionId": "s1", "cwd": "/w1",
		"hostId": "h1", "hostName": "H1",
		"pendingRequests": []any{
			map[string]any{"method": "x.ai/mcp/elicit", "sessionId": "s1"},
		},
	})
	_, body = f.do(t, f.guest.Token, http.MethodGet, "/api/status?host=h1&session=s1", nil)
	pi, _ = body["pendingInput"].(map[string]any)
	if body["sessionState"] != "awaiting" || pi["kind"] != "mcp_elicit" {
		t.Errorf("pending without busy not reported as awaiting: %v", body)
	}
	// No receivedAt on this host → no countdown key (FE renders without it).
	if _, ok := pi["receivedAt"]; ok {
		t.Errorf("receivedAt invented out of thin air: %v", pi)
	}
}

// TestGuestRefresh: re-reads /api/sessions per host, updates titles and
// flags sessions the host no longer lists.
func TestGuestRefresh(t *testing.T) {
	f := newGuestFixture(t)
	f.host1.respond("/api/sessions", map[string]any{
		"ok": true,
		"sessions": []any{
			map[string]any{"sessionId": "s1", "cwd": "/w1-new", "title": "renamed title"},
		},
	})
	f.host2.respond("/api/sessions", map[string]any{
		"ok":       true,
		"sessions": []any{},
	})
	res, body := f.do(t, f.admin, http.MethodPost, "/api/guest-tokens/refresh",
		map[string]any{"id": f.guest.ID})
	if res.StatusCode != 200 {
		t.Fatalf("refresh = %d %v", res.StatusCode, body)
	}
	tok, _ := body["token"].(map[string]any)
	sessions, _ := tok["sessions"].([]any)
	if len(sessions) != 2 {
		t.Fatalf("sessions = %v", sessions)
	}
	for _, sv := range sessions {
		sm, _ := sv.(map[string]any)
		switch sm["sessionId"] {
		case "s1":
			if sm["title"] != "renamed title" {
				t.Errorf("title not refreshed: %v", sm)
			}
			if sm["cwd"] != "/w1-new" {
				t.Errorf("cwd not refreshed: %v", sm)
			}
			if sm["stale"] == true {
				t.Errorf("s1 should not be stale: %v", sm)
			}
		case "s2":
			if sm["stale"] != true {
				t.Errorf("s2 should be stale: %v", sm)
			}
		}
	}
	// A host that is offline keeps its previous snapshot: freshness can only
	// be asserted against a host that actually answered this refresh.
	f.host2.conn.Close(websocket.StatusNormalClosure, "")
	time.Sleep(50 * time.Millisecond)
	fresh, err := f.h.CreateGuestToken("fresh", 0, []hub.GuestSession{
		{HostID: "h2", SessionID: "s2", Title: "stale-check"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, body = f.do(t, f.admin, http.MethodPost, "/api/guest-tokens/refresh", map[string]any{"id": fresh.ID})
	got, _ := f.h.GuestByID(fresh.ID)
	if len(got.Sessions) != 1 {
		t.Fatalf("sessions = %+v", got.Sessions)
	}
	if got.Sessions[0].Stale {
		t.Error("offline host flipped a session to stale")
	}
	_ = body
}

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
