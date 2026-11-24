package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/internal/hub"
	"github.com/coder/websocket"
)

// ── helpers ───────────────────────────────────────────────────────────

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
	spawn, _ := json.Marshal(map[string]any{
		"v": 3, "type": "events", "seq": 1, "ack": 0,
		"events": []any{map[string]any{
			"type": "subagent_spawned", "seq": 1, "sessionId": "s1",
			"update": map[string]any{"child_session_id": "child-1", "subagent_id": "child-1"},
		}},
	})
	if err := f.host1.conn.Write(context.Background(), websocket.MessageText, spawn); err != nil {
		t.Fatalf("spawn event: %v", err)
	}
	// Wait until the hub has learned the relation (it is applied synchronously
	// on the host read path, but the relay below may race the session loop).
	deadline := time.Now().Add(2 * time.Second)
	for f.h.GuestParentOf("h1", "child-1") == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

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
