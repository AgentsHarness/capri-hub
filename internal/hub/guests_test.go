package hub

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestGuestsPersistAndReload: the token table survives a restart, and the
// file lives next to hub.json with 0600 perms.
func TestGuestsPersistAndReload(t *testing.T) {
	dir := t.TempDir()
	h := NewWithDir(dir)
	g, err := h.CreateGuestToken("给小王", 0, []GuestSession{
		{HostID: "h_office", HostName: "Office Mac", SessionID: "s_1a2b", Cwd: "/repo/acp-fe", Title: "访客模式设计"},
		{HostID: "h_vps", SessionID: "s_9c8d", Cwd: "/srv/api"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	path := filepath.Join(dir, "guests.json")
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("guests.json missing: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("guests.json mode = %o, want 600", st.Mode().Perm())
	}

	// Reload in a fresh hub over the same dir.
	h2 := NewWithDir(dir)
	got, ok := h2.GuestByToken(g.Token)
	if !ok {
		t.Fatal("token should survive reload")
	}
	if got.Label != "给小王" || len(got.Sessions) != 2 {
		t.Fatalf("reloaded = %+v", got)
	}
	if got.Sessions[0].Title != "访客模式设计" || got.Sessions[0].HostName != "Office Mac" {
		t.Errorf("session snapshot lost: %+v", got.Sessions[0])
	}
}

// TestGuestsConcurrentWritesKeepAllEntries: concurrent creates/adds must not
// lose records (each write persists the full table under the hub lock).
func TestGuestsConcurrentWritesKeepAllEntries(t *testing.T) {
	h := NewWithDir(t.TempDir())
	const n = 8
	var wg sync.WaitGroup
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			g, err := h.CreateGuestToken("", 0, []GuestSession{
				{HostID: "h1", SessionID: "s1"},
			})
			if err == nil {
				ids[i] = g.ID
			}
		}(i)
	}
	wg.Wait()
	if got := len(h.GuestTokens()); got != n {
		t.Fatalf("in-memory tokens = %d, want %d", got, n)
	}
	// And a reload must see them all — a lost update would show up here.
	h2 := NewWithDir(GuestDataDir(h))
	if got := len(h2.GuestTokens()); got != n {
		t.Fatalf("persisted tokens = %d, want %d", got, n)
	}
}

// TestGuestTokenLookup: normal, expired, revoked, unknown.
func TestGuestTokenLookup(t *testing.T) {
	h := NewWithDir(t.TempDir())
	now := time.Now()
	live, _ := h.CreateGuestToken("live", 0, nil)
	expired, _ := h.CreateGuestToken("expired", now.Add(-time.Minute).Unix(), nil)
	// A token that is still "not expired" by wall clock.
	future, _ := h.CreateGuestToken("future", now.Add(time.Hour).Unix(), nil)
	revoked, _ := h.CreateGuestToken("revoked", 0, nil)
	if _, err := h.UpdateGuestToken(revoked.ID, nil, nil, boolPtr(true)); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if _, ok := h.GuestByToken(live.Token); !ok {
		t.Error("live token should resolve")
	}
	if _, ok := h.GuestByToken(expired.Token); ok {
		t.Error("expired token must not resolve")
	}
	if _, ok := h.GuestByToken(future.Token); !ok {
		t.Error("not-yet-expired token should resolve")
	}
	if _, ok := h.GuestByToken(revoked.Token); ok {
		t.Error("revoked token must not resolve")
	}
	if _, ok := h.GuestByToken("g_does-not-exist"); ok {
		t.Error("unknown token must not resolve")
	}
	if _, ok := h.GuestByToken(""); ok {
		t.Error("empty token must not resolve")
	}
}

func boolPtr(b bool) *bool { return &b }

// TestGuestTokenShape: 令牌要短到能贴进分享链接 / 手抄——`g_` + 22 个
// base64url 字符（16 字节随机数 = 128 bit）。旧格式是 66 字符的 hex，
// 手抄不现实。这里同时锁住字符集（URL-safe，能直接进 fragment）与唯一性。
func TestGuestTokenShape(t *testing.T) {
	h := NewWithDir(t.TempDir())
	const wantLen = 24 // "g_" + 22
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		g, err := h.CreateGuestToken("t", 0, nil)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if len(g.Token) != wantLen {
			t.Fatalf("token %q len = %d, want %d", g.Token, len(g.Token), wantLen)
		}
		if !strings.HasPrefix(g.Token, "g_") {
			t.Fatalf("token %q must keep the g_ prefix", g.Token)
		}
		for _, c := range g.Token[2:] {
			ok := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
				c == '-' || c == '_'
			if !ok {
				t.Fatalf("token %q has non-base64url char %q", g.Token, c)
			}
		}
		if seen[g.Token] {
			t.Fatalf("duplicate token %q", g.Token)
		}
		seen[g.Token] = true
	}
}

// TestGuestTokenLegacyStillResolves：旧格式（长的 hex）已经在访客手里的
// 令牌不能因为生成器换了就作废——查表是按明文比的。
func TestGuestTokenLegacyStillResolves(t *testing.T) {
	h := NewWithDir(t.TempDir())
	legacy := GuestToken{
		ID:    "g_legacy",
		Token: "g_" + strings.Repeat("ab", 32),
		Label: "老访客",
	}
	h.mu.Lock()
	h.guests = append(h.guests, legacy)
	h.mu.Unlock()
	got, ok := h.GuestByToken(legacy.Token)
	if !ok || got.ID != legacy.ID {
		t.Fatalf("legacy long token must still resolve, got %+v ok=%v", got, ok)
	}
}

// TestGuestSessionWhitelistOps: add dedupes, remove is exact to (host, session).
func TestGuestSessionWhitelistOps(t *testing.T) {
	h := NewWithDir(t.TempDir())
	g, _ := h.CreateGuestToken("t", 0, nil)

	g, err := h.AddGuestSessions(g.ID, []GuestSession{
		{HostID: "h1", SessionID: "s1", Title: "one"},
		{HostID: "h1", SessionID: "s2", Title: "two"},
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if len(g.Sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(g.Sessions))
	}
	// Re-adding the same (host, session) updates in place, keeping AddedAt.
	firstAdded := g.Sessions[0].AddedAt
	time.Sleep(2 * time.Millisecond)
	g, _ = h.AddGuestSessions(g.ID, []GuestSession{{HostID: "h1", SessionID: "s1", Title: "renamed"}})
	if len(g.Sessions) != 2 {
		t.Fatalf("duplicate add grew the list: %+v", g.Sessions)
	}
	if g.Sessions[0].Title != "renamed" {
		t.Errorf("title not refreshed: %+v", g.Sessions[0])
	}
	if g.Sessions[0].AddedAt != firstAdded {
		t.Errorf("AddedAt should be kept from the first add")
	}

	// Same session id on a DIFFERENT host is a different entry.
	g, _ = h.AddGuestSessions(g.ID, []GuestSession{{HostID: "h2", SessionID: "s1"}})
	if len(g.Sessions) != 3 {
		t.Fatalf("cross-host add = %d sessions, want 3", len(g.Sessions))
	}
	// Remove is exact: (h1, s1) only.
	g, _ = h.RemoveGuestSessions(g.ID, []GuestSessionRef{{HostID: "h1", SessionID: "s1"}})
	if len(g.Sessions) != 2 {
		t.Fatalf("after remove = %+v", g.Sessions)
	}
	for _, s := range g.Sessions {
		if s.HostID == "h1" && s.SessionID == "s1" {
			t.Error("removed entry still present")
		}
	}
}

// TestGuestSessionFor: the request's session when whitelisted, else the
// host's first whitelisted session; ("","") when the host has none.
func TestGuestSessionFor(t *testing.T) {
	g := GuestToken{Sessions: []GuestSession{
		{HostID: "h1", SessionID: "a", Cwd: "/a"},
		{HostID: "h1", SessionID: "b", Cwd: "/b"},
		{HostID: "h2", SessionID: "c", Cwd: "/c"},
	}}
	if sid, cwd := GuestSessionFor(g, "h1", "b"); sid != "b" || cwd != "/b" {
		t.Errorf("whitelisted pick = %q,%q", sid, cwd)
	}
	if sid, _ := GuestSessionFor(g, "h1", "zzz"); sid != "a" {
		t.Errorf("out-of-scope pick = %q, want first of host (a)", sid)
	}
	if sid, _ := GuestSessionFor(g, "h1", ""); sid != "a" {
		t.Errorf("empty pick = %q, want first of host (a)", sid)
	}
	if sid, _ := GuestSessionFor(g, "h9", "a"); sid != "" {
		t.Errorf("unknown host = %q, want empty", sid)
	}
	if !GuestAllowsSession(g, "h2", "c") {
		t.Error("h2/c should be allowed")
	}
	if GuestAllowsSession(g, "h2", "a") {
		t.Error("session id from another host must not be allowed")
	}
}

// TestGuestRefreshMarksStale uses ReplaceGuestSessionSnapshot directly (the
// handler-level refresh is covered in cmd/capri-hub).
func TestGuestRefreshMarksStale(t *testing.T) {
	h := NewWithDir(t.TempDir())
	g, _ := h.CreateGuestToken("t", 0, []GuestSession{
		{HostID: "h1", SessionID: "s1", Title: "old"},
		{HostID: "h1", SessionID: "s2", Title: "gone"},
	})
	next := []GuestSession{
		{HostID: "h1", SessionID: "s1", Title: "new"},
		{HostID: "h1", SessionID: "s2", Stale: true},
	}
	got, err := h.ReplaceGuestSessionSnapshot(g.ID, next)
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	if got.Sessions[0].Title != "new" || got.Sessions[0].Stale {
		t.Errorf("s1 = %+v", got.Sessions[0])
	}
	if !got.Sessions[1].Stale {
		t.Errorf("s2 should be stale: %+v", got.Sessions[1])
	}
	// Persisted, not just in memory.
	h2 := NewWithDir(GuestDataDir(h))
	reloaded, _ := h2.GuestByID(g.ID)
	if !reloaded.Sessions[1].Stale {
		t.Error("stale flag did not persist")
	}
}

// TestGuestUnknownIDErrors: update/delete/add/remove on a missing id.
func TestGuestUnknownIDErrors(t *testing.T) {
	h := NewWithDir(t.TempDir())
	if _, err := h.UpdateGuestToken("nope", nil, nil, nil); err != ErrGuestUnknown {
		t.Errorf("update err = %v", err)
	}
	if err := h.DeleteGuestToken("nope"); err != ErrGuestUnknown {
		t.Errorf("delete err = %v", err)
	}
	if _, err := h.AddGuestSessions("nope", nil); err != ErrGuestUnknown {
		t.Errorf("add err = %v", err)
	}
	if _, err := h.RemoveGuestSessions("nope", nil); err != ErrGuestUnknown {
		t.Errorf("remove err = %v", err)
	}
	if _, err := h.ReplaceGuestSessionSnapshot("nope", nil); err != ErrGuestUnknown {
		t.Errorf("replace err = %v", err)
	}
}

// TestGuestCorruptFileStartsEmpty: an unreadable guests.json must not panic
// the hub; the next write rebuilds it.
func TestGuestCorruptFileStartsEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "guests.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := NewWithDir(dir)
	if len(h.GuestTokens()) != 0 {
		t.Fatalf("tokens = %d, want 0", len(h.GuestTokens()))
	}
	if _, err := h.CreateGuestToken("t", 0, nil); err != nil {
		t.Fatalf("create after corrupt file: %v", err)
	}
	var doc guestFileDoc
	raw, _ := os.ReadFile(filepath.Join(dir, "guests.json"))
	if json.Unmarshal(raw, &doc) != nil || len(doc.Tokens) != 1 {
		t.Fatalf("rebuilt file unreadable: %s", raw)
	}
}

// TestGuestBroadcastFilter: a guest subscriber only receives events whose
// top-level sessionId is whitelisted, and never hub-level events.
func TestGuestBroadcastFilter(t *testing.T) {
	h := NewWithDir("")
	g, _ := h.CreateGuestToken("t", 0, []GuestSession{
		{HostID: "h1", SessionID: "s1"},
		{HostID: "h2", SessionID: "s9"},
	})
	ch, unsub, kicked, ok := h.TrySubscribeGuest(0, "h1", g)
	if !ok || kicked == nil {
		t.Fatal("guest subscribe failed")
	}
	defer unsub()

	h.Broadcast(Event{"type": "chunk", "text": "ok", "hostId": "h1", "sessionId": "s1"})
	h.Broadcast(Event{"type": "chunk", "text": "other-session", "hostId": "h1", "sessionId": "s2"})
	h.Broadcast(Event{"type": "chunk", "text": "other-host", "hostId": "h3", "sessionId": "s1"})
	h.Broadcast(Event{"type": "hosts_changed", "params": map[string]any{}})
	h.Broadcast(Event{"type": "chunk", "text": "no-session", "hostId": "h1"})

	want := "ok"
	select {
	case ev := <-ch:
		if ev["text"] != want {
			t.Fatalf("first event = %+v, want only the whitelisted one", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("whitelisted event never arrived")
	}
	// Nothing else should follow.
	select {
	case ev := <-ch:
		t.Fatalf("filtered event leaked: %+v", ev)
	case <-time.After(150 * time.Millisecond):
	}
}

// TestGuestKickOnRevoke: revoking a token kicks live guest subscribers.
func TestGuestKickOnRevoke(t *testing.T) {
	h := NewWithDir("")
	g, _ := h.CreateGuestToken("t", 0, []GuestSession{{HostID: "h1", SessionID: "s1"}})
	_, unsub, kicked, ok := h.TrySubscribeGuest(0, "h1", g)
	if !ok {
		t.Fatal("subscribe failed")
	}
	defer unsub()
	if _, err := h.UpdateGuestToken(g.ID, nil, nil, boolPtr(true)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	select {
	case <-kicked:
	case <-time.After(time.Second):
		t.Fatal("guest subscriber was not kicked on revoke")
	}
}

// TestGuestChildScope: a guest whose whitelist names the PARENT session also
// receives that parent's subagent child transcript (the child is its own
// session id), and only that one level — an unrelated session stays hidden.
func TestGuestChildScope(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	g, _ := h.CreateGuestToken("t", 0, []GuestSession{{HostID: "h1", SessionID: "parent"}})

	// Host announces the child on the parent's event stream.
	h.RegisterRawEvents("h1", []json.RawMessage{
		json.RawMessage(`{"type":"subagent_spawned","seq":1,"sessionId":"parent","update":{"child_session_id":"child-1","subagent_id":"child-1"}}`),
	})

	ch, unsub, _, ok := h.TrySubscribeGuest(0, "h1", g)
	if !ok {
		t.Fatal("guest subscribe failed")
	}
	defer unsub()

	if !h.GuestChildAllowed(g, "h1", "child-1") {
		t.Fatal("child of a whitelisted parent should be readable")
	}
	if h.GuestChildAllowed(g, "h1", "stranger") {
		t.Error("session with no recorded parent must stay out of scope")
	}

	h.Broadcast(Event{"type": "chunk", "text": "parent", "hostId": "h1", "sessionId": "parent"})
	h.Broadcast(Event{"type": "chunk", "text": "child", "hostId": "h1", "sessionId": "child-1"})
	h.Broadcast(Event{"type": "chunk", "text": "stranger", "hostId": "h1", "sessionId": "stranger"})

	got := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case ev := <-ch:
			// The spawn announcement itself is the parent's event (expected);
			// the test is about what the chunks below it may carry.
			if ev["type"] != "chunk" {
				i--
				continue
			}
			got[ev["text"].(string)] = true
		case <-time.After(time.Second):
			t.Fatalf("guest missed event %d: %v", i, got)
		}
	}
	select {
	case ev := <-ch:
		if ev["type"] == "chunk" {
			t.Fatalf("out-of-scope event leaked: %+v", ev)
		}
	case <-time.After(150 * time.Millisecond):
	}
	if !got["parent"] || !got["child"] {
		t.Fatalf("guest events = %v, want parent + child", got)
	}
}

// TestGuestChildScopeNeedsWhitelistedParent: a child whose parent is NOT
// whitelisted stays hidden (the relation alone grants nothing).
func TestGuestChildScopeNeedsWhitelistedParent(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	g, _ := h.CreateGuestToken("t", 0, []GuestSession{{HostID: "h1", SessionID: "shared"}})
	h.RegisterRawEvents("h1", []json.RawMessage{
		json.RawMessage(`{"type":"subagent_spawned","sessionId":"private","update":{"child_session_id":"child-2","subagent_id":"child-2"}}`),
	})
	ch, unsub, _, ok := h.TrySubscribeGuest(0, "h1", g)
	if !ok {
		t.Fatal("guest subscribe failed")
	}
	defer unsub()
	if h.GuestChildAllowed(g, "h1", "child-2") {
		t.Error("child of a non-whitelisted parent must not be readable")
	}
	h.Broadcast(Event{"type": "chunk", "text": "leak", "hostId": "h1", "sessionId": "child-2"})
	select {
	case ev := <-ch:
		t.Fatalf("child of a private parent leaked: %+v", ev)
	case <-time.After(150 * time.Millisecond):
	}
}

// TestAdminSubscriberUnaffected: admin subscribers still see hub-level
// events and every host.
func TestAdminSubscriberUnaffected(t *testing.T) {
	h := NewWithDir("")
	ch, unsub, ok := h.TrySubscribeHost(0, "")
	if !ok {
		t.Fatal("subscribe failed")
	}
	defer unsub()
	h.Broadcast(Event{"type": "hosts_changed"})
	h.Broadcast(Event{"type": "chunk", "hostId": "h9", "sessionId": "s9"})
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case ev := <-ch:
			seen[ev["type"].(string)] = true
		case <-time.After(time.Second):
			t.Fatalf("admin missed event %d: %v", i, seen)
		}
	}
	if !seen["hosts_changed"] || !seen["chunk"] {
		t.Fatalf("admin events = %v", seen)
	}
}
