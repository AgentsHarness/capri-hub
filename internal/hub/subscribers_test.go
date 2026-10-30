package hub

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestSubscribersSnapshot: the admin panel's roster reports who is watching
// — registration time, address, browser, credential — and follows the
// host/session each page declares. These fields are display-only, so a
// wrong value shows the operator a lie rather than breaking fan-out; the
// test pins the values the panel renders.
func TestSubscribersSnapshot(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")

	adminCh, adminUnsub, ok := h.TrySubscribeHostInfo(0, "h1", SubscriberInfo{
		IP:   "203.0.113.9",
		UA:   "Mozilla/5.0",
		Role: "admin",
	})
	if !ok {
		t.Fatal("TrySubscribeHostInfo refused")
	}
	defer adminUnsub()

	guest := GuestToken{
		ID: "g_abc123", Label: "小王", ExpiresAt: 0,
		Sessions: []GuestSession{{HostID: "h1", SessionID: "s1"}},
	}
	guestCh, guestUnsub, _, ok := h.TrySubscribeGuestInfo(0, "h1", guest, SubscriberInfo{
		IP: "198.51.100.4", UA: "Safari", Role: "guest",
		GuestID: "g_abc123", GuestLabel: "小王",
	})
	if !ok {
		t.Fatal("TrySubscribeGuestInfo refused")
	}
	defer guestUnsub()

	// Declared session/host land on the row (the subscribe control frame
	// path calls these two setters).
	if !h.SetSubscriberHost(adminCh, "h1") {
		t.Fatal("SetSubscriberHost refused a live channel")
	}
	if !h.SetSubscriberSession(adminCh, "s-admin") {
		t.Fatal("SetSubscriberSession refused a live admin channel")
	}
	if !h.SetSubscriberSession(guestCh, "s1") {
		t.Fatal("SetSubscriberSession refused a live guest channel")
	}

	rows := h.Subscribers()
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	// Registration order (id ascending), so the panel does not reshuffle.
	if rows[0].ID >= rows[1].ID {
		t.Fatalf("rows not ordered by registration id: %+v", rows)
	}
	a, g := rows[0], rows[1]
	if a.IP != "203.0.113.9" || a.UserAgent != "Mozilla/5.0" || a.Role != "admin" {
		t.Errorf("admin identity row = %+v", a)
	}
	if a.HostID != "h1" || a.SessionID != "s-admin" {
		t.Errorf("admin host/session = %q/%q, want h1/s-admin", a.HostID, a.SessionID)
	}
	if a.GuestID != "" || a.GuestLabel != "" {
		t.Errorf("admin row must not carry guest identity: %+v", a)
	}
	if g.Role != "guest" || g.GuestID != "g_abc123" || g.GuestLabel != "小王" {
		t.Errorf("guest identity row = %+v", g)
	}
	if g.IP != "198.51.100.4" || g.SessionID != "s1" {
		t.Errorf("guest ip/session = %q/%q", g.IP, g.SessionID)
	}
	if a.ConnectedAt <= 0 || time.Since(time.UnixMilli(a.ConnectedAt)) > time.Minute {
		t.Errorf("connectedAt = %d, want a recent epoch-ms stamp", a.ConnectedAt)
	}

	// A host switch that names no session clears the old one: the row must
	// not keep pointing at a transcript on the host the page just left.
	h.SetSubscriberSession(adminCh, "")
	if rows := h.Subscribers(); rows[0].SessionID != "" {
		t.Errorf("session after clear = %q, want empty", rows[0].SessionID)
	}

	// Leaving removes the row — the panel polls this snapshot.
	guestUnsub()
	if rows := h.Subscribers(); len(rows) != 1 || rows[0].Role != "admin" {
		t.Fatalf("after guest left rows = %+v", rows)
	}
}

// TestSubscriberIDFor: hello carries the socket's own row id so the panel
// can mark "this page" — two tabs on one machine share an address and UA.
func TestSubscriberIDFor(t *testing.T) {
	h := NewWithDir("")
	ch, unsub, ok := h.TrySubscribeHost(0, "")
	if !ok {
		t.Fatal("TrySubscribeHost refused")
	}
	id, found := h.SubscriberIDFor(ch)
	if !found || id != h.Subscribers()[0].ID {
		t.Fatalf("SubscriberIDFor = %d/%v, want the snapshot row id", id, found)
	}
	unsub()
	if _, found := h.SubscriberIDFor(ch); found {
		t.Fatal("SubscriberIDFor still finds an unsubscribed channel")
	}
}

// TestSubscriberSessionUnchangedByGuestScope: recording a session is
// bookkeeping; it must not widen what a guest receives.
func TestSubscriberSessionIsBookkeepingOnly(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	guest := GuestToken{
		ID: "g_1", Label: "visitor",
		Sessions: []GuestSession{{HostID: "h1", SessionID: "s1"}},
	}
	ch, unsub, _, ok := h.TrySubscribeGuestInfo(0, "h1", guest, SubscriberInfo{Role: "guest"})
	if !ok {
		t.Fatal("TrySubscribeGuestInfo refused")
	}
	defer unsub()

	h.SetSubscriberSession(ch, "s-not-whitelisted")
	h.Broadcast(Event{"type": "prompt_complete", "hostId": "h1", "sessionId": "s-not-whitelisted"})
	select {
	case ev := <-ch:
		t.Fatalf("guest received an event for an out-of-scope session: %v", ev)
	case <-time.After(150 * time.Millisecond):
	}
}

// ── 上行会话过滤：hub 侧「页面正在看哪些会话」──────────────────────

// 未声明会话的页面让集合退化成 all（host 因此不过滤）。`subscribe` 帧只
// 记名册（旧 FE 也发它，且可能不带 session），不算 viewing 声明。
func TestViewingAllWhenPageSilent(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	ch, unsub, ok1 := h.TrySubscribeHost(0, "h1")
	if !ok1 {
		t.Fatal("TrySubscribeHost refused")
	}
	defer unsub()

	v, _, ok := testViewing(h, "h1")
	if !ok || !v.All {
		t.Fatalf("viewing = %+v ok=%v, want all (page has not declared a session)", v, ok)
	}
	// The subscribe-frame path records the roster session but must NOT
	// narrow the host: an old FE never sends anything else.
	if !h.SetSubscriberSession(ch, "s1") {
		t.Fatal("SetSubscriberSession refused a live channel")
	}
	if v, _, ok := testViewing(h, "h1"); !ok || !v.All {
		t.Fatalf("viewing after subscribe-only = %+v ok=%v, want all", v, ok)
	}
	// The explicit viewing frame is what narrows it.
	if !h.SetSubscriberViewing(ch, "s1") {
		t.Fatal("SetSubscriberViewing refused a live channel")
	}
	v, _, ok = testViewing(h, "h1")
	if !ok || v.All || len(v.Sessions) != 1 || v.Sessions[0] != "s1" {
		t.Fatalf("viewing after declare = %+v ok=%v, want [s1]", v, ok)
	}
}

// 两个页面看不同会话 → 并集；切走后旧会话从集合里消失。
func TestViewingUnionAcrossPages(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	ch1, unsub1, ok1 := h.TrySubscribeHost(0, "h1")
	if !ok1 {
		t.Fatal("TrySubscribeHost refused")
	}
	defer unsub1()
	ch2, unsub2, ok2 := h.TrySubscribeHost(0, "h1")
	if !ok2 {
		t.Fatal("TrySubscribeHost refused")
	}
	defer unsub2()
	h.SetSubscriberViewing(ch1, "s1")
	h.SetSubscriberViewing(ch2, "s2")

	v, _, _ := testViewing(h, "h1")
	if len(v.Sessions) != 2 || v.Sessions[0] != "s1" || v.Sessions[1] != "s2" {
		t.Fatalf("viewing = %+v, want sorted [s1 s2]", v)
	}

	h.SetSubscriberViewing(ch2, "s3")
	v, _, _ = testViewing(h, "h1")
	if len(v.Sessions) != 2 || v.Sessions[0] != "s1" || v.Sessions[1] != "s3" {
		t.Fatalf("viewing after switch = %+v, want [s1 s3]", v)
	}
}

// 只订阅别的 host 的页面不贡献会话，也不让集合变成 all。
func TestViewingIgnoresOtherHostWatchers(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	testPair(t, h, "h2", "H2")
	ch1, unsub1, ok1 := h.TrySubscribeHost(0, "h1")
	if !ok1 {
		t.Fatal("TrySubscribeHost refused")
	}
	defer unsub1()
	h.SetSubscriberViewing(ch1, "s1")

	other, otherUnsub, ok := h.TrySubscribeHost(0, "h2")
	if !ok {
		t.Fatal("TrySubscribeHost refused")
	}
	defer otherUnsub()
	// 这个页面在 h2 上没声明会话——不得把 h1 的集合拉成 all。
	_ = other

	v, _, ok := testViewing(h, "h1")
	if !ok || v.All || len(v.Sessions) != 1 || v.Sessions[0] != "s1" {
		t.Fatalf("viewing for h1 = %+v ok=%v, want [s1]", v, ok)
	}
}

// 子代理子会话跟着父会话进集合（一层）。
func TestViewingExpandsSubagentChild(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	ch, unsub, ok1 := h.TrySubscribeHost(0, "h1")
	if !ok1 {
		t.Fatal("TrySubscribeHost refused")
	}
	defer unsub()
	h.SetSubscriberViewing(ch, "parent")
	h.noteGuestChild("h1", "parent", "child", "sub-1")

	v, _, _ := testViewing(h, "h1")
	got := map[string]bool{}
	for _, sid := range v.Sessions {
		got[sid] = true
	}
	if !got["parent"] || !got["child"] {
		t.Fatalf("viewing = %v, want parent + child", v.Sessions)
	}
}

// 没有订阅者时不下发集合（host 此时本来就被 subscribers==0 暂停）。
func TestViewingAbsentWithoutWatchers(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	if v, _, ok := testViewing(h, "h1"); ok {
		t.Fatalf("viewing = %+v, want no frame without watchers", v)
	}
}

// 页面显式声明「当前没有会话」（空串）不等于「不知道怎么过滤」：它仍算
// 支持 viewing 协议的听众，只是不贡献会话。旧 FE 从不 declarations，
// 才会把集合拉成 all。
func TestViewingEmptyDeclarationIsNotAll(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	ch, unsub, ok := h.TrySubscribeHost(0, "h1")
	if !ok {
		t.Fatal("TrySubscribeHost refused")
	}
	defer unsub()
	// 未声明任何内容：全量放行。
	if v, _, ok := testViewing(h, "h1"); !ok || !v.All {
		t.Fatalf("viewing before any declaration = %+v ok=%v, want all", v, ok)
	}
	// 显式声明空：不再是 all（host 可以放心裁剪），只是集合为空。
	if !h.SetSubscriberViewing(ch, "") {
		t.Fatal("SetSubscriberViewing refused")
	}
	v, _, ok := testViewing(h, "h1")
	if !ok || v.All {
		t.Fatalf("viewing after empty declaration = %+v ok=%v, want a narrowable empty set", v, ok)
	}
	if len(v.Sessions) != 0 {
		t.Fatalf("viewing sessions = %v, want empty", v.Sessions)
	}
}

// A page-supplied session id longer than maxViewingSessionIDLen must never
// enter the set (real ids are UUID-sized); an unrepresentable id widens to
// all rather than narrowing the host against a garbage name.
func TestViewingRejectsOversizedSessionID(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	ch, unsub, ok := h.TrySubscribeHost(0, "h1")
	if !ok {
		t.Fatal("TrySubscribeHost refused")
	}
	defer unsub()

	if !h.SetSubscriberViewing(ch, strings.Repeat("x", maxViewingSessionIDLen+1)) {
		t.Fatal("SetSubscriberViewing refused")
	}
	v, _, ok := testViewing(h, "h1")
	if !ok || !v.All {
		t.Fatalf("viewing with an oversized id = %+v ok=%v, want all", v, ok)
	}
	if len(v.Sessions) != 0 {
		t.Fatalf("viewing sessions = %v, want none", v.Sessions)
	}
}

// Past maxViewingSessions distinct ids the set widens to all (the host then
// trims nothing) instead of emitting an unbounded frame.
func TestViewingWidensToAllAtSessionCap(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	for i := 0; i <= maxViewingSessions; i++ {
		ch, unsub, ok := h.TrySubscribeHost(0, "h1")
		if !ok {
			t.Fatalf("TrySubscribeHost refused at %d", i)
		}
		defer unsub()
		if !h.SetSubscriberViewing(ch, fmt.Sprintf("s-%03d", i)) {
			t.Fatalf("SetSubscriberViewing refused at %d", i)
		}
	}
	v, _, ok := testViewing(h, "h1")
	if !ok || !v.All {
		t.Fatalf("viewing past the cap = %+v ok=%v, want all", v, ok)
	}
	if len(v.Sessions) != 0 {
		t.Fatalf("viewing sessions = %v, want none once widened", v.Sessions)
	}
}
