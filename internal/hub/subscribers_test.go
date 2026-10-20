package hub

import (
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
