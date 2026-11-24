package hub

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/wire"
)

// TestSubscriberHostFilter: the /ws/fe host filter is the whole point of
// 分流 — a page watching h1 must not receive one byte of h2's stream (it
// used to receive everything and drop it client-side, which still cost the
// hub→browser bandwidth and made h2's seq/resync land on h1's watermark).
// Hub-level frames (no hostId) stay for everyone: the registry and prefs
// are per-hub, not per-host.
func TestSubscriberHostFilter(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	testPair(t, h, "h2", "H2")

	scopedCh, scopedUnsub, ok := h.TrySubscribeHost(0, "h1")
	if !ok {
		t.Fatal("TrySubscribeHost refused")
	}
	defer scopedUnsub()
	allCh, allUnsub := h.Subscribe()
	defer allUnsub()

	if !hubRaw(h, "h1", Event{"seq": uint64(1), "type": "chunk", "text": "a"}) {
		t.Fatal("register h1")
	}
	if !hubRaw(h, "h2", Event{"seq": uint64(1), "type": "chunk", "text": "b"}) {
		t.Fatal("register h2")
	}
	h.Broadcast(hostsChanged())

	scoped := drainEvents(scopedCh, 200*time.Millisecond)
	for _, ev := range scoped {
		if host, _ := ev["hostId"].(string); host == "h2" {
			t.Fatalf("h2 event leaked into the h1-filtered subscriber: %v", eventTypes(scoped))
		}
	}
	if !containsType(eventTypes(scoped), "chunk@h1") {
		t.Errorf("filtered subscriber missed its own host: %v", eventTypes(scoped))
	}
	if !containsType(eventTypes(scoped), "hosts_changed") {
		t.Errorf("filtered subscriber missed hub-level hosts_changed: %v", eventTypes(scoped))
	}

	all := drainEvents(allCh, 200*time.Millisecond)
	types := eventTypes(all)
	if !containsType(types, "chunk@h1") || !containsType(types, "chunk@h2") {
		t.Errorf("unfiltered subscriber must still get every host: %v", types)
	}

	// The per-host audience drives the uplink pause, not the raw count.
	if n := h.SubscriberCountFor("h1"); n != 2 {
		t.Errorf("SubscriberCountFor(h1) = %d, want 2 (filtered + watch-all)", n)
	}
	if n := h.SubscriberCountFor("h2"); n != 1 {
		t.Errorf("SubscriberCountFor(h2) = %d, want 1 (watch-all only)", n)
	}
	if n := h.SubscriberCount(); n != 2 {
		t.Errorf("SubscriberCount = %d, want 2 live clients", n)
	}

	// Retargeting mid-session (the page switched hosts without reconnecting).
	if !h.SetSubscriberHost(scopedCh, "h2") {
		t.Fatal("SetSubscriberHost rejected a live channel")
	}
	if !hubRaw(h, "h1", Event{"seq": uint64(2), "type": "chunk", "text": "c"}) {
		t.Fatal("register h1 c")
	}
	if !hubRaw(h, "h2", Event{"seq": uint64(2), "type": "chunk", "text": "d"}) {
		t.Fatal("register h2 d")
	}
	after := eventTypes(drainEvents(scopedCh, 200*time.Millisecond))
	if !containsType(after, "chunk@h2") || containsType(after, "chunk@h1") {
		t.Errorf("after retarget to h2 = %v, want h2 only", after)
	}
	if n := h.SubscriberCountFor("h1"); n != 1 {
		t.Errorf("SubscriberCountFor(h1) after retarget = %d, want 1", n)
	}
	if n := h.SubscriberCountFor("h2"); n != 2 {
		t.Errorf("SubscriberCountFor(h2) after retarget = %d, want 2", n)
	}

	// "" restores watch-all (old FE behaviour on the same connection).
	if !h.SetSubscriberHost(scopedCh, "") {
		t.Fatal("SetSubscriberHost rejected clearing the filter")
	}
	if !hubRaw(h, "h1", Event{"seq": uint64(3), "type": "chunk", "text": "e"}) {
		t.Fatal("register h1 e")
	}
	if !containsType(eventTypes(drainEvents(scopedCh, 200*time.Millisecond)), "chunk@h1") {
		t.Error("clearing the filter must restore the every-host stream")
	}
	if h.SetSubscriberHost(make(chan Event), "h1") {
		t.Error("SetSubscriberHost accepted a foreign channel")
	}
}

func containsType(types []string, want string) bool {
	for _, t := range types {
		if t == want {
			return true
		}
	}
	return false
}

// TestAudienceNotifyPerHost: the audience frame decides whether a host uploads
// bridge events at all. With per-subscriber filtering it must carry the
// PER-HOST audience, otherwise a page watching h1 keeps h2 uploading a stream
// nobody reads.
func TestAudienceNotifyPerHost(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	testPair(t, h, "h2", "H2")

	fh1 := dialFakeHost(t, h, "h1", 1)
	fh2 := dialFakeHost(t, h, "h2", 1)

	ch, unsub, ok := h.TrySubscribeHost(0, "h1")
	if !ok {
		t.Fatal("TrySubscribeHost refused")
	}
	defer unsub()

	if a := fh1.recvType(wire.TypeAudience, 2*time.Second).AudienceState(); a.Watchers != 1 {
		t.Fatalf("h1 audience = %+v, want 1 watcher", a)
	}
	// h2 has no viewer: its snapshot never changed, so nothing is sent.
	fh2.noFrame(200 * time.Millisecond)

	if !h.SetSubscriberHost(ch, "h2") {
		t.Fatal("SetSubscriberHost rejected a live channel")
	}
	if a := fh1.recvType(wire.TypeAudience, 2*time.Second).AudienceState(); a.Watchers != 0 {
		t.Fatalf("h1 audience after retarget = %+v, want 0 watchers", a)
	}
	if a := fh2.recvType(wire.TypeAudience, 2*time.Second).AudienceState(); a.Watchers != 1 {
		t.Fatalf("h2 audience after retarget = %+v, want 1 watcher", a)
	}

	unsub()
	if a := fh2.recvType(wire.TypeAudience, 2*time.Second).AudienceState(); a.Watchers != 0 {
		t.Fatalf("h2 audience after unsubscribe = %+v, want 0 watchers", a)
	}
}

// TestResyncCarriesHostId: seq counters are per-host, so an untagged resync
// tripped by h2's drop storm was applied to whichever host the FE happened
// to watch — jumping h1's watermark to h2's sequence silently dropped every
// h1 event below it (the page looked live but frozen).
func TestResyncCarriesHostId(t *testing.T) {
	ev := Event{"type": "chunk", "seq": uint64(9000), "hostId": "h2"}
	rf := resyncFrame(ev)
	if rf["type"] != "resync" {
		t.Errorf("type = %v, want resync", rf["type"])
	}
	if got, _ := rf["hostId"].(string); got != "h2" {
		t.Errorf("resync hostId = %q, want h2 — the FE cannot attribute it otherwise", got)
	}
	if got, _ := rf["fromSeq"].(uint64); got != 9000 {
		t.Errorf("resync fromSeq = %v, want 9000", rf["fromSeq"])
	}
	// Hub-level events carry no host: their resync stays untagged rather
	// than falsely attributed to some host.
	hostless := resyncFrame(Event{"seq": uint64(1), "type": "hosts_changed"})
	if _, has := hostless["hostId"]; has {
		t.Errorf("hostless resync must not carry a hostId: %v", hostless)
	}
	// The filtered subscriber only ever sees its own host's drops, so the
	// frame it receives can only be about that host.
	s := &feSubscriber{ch: make(chan Event, 1)}
	s.host.Store("h1")
	if s.watches("h2") {
		t.Error("h1-filtered subscriber must not watch h2")
	}
}

// TestUnwatchedHostStatusStillVisible: the host list's live status (online /
// ready / busy / pendingCount) comes from the heartbeat's status snapshot and
// the hub-level hosts_changed frame, never from the data-plane event stream.
// A host nobody watches pauses its event upload, and it must still be
// correct in every browser's list — otherwise 分流 would silently freeze the
// picker on stale states for exactly the hosts the user is about to switch
// to.
func TestUnwatchedHostStatusStillVisible(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	testPair(t, h, "h2", "H2")

	ch, unsub, ok := h.TrySubscribeHost(0, "h1")
	if !ok {
		t.Fatal("TrySubscribeHost refused")
	}
	defer unsub()
	// Drain the frames emitted while pairing/hooking up so the assertions
	// below only see what the status changes produce.
	drainEvents(ch, 100*time.Millisecond)

	busy, pending := true, 3
	if !h.UpdateHostStatus("h2", HostStatusPatch{Busy: &busy, PendingCount: &pending}) {
		t.Fatal("UpdateHostStatus h2")
	}
	ready := true
	if !h.UpdateHostStatus("h2", HostStatusPatch{Ready: &ready}) {
		t.Fatal("status ready h2")
	}

	evs := drainEvents(ch, 200*time.Millisecond)
	nChanged := 0
	for _, ev := range evs {
		if ev["type"] == "hosts_changed" {
			nChanged++
		}
		if host, _ := ev["hostId"].(string); host == "h2" {
			t.Fatalf("h2 data-plane event reached the h1 page: %v", ev)
		}
	}
	if nChanged == 0 {
		t.Fatal("no hosts_changed for the h1-filtered subscriber — the host list " +
			"would go stale for every host the page is not watching")
	}

	var h2 *HostInfo
	hosts := h.ListHosts()
	for i := range hosts {
		if hosts[i].HostID == "h2" {
			h2 = &hosts[i]
		}
	}
	if h2 == nil {
		t.Fatal("h2 missing from the registry")
	}
	if !h2.Busy || h2.PendingCount != 3 || !h2.Ready {
		t.Errorf("unwatched h2 registry = busy:%v pending:%v ready:%v, want true/3/true",
			h2.Busy, h2.PendingCount, h2.Ready)
	}
}

// hubRaw ingests one event the way the host wire does: as raw JSON through
// RegisterRawEvents, which is the only ingest path production uses.
func hubRaw(h *Hub, hostID string, ev Event) bool {
	b, err := json.Marshal(ev)
	if err != nil {
		return false
	}
	return testIngest(h, hostID, []json.RawMessage{b})
}
