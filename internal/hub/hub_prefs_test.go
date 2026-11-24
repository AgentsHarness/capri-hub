package hub

import (
	"testing"
	"time"
)

// TestPairPortAndPersist: optional Pair port is stored and survives restart.
func TestPairPortAndPersist(t *testing.T) {
	dir := t.TempDir()
	h1 := NewWithDir(dir)
	code, _ := h1.PairingCode()
	if _, err := h1.Pair(code, "h1", "H1", 8765); err != nil {
		t.Fatalf("Pair: %v", err)
	}
	if hosts := h1.ListHosts(); len(hosts) != 1 || hosts[0].Port != 8765 {
		t.Fatalf("after Pair port = %+v, want 8765", hosts)
	}
	h2 := NewWithDir(dir)
	if hosts := h2.ListHosts(); len(hosts) != 1 || hosts[0].Port != 8765 {
		t.Fatalf("after restart port = %+v, want 8765", hosts)
	}
}

// TestHostVersionPersists: the last version reported by a host survives a hub
// restart, so an offline host still shows what it was running.
func TestHostVersionPersists(t *testing.T) {
	dir := t.TempDir()
	h1 := NewWithDir(dir)
	testPair(t, h1, "h1", "H1")
	version := "v0.5.0"
	if !h1.UpdateHostStatus("h1", HostStatusPatch{Version: &version}) {
		t.Fatal("UpdateHostStatus failed")
	}
	h2 := NewWithDir(dir)
	if hosts := h2.ListHosts(); len(hosts) != 1 || hosts[0].Version != "v0.5.0" {
		t.Fatalf("after restart version = %+v, want v0.5.0", hosts)
	}
}

// TestSubscribeNotBlockedBySlowHost: subscriber-count notifications are
// written per host in the background, so a slow/half-open host (write
// timeouts of tens of seconds) must not stall subscribe/unsubscribe.
func TestSubscribeNotBlockedBySlowHost(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	fh := dialFakeHost(t, h, "h1", 1)
	release := make(chan struct{})
	fh.ft.setBlock(release) // simulate a host whose write never completes
	defer close(release)

	done := make(chan struct{})
	go func() {
		ch, unsub := h.Subscribe()
		defer unsub()
		_ = ch
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Subscribe blocked on a slow host write")
	}
}

// TestTrySubscribeCap: TrySubscribe must reject registration beyond the
// cap (resource guard for the open /ws/fe endpoint), free a slot on
// unsubscribe, and treat max=0 as unlimited (Subscribe keeps working).
func TestTrySubscribeCap(t *testing.T) {
	h := NewWithDir(t.TempDir())

	ch1, unsub1, ok := h.TrySubscribe(2)
	if !ok || ch1 == nil {
		t.Fatalf("first subscribe: ok=%v ch=%v", ok, ch1)
	}
	defer unsub1()
	ch2, unsub2, ok := h.TrySubscribe(2)
	if !ok || ch2 == nil {
		t.Fatalf("second subscribe: ok=%v ch=%v", ok, ch2)
	}
	defer unsub2()
	if h.SubscriberCount() != 2 {
		t.Errorf("count = %d, want 2", h.SubscriberCount())
	}

	if ch, unsub, ok := h.TrySubscribe(2); ok {
		unsub()
		t.Fatalf("third subscribe beyond cap must fail (ch=%v)", ch)
	}
	if h.SubscriberCount() != 2 {
		t.Errorf("count after rejected subscribe = %d, want 2", h.SubscriberCount())
	}

	// Unsubscribing frees a slot.
	unsub1()
	if _, _, ok := h.TrySubscribe(2); !ok {
		t.Error("subscribe after unsub must succeed")
	}
	if h.SubscriberCount() != 2 {
		t.Errorf("count after refill = %d, want 2", h.SubscriberCount())
	}

	// max=0 means unlimited.
	if _, unsub, ok := h.TrySubscribe(0); !ok {
		t.Error("TrySubscribe(0) must always succeed")
	} else {
		unsub()
	}
}

// ── browser prefs (pins / todos) ──────────────────────────────────────

func TestPrefsRoundtripAndPersist(t *testing.T) {
	dir := t.TempDir()
	h := NewWithDir(dir)
	doc := BrowserPrefs{Entries: PrefsEntries{
		"ws:/home/u/a":          {V: "1", At: 1, Site: "A"},
		"ws:/home/u/b":          {V: "1", At: 1, Site: "A"},
		"se:s1":                 {V: "1", At: 1, Site: "A"},
		"todo:s1":               {V: "todo", At: 1, Site: "A"},
		"todo:s2":               {V: "completed", At: 1, Site: "A"},
		"fe:collapseToolGroups": {V: "false", At: 1, Site: "A"},
	}}
	if _, err := h.SetPrefs(doc); err != nil {
		t.Fatalf("SetPrefs: %v", err)
	}
	got, _ := h.Prefs()
	if len(got.PinnedWorkspaces) != 2 || got.PinnedSessions[0] != "s1" || got.Todos["s2"] != "completed" {
		t.Errorf("Prefs = %+v, want the stored doc", got)
	}
	if got.FePrefs["collapseToolGroups"] != false {
		t.Errorf("Prefs.FePrefs = %+v, want collapseToolGroups=false", got.FePrefs)
	}
	// Returned docs must be deep copies: mutating one cannot touch the store.
	got.PinnedWorkspaces[0] = "MUTATED"
	got.Todos["s1"] = "completed"
	got.FePrefs["collapseToolGroups"] = true
	again, _ := h.Prefs()
	if again.PinnedWorkspaces[0] != "/home/u/a" || again.Todos["s1"] != "todo" ||
		again.FePrefs["collapseToolGroups"] != false {
		t.Errorf("Prefs is not a deep copy: %+v", again)
	}
	// A fresh Hub on the same dir reloads the doc from prefs.json.
	h2 := NewWithDir(dir)
	reloaded, _ := h2.Prefs()
	if reloaded.PinnedWorkspaces[0] != "/home/u/a" || reloaded.Todos["s2"] != "completed" ||
		reloaded.FePrefs["collapseToolGroups"] != false {
		t.Errorf("reloaded Prefs = %+v, want the persisted doc", reloaded)
	}
	// A tombstone removes the item for every reader.
	if _, err := h.SetPrefs(docWith(PrefsEntries{"todo:s2": seDelete("s2", 2, "A")})); err != nil {
		t.Fatalf("SetPrefs tombstone: %v", err)
	}
	got, _ = h.Prefs()
	if _, ok := got.Todos["s2"]; ok {
		t.Errorf("Prefs after tombstone = %+v, want s2's todo gone", got.Todos)
	}
	if got.PinnedSessions[0] != "s1" {
		t.Errorf("unrelated entry moved: %+v", got.PinnedSessions)
	}
}

func TestPrefsEmptyDoc(t *testing.T) {
	h := NewWithDir(t.TempDir())
	p, version := h.Prefs()
	if p.PinnedWorkspaces == nil || p.PinnedSessions == nil || p.Todos == nil {
		t.Errorf("empty doc must have non-nil containers: %+v", p)
	}
	if version != 0 {
		t.Errorf("fresh hub version = %d, want 0", version)
	}
}

// TestPrefsVersion: every accepted write bumps the version and the version
// survives a hub restart via prefs.json.
func TestPrefsVersion(t *testing.T) {
	dir := t.TempDir()
	h := NewWithDir(dir)

	v1, err := h.SetPrefs(docWith(PrefsEntries{"se:s1": sePin("s1", 1, "A")}))
	if err != nil || v1 != 1 {
		t.Fatalf("write: v=%d err=%v, want v=1 nil", v1, err)
	}
	v2, err := h.SetPrefs(docWith(PrefsEntries{"se:s2": sePin("s2", 2, "A")}))
	if err != nil || v2 != 2 {
		t.Fatalf("second write: v=%d err=%v, want v=2 nil", v2, err)
	}
	doc, v := h.Prefs()
	if v != v2 || len(doc.PinnedSessions) != 2 {
		t.Errorf("doc=%+v v=%d, want both pins at v=%d", doc, v, v2)
	}

	// A subscriber sees prefs_changed carrying the new version.
	ch, unsub, ok := h.TrySubscribe(0)
	if !ok {
		t.Fatalf("TrySubscribe failed")
	}
	defer unsub()
	if _, err := h.SetPrefs(docWith(PrefsEntries{"se:s3": sePin("s3", 3, "A")})); err != nil {
		t.Fatalf("broadcast write: %v", err)
	}
	select {
	case ev := <-ch:
		params, _ := ev["params"].(map[string]any)
		if ver, _ := params["version"].(uint64); ver != v+1 {
			t.Errorf("broadcast version = %v, want %d", params["version"], v+1)
		}
	case <-time.After(time.Second):
		t.Fatalf("no prefs_changed broadcast received")
	}

	// Version persists with the doc: a fresh hub reloads both.
	h2 := NewWithDir(dir)
	if _, vr := h2.Prefs(); vr != v+1 {
		t.Errorf("reloaded version = %d, want %d", vr, v+1)
	}
}

// SetPrefs must broadcast prefs_changed to browser subscribers so other
// browsers apply the edit live (one-end sync).
func TestPrefsBroadcast(t *testing.T) {
	h := NewWithDir("") // no disk, still broadcasts
	ch, unsub := h.Subscribe()
	defer unsub()
	doc := BrowserPrefs{Entries: PrefsEntries{
		"se:s1":   {V: "1", At: 1, Site: "A"},
		"todo:s1": {V: "todo", At: 1, Site: "A"},
	}}
	if _, err := h.SetPrefs(doc); err != nil {
		t.Fatalf("SetPrefs: %v", err)
	}
	select {
	case ev := <-ch:
		if ev["type"] != "prefs_changed" {
			t.Errorf("broadcast type = %v, want prefs_changed", ev["type"])
		}
		params, _ := ev["params"].(map[string]any)
		prefs, ok := params["prefs"].(BrowserPrefs)
		if !ok {
			t.Fatalf("broadcast params.prefs = %T, want BrowserPrefs", params["prefs"])
		}
		if len(prefs.PinnedSessions) != 1 || prefs.PinnedSessions[0] != "s1" || prefs.Todos["s1"] != "todo" {
			t.Errorf("broadcast prefs = %+v, want the stored doc", prefs)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no prefs_changed broadcast received")
	}
}
