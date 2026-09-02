package hub

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Preference entries: merge semantics, the legacy bridge, and the projection.
//
// Timestamps are anchored at "now" (t0) plus small offsets: tombstones are
// pruned by wall clock (prefsTombstoneHorizon), so epoch-scale numbers would
// be collected as expired the moment they arrived.

var t0 = time.Now().UnixMilli()

func sePin(id string, at int64, site string) PrefsEntry {
	return PrefsEntry{V: "1", At: at, Site: site}
}

func seDelete(id string, at int64, site string) PrefsEntry {
	return PrefsEntry{At: at, Site: site, Del: true}
}

func docWith(entries PrefsEntries) BrowserPrefs {
	return BrowserPrefs{Entries: entries}
}

// A stale client re-pushing its old entries must NOT restore what another
// client deleted. This is the whole point of the entries model: under the old
// snapshot+replace protocol the same sequence resurrected the pin and then
// echoed that resurrection to every other browser.
func TestPrefsEntriesMergeNeverResurrectsADeletedPin(t *testing.T) {
	h := NewWithDir(t.TempDir())

	// Client A pins s1, then cancels the pin (a tombstone, not an absence).
	if _, err := h.SetPrefs(docWith(PrefsEntries{"se:s1": sePin("s1", t0, "A")}), 0, false); err != nil {
		t.Fatalf("pin: %v", err)
	}
	if _, err := h.SetPrefs(docWith(PrefsEntries{"se:s1": seDelete("s1", t0+100, "A")}), 0, false); err != nil {
		t.Fatalf("unpin: %v", err)
	}
	got, _ := h.Prefs()
	if len(got.PinnedSessions) != 0 {
		t.Fatalf("after unpin, pinnedSessions = %v, want empty", got.PinnedSessions)
	}

	// A third client that never saw the delete pushes its stale copy —
	// including the older "pinned s1" record.
	if _, err := h.SetPrefs(docWith(PrefsEntries{"se:s1": sePin("s1", t0, "C")}), 0, false); err != nil {
		t.Fatalf("stale write must still be accepted: %v", err)
	}
	got, _ = h.Prefs()
	if len(got.PinnedSessions) != 0 {
		t.Errorf("stale client resurrected the pin: %v", got.PinnedSessions)
	}
	// The winning tombstone stays on record: it must keep winning until every
	// offline client has caught up.
	if e, ok := got.Entries["se:s1"]; !ok || !e.Del {
		t.Errorf("entries[se:s1] = %+v, want the tombstone retained", e)
	}

	// And a genuinely newer write still lands.
	if _, err := h.SetPrefs(docWith(PrefsEntries{"se:s1": sePin("s1", t0+200, "C")}), 0, false); err != nil {
		t.Fatalf("newer write: %v", err)
	}
	got, _ = h.Prefs()
	if len(got.PinnedSessions) != 1 || got.PinnedSessions[0] != "s1" {
		t.Errorf("after a newer pin, pinnedSessions = %v, want [s1]", got.PinnedSessions)
	}
}

// Convergence must not depend on the order writes arrive in (a late
// broadcast, a retried PUT, a reconnect flush): merging the same records in
// either order yields the same doc.
func TestPrefsEntriesMergeIsOrderIndependent(t *testing.T) {
	a := PrefsEntries{"se:s1": sePin("s1", t0, "A"), "se:s2": seDelete("s2", t0+150, "A")}
	b := PrefsEntries{"se:s2": sePin("s2", t0+120, "B"), "se:s3": sePin("s3", t0+90, "B")}

	forward := NewWithDir(t.TempDir())
	reverse := NewWithDir(t.TempDir())
	for _, step := range []struct {
		h    *Hub
		docs []PrefsEntries
	}{{forward, []PrefsEntries{a, b}}, {reverse, []PrefsEntries{b, a}}} {
		for _, d := range step.docs {
			if _, err := step.h.SetPrefs(docWith(d), 0, false); err != nil {
				t.Fatal(err)
			}
		}
	}

	fw, _ := forward.Prefs()
	rv, _ := reverse.Prefs()
	if !samePrefsEntries(fw.Entries, rv.Entries) {
		t.Errorf("merge order changed the state: %+v vs %+v", fw.Entries, rv.Entries)
	}
	// s2's delete (+150) beats its add (+120); s1 and s3 stay pinned.
	if len(fw.PinnedSessions) != 2 || fw.PinnedSessions[0] != "s1" || fw.PinnedSessions[1] != "s3" {
		t.Errorf("projection = %v, want [s1 s3]", fw.PinnedSessions)
	}
}

// Two writers stamping the same millisecond are ordered by site, and the
// stored doc is identical whichever arrival order produced it — the tiebreak
// is part of the record, not a race artifact.
func TestPrefsEntriesSameClockTieBreak(t *testing.T) {
	base := PrefsEntries{"se:s1": sePin("s1", t0+500, "AAA")}
	challenger := PrefsEntries{"se:s1": seDelete("s1", t0+500, "BBB")}

	run := func(order ...PrefsEntries) BrowserPrefs {
		h := NewWithDir(t.TempDir())
		for _, d := range order {
			if _, err := h.SetPrefs(docWith(d), 0, false); err != nil {
				t.Fatal(err)
			}
		}
		got, _ := h.Prefs()
		return got
	}

	got := run(base, challenger)
	if e := got.Entries["se:s1"]; !e.Del || e.Site != "BBB" {
		t.Errorf("entries[se:s1] = %+v, want the later site to win the tie", e)
	}
	if !samePrefsEntries(got.Entries, run(challenger, base).Entries) {
		t.Errorf("arrival order changed the state: %+v", got.Entries)
	}
}

// A client's snapshot fields are never trusted: the projection is recomputed
// from the merged entries, so a client whose view disagrees with its own
// entries cannot put the doc in a split state.
func TestPrefsProjectionRecomputedFromEntries(t *testing.T) {
	h := NewWithDir(t.TempDir())
	lying := BrowserPrefs{
		Entries:        PrefsEntries{"se:real": sePin("real", t0, "A")},
		PinnedSessions: []string{"ghost"},
	}
	if _, err := h.SetPrefs(lying, 0, false); err != nil {
		t.Fatal(err)
	}
	got, _ := h.Prefs()
	if len(got.PinnedSessions) != 1 || got.PinnedSessions[0] != "real" {
		t.Errorf("pinnedSessions = %v, want the projection of entries ([real])", got.PinnedSessions)
	}
	if _, ok := got.Entries["se:ghost"]; ok {
		t.Errorf("ghost leaked into the doc: %+v", got.Entries)
	}
}

// Legacy FE writes (no entries) keep their last-write-wins contract: the
// snapshot IS the state, so what vanished from it is tombstoned — recorded as
// a deletion rather than silently dropped, which is what stops a later
// entries-aware merge from resurrecting it.
func TestPrefsLegacyWriteTombstonesWhatVanished(t *testing.T) {
	h := NewWithDir(t.TempDir())
	if _, err := h.SetPrefs(BrowserPrefs{
		PinnedSessions: []string{"s1", "s2"},
		Todos:          map[string]string{"s1": "todo"},
		FePrefs:        FePrefs{"collapseToolGroups": true},
	}, 0, false); err != nil {
		t.Fatal(err)
	}
	// An old FE drops s2 and the s1 todo, and omits liteReplay (an FE that
	// never chose it does not write the key — absence must not read as delete).
	if _, err := h.SetPrefs(BrowserPrefs{
		PinnedSessions: []string{"s1"},
		FePrefs:        FePrefs{"collapseToolGroups": true},
	}, 0, false); err != nil {
		t.Fatal(err)
	}
	got, _ := h.Prefs()
	if len(got.PinnedSessions) != 1 || got.PinnedSessions[0] != "s1" {
		t.Fatalf("pinnedSessions = %v, want [s1]", got.PinnedSessions)
	}
	if e, ok := got.Entries["se:s2"]; !ok || !e.Del {
		t.Errorf("entries[se:s2] = %+v, want a tombstone for the dropped pin", e)
	}
	if _, ok := got.Todos["s1"]; ok {
		t.Errorf("todos = %v, want the dropped todo removed", got.Todos)
	}
	if e, ok := got.Entries["todo:s1"]; !ok || !e.Del {
		t.Errorf("entries[todo:s1] = %+v, want a tombstone", e)
	}
	// A deletion the legacy snapshot does not mention stays on the record
	// (dropping it is what lets some other client's stale copy resurrect the
	// item later). A legacy write that *does* name a key still re-pins it —
	// that is the old client's last-write-wins contract, unchanged.
	s2Tombstone := got.Entries["se:s2"]
	if _, err := h.SetPrefs(BrowserPrefs{PinnedSessions: []string{"s1"}}, 0, false); err != nil {
		t.Fatal(err)
	}
	got, _ = h.Prefs()
	if got.Entries["se:s2"] != s2Tombstone {
		t.Errorf("entries[se:s2] = %+v, want the earlier tombstone preserved verbatim (%+v)",
			got.Entries["se:s2"], s2Tombstone)
	}
	if _, err := h.SetPrefs(docWith(PrefsEntries{"se:s2": sePin("s2", t0-5000, "stale")}), 0, false); err != nil {
		t.Fatal(err)
	}
	got, _ = h.Prefs()
	for _, id := range got.PinnedSessions {
		if id == "s2" {
			t.Errorf("a stale client resurrected s2 after the legacy write: %v", got.PinnedSessions)
		}
	}

	// An fePrefs key another client chose survives a legacy write that does
	// not mention it — and keeps its own stamp rather than being re-dated.
	feEntry := got.Entries["fe:collapseToolGroups"]
	if _, err := h.SetPrefs(docWith(PrefsEntries{"fe:liteReplay": {V: "true", At: t0 + 86400000, Site: "A"}}), 0, false); err != nil {
		t.Fatal(err)
	}
	if _, err := h.SetPrefs(BrowserPrefs{PinnedSessions: []string{"s1"}}, 0, false); err != nil {
		t.Fatal(err)
	}
	got, _ = h.Prefs()
	if got.FePrefs["liteReplay"] != true {
		t.Errorf("fePrefs = %v, want an unmentioned fePrefs key left alone", got.FePrefs)
	}
	if got.Entries["fe:collapseToolGroups"] != feEntry {
		t.Errorf("fePrefs entry was re-dated by a legacy write: %+v", got.Entries["fe:collapseToolGroups"])
	}
}

// A conditional write from a stale legacy client is still rejected (its whole
// document would otherwise clobber a newer one); an entries write is never
// rejected, because merging cannot clobber anything.
func TestPrefsConditionalWriteOnlyGuardsLegacy(t *testing.T) {
	h := NewWithDir(t.TempDir())
	if _, err := h.SetPrefs(docWith(PrefsEntries{"se:s1": sePin("s1", t0, "A")}), 7, false); err != nil {
		t.Fatal(err)
	}
	// Legacy snapshot write with a stale base → conflict.
	if _, err := h.SetPrefs(BrowserPrefs{PinnedSessions: []string{"legacy"}}, 3, true); !errors.Is(err, ErrPrefsConflict) {
		t.Fatalf("stale legacy conditional write = %v, want ErrPrefsConflict", err)
	}
	got, _ := h.Prefs()
	if len(got.PinnedSessions) != 1 || got.PinnedSessions[0] != "s1" {
		t.Errorf("rejected write mutated the doc: %v", got.PinnedSessions)
	}
	// Entries write with the same stale base → merged in, no conflict.
	if _, err := h.SetPrefs(docWith(PrefsEntries{"se:s9": sePin("s9", t0+10, "B")}), 3, true); err != nil {
		t.Fatalf("entries write must ignore a stale base: %v", err)
	}
	got, _ = h.Prefs()
	if len(got.PinnedSessions) != 2 {
		t.Errorf("pinnedSessions = %v, want s1 and s9", got.PinnedSessions)
	}
}

// Re-pushing state the hub already holds must not bump the version or wake
// every other browser — otherwise each client's boot sync churns the shared
// doc for no reason.
func TestPrefsNoopWriteKeepsVersionAndStaysQuiet(t *testing.T) {
	h := NewWithDir(t.TempDir())
	ch, unsub := h.Subscribe()
	defer unsub()
	entries := PrefsEntries{"se:s1": sePin("s1", t0, "A")}
	v1, err := h.SetPrefs(docWith(entries), 0, false)
	if err != nil {
		t.Fatal(err)
	}
	drainPrefsEvents(ch)
	v2, err := h.SetPrefs(docWith(entries), 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if v2 != v1 {
		t.Errorf("version after a no-op write = %d, want %d", v2, v1)
	}
	select {
	case ev := <-ch:
		t.Errorf("no-op write broadcast %v, want silence", ev["type"])
	case <-time.After(50 * time.Millisecond):
	}
}

// Tombstones only have to outlive the oldest offline client.
func TestPrefsTombstonesPrunedAfterHorizon(t *testing.T) {
	h := NewWithDir(t.TempDir())
	expired := t0 - (prefsTombstoneHorizon + time.Hour).Milliseconds()
	young := t0 - time.Hour.Milliseconds()
	entries := PrefsEntries{
		"se:gone": seDelete("gone", expired, "A"),
		"se:new":  seDelete("new", young, "A"),
		"se:keep": sePin("keep", expired, "A"),
	}
	if _, err := h.SetPrefs(docWith(entries), 0, false); err != nil {
		t.Fatal(err)
	}
	got, _ := h.Prefs()
	if _, ok := got.Entries["se:gone"]; ok {
		t.Errorf("an expired tombstone survived: %+v", got.Entries)
	}
	if e, ok := got.Entries["se:new"]; !ok || !e.Del {
		t.Errorf("entries[se:new] = %+v, want the young tombstone kept", e)
	}
	// A live record is never pruned, however old.
	if e, ok := got.Entries["se:keep"]; !ok || e.Del {
		t.Errorf("entries[se:keep] = %+v, want the old pin kept", e)
	}
}

// Entries must survive the prefs.json round trip — they are the truth, and
// the snapshot alone would lose every deletion.
func TestPrefsEntriesPersistedAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	h := NewWithDir(dir)
	if _, err := h.SetPrefs(docWith(PrefsEntries{
		"se:s1": sePin("s1", t0, "A"),
		"se:s2": seDelete("s2", t0+10, "A"),
	}), 0, false); err != nil {
		t.Fatal(err)
	}
	restarted := NewWithDir(dir)
	got, version := restarted.Prefs()
	if version == 0 {
		t.Errorf("version lost across restart: %d", version)
	}
	if e, ok := got.Entries["se:s2"]; !ok || !e.Del {
		t.Fatalf("tombstone lost across restart: %+v", got.Entries)
	}
	// A stale client still cannot resurrect s2 after the restart.
	if _, err := restarted.SetPrefs(docWith(PrefsEntries{"se:s2": sePin("s2", t0-1000, "B")}), 0, false); err != nil {
		t.Fatal(err)
	}
	got, _ = restarted.Prefs()
	for _, id := range got.PinnedSessions {
		if id == "s2" {
			t.Errorf("s2 resurrected after restart: %v", got.PinnedSessions)
		}
	}
}

// A hub upgrading over a pre-entries prefs.json keeps the old doc as the
// baseline, and a client cache that predates the upgrade cannot push its
// stale copy back over it.
func TestPrefsUpgradedHubMaterializesLegacyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "prefs.json"),
		[]byte(`{"pinnedWorkspaces":["/a"],"pinnedSessions":["s1"],"todos":{"s1":"todo"},"version":41}`), 0o600); err != nil {
		t.Fatalf("write prefs.json: %v", err)
	}
	h := NewWithDir(dir)
	got, version := h.Prefs()
	if len(got.Entries) != 3 {
		t.Fatalf("legacy doc not materialized into entries: %+v", got.Entries)
	}
	if version != 41 {
		t.Errorf("version = %d, want the persisted 41", version)
	}
	// The migrated cache of a browser that has never synced is stamped 0.
	staleClient := PrefsEntries{
		"se:s1":   sePin("s1", 0, "old"),
		"todo:s1": {V: "completed", At: 0, Site: "old"},
	}
	if _, err := h.SetPrefs(docWith(staleClient), 0, false); err != nil {
		t.Fatal(err)
	}
	got, _ = h.Prefs()
	if got.Todos["s1"] != "todo" {
		t.Errorf("todos = %v, want the hub's status (a stale cache must not win)", got.Todos)
	}
	// A key the hub has never heard of still comes through — a genuinely
	// local-only pin is data, not noise.
	if _, err := h.SetPrefs(docWith(PrefsEntries{"se:localonly": sePin("localonly", 0, "old")}), 0, false); err != nil {
		t.Fatal(err)
	}
	got, _ = h.Prefs()
	if len(got.PinnedSessions) != 2 {
		t.Errorf("pinnedSessions = %v, want s1 plus the local-only pin", got.PinnedSessions)
	}
}

func drainPrefsEvents(ch chan Event) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}
