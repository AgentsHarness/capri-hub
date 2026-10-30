package hub

import (
	"sort"
	"time"
)

// Preference entries: the per-item last-write-wins set behind the browser
// prefs document.
//
// The document used to be a plain snapshot (pinned sessions / workspaces +
// a todo map) and PUT replaced it wholesale. A snapshot cannot express a
// DELETION, so any client holding a stale snapshot that wrote back restored
// every pin another client had just cancelled — permanently, because the
// hub then echoed that resurrected doc to everyone. The retry/conditional
// machinery around it only narrowed the window; it could not close it.
//
// So the doc carries `entries` instead: one record per preference item
// (a session pin, a todo status, an FE appearance flag), each stamped with
// the writer's clock and identity, and deletion recorded as a tombstone.
// Merging picks the higher (At, Site) per key — commutative, associative,
// idempotent — so convergence no longer depends on write order, retries,
// broadcasts arriving, or the writer knowing which version it last saw. A
// stale snapshot now contributes nothing it hasn't actually touched: its
// entries are older, and the newer tombstone wins.
//
// The pinnedSessions / pinnedWorkspaces / todos / fePrefs fields remain on
// the wire as a PROJECTION of entries, which is also how a prefs.json written
// before entries existed is read back.
//
// Key grammar (shared with the FE's store/prefsEntries.ts):
//
//	ws:<cwd>          pin a workspace        v = "1"
//	se:<sessionId>    pin a session          v = "1"
//	todo:<sessionId>  session todo status    v = "todo" | "completed"
//	fe:<field>        FE appearance flag     v = "true" | "false"
const (
	prefsKeyWorkspacePrefix = "ws:"
	prefsKeySessionPrefix   = "se:"
	prefsKeyTodoPrefix      = "todo:"
	prefsKeyFePrefix        = "fe:"

	// prefsTombstoneHorizon is how long a deletion record is kept. It only
	// has to outlive the oldest offline client (a browser that missed the
	// delete and later pushes its stale copy); past that the tombstone is
	// dead weight and can be dropped.
	prefsTombstoneHorizon = 60 * 24 * time.Hour

	// prefsLegacySite labels entries the hub had to invent while migrating a
	// prefs.json written before entries existed. Such an entry always loses a
	// tie against a real client.
	prefsLegacySite = "hub-legacy"
)

// PrefsEntry is one item's last-write-wins record.
type PrefsEntry struct {
	// V is the item's value ("1" for a pin, the status for a todo, the
	// stringified bool for an FE flag). Empty on a tombstone.
	V string `json:"v"`
	// At is the writer's wall clock in epoch ms when it made the change.
	At int64 `json:"at"`
	// Site identifies the writing browser origin; it breaks ties when two
	// writers stamp the same millisecond.
	Site string `json:"site"`
	// Del marks the item as deleted (tombstone).
	Del bool `json:"d,omitempty"`
}

// PrefsEntries is the doc's source of truth, keyed by the grammar above.
type PrefsEntries map[string]PrefsEntry

// prefsEntryWins reports whether a is the more recent record of the same key.
func prefsEntryWins(a, b PrefsEntry) bool {
	if a.At != b.At {
		return a.At > b.At
	}
	return a.Site > b.Site
}

// mergePrefsEntries folds src into dst (per key, newest record wins) and
// returns dst. Both inputs are left untouched.
func mergePrefsEntries(dst, src PrefsEntries) PrefsEntries {
	if dst == nil {
		dst = PrefsEntries{}
	}
	for k, e := range src {
		if cur, ok := dst[k]; !ok || prefsEntryWins(e, cur) {
			dst[k] = e
		}
	}
	return dst
}

// prunePrefsTombstones drops deletion records older than the horizon.
func prunePrefsTombstones(entries PrefsEntries, now time.Time) {
	cut := now.Add(-prefsTombstoneHorizon).UnixMilli()
	for k, e := range entries {
		if e.Del && e.At < cut {
			delete(entries, k)
		}
	}
}

// projectPrefsEntries fills the document's snapshot fields from entries. The
// snapshot is what FEs render; entries stay the authority, so this is always
// recomputed rather than trusted from outside.
func projectPrefsEntries(entries PrefsEntries) (workspaces, sessions []string, todos map[string]string, fe FePrefs) {
	workspaces = []string{}
	sessions = []string{}
	todos = map[string]string{}
	fe = FePrefs{}
	for k, e := range entries {
		if e.Del {
			continue
		}
		switch {
		case len(k) > len(prefsKeyWorkspacePrefix) && k[:len(prefsKeyWorkspacePrefix)] == prefsKeyWorkspacePrefix:
			workspaces = append(workspaces, k[len(prefsKeyWorkspacePrefix):])
		case len(k) > len(prefsKeySessionPrefix) && k[:len(prefsKeySessionPrefix)] == prefsKeySessionPrefix:
			sessions = append(sessions, k[len(prefsKeySessionPrefix):])
		case len(k) > len(prefsKeyTodoPrefix) && k[:len(prefsKeyTodoPrefix)] == prefsKeyTodoPrefix:
			todos[k[len(prefsKeyTodoPrefix):]] = e.V
		case len(k) > len(prefsKeyFePrefix) && k[:len(prefsKeyFePrefix)] == prefsKeyFePrefix:
			fe[k[len(prefsKeyFePrefix):]] = e.V == "true"
		}
	}
	sort.Strings(workspaces)
	sort.Strings(sessions)
	return workspaces, sessions, todos, fe
}

// applyPrefsProjection sets p's snapshot fields from its entries.
func applyPrefsProjection(p *BrowserPrefs) {
	ws, se, todos, fe := projectPrefsEntries(p.Entries)
	p.PinnedWorkspaces = ws
	p.PinnedSessions = se
	p.Todos = todos
	p.FePrefs = fe
}

// entriesFromSnapshot materializes a snapshot-only prefs.json (written before
// entries existed) into entries stamped at `at`. This is a one-time on-disk
// migration, not a wire path.
func entriesFromSnapshot(p BrowserPrefs, at int64) PrefsEntries {
	out := PrefsEntries{}
	stamp := func(key, val string) { out[key] = PrefsEntry{V: val, At: at, Site: prefsLegacySite} }
	for _, cwd := range p.PinnedWorkspaces {
		stamp(prefsKeyWorkspacePrefix+cwd, "1")
	}
	for _, id := range p.PinnedSessions {
		stamp(prefsKeySessionPrefix+id, "1")
	}
	for id, status := range p.Todos {
		stamp(prefsKeyTodoPrefix+id, status)
	}
	for field, val := range p.FePrefs {
		if b, ok := val.(bool); ok {
			stamp(prefsKeyFePrefix+field, boolEntryValue(b))
		}
	}
	return out
}

func boolEntryValue(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// samePrefsEntries reports two entry sets holding exactly the same records.
func samePrefsEntries(a, b PrefsEntries) bool {
	if len(a) != len(b) {
		return false
	}
	for k, e := range a {
		if b[k] != e {
			return false
		}
	}
	return true
}
