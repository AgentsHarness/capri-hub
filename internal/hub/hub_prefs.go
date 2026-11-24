package hub

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

// ── browser preferences (pins / todos) ────────────────────────────────

// loadPrefs reads prefs.json into h.prefs (+ version). A missing file
// starts empty; an unreadable one is ignored (rebuilt on the next write).
// The version rides in the same JSON object as a sibling key, so an older
// hub reading a newer file still finds every doc field.
func (h *Hub) loadPrefs() {
	b, err := os.ReadFile(h.prefsFile)
	if err != nil {
		return
	}
	var raw prefsFileDoc
	if json.Unmarshal(b, &raw) != nil {
		log.Printf("[capri-hub] prefs: ignoring unreadable %s", h.prefsFile)
		return
	}
	h.prefs = sanitizePrefs(raw.BrowserPrefs)
	h.prefsVersion = raw.Version
	// A prefs.json written before entries existed carries only the
	// snapshot: materialize it so the merged state has a starting point.
	// Stamped with the load time — any later real write (including a
	// deletion) is newer and wins, and a stale offline client stamped at 0
	// cannot overwrite it.
	if len(h.prefs.Entries) == 0 {
		h.prefs.Entries = entriesFromSnapshot(h.prefs, time.Now().UnixMilli())
	}
	prunePrefsTombstones(h.prefs.Entries, time.Now())
}

// prefsFileDoc is the prefs.json envelope: the doc fields at the top level
// plus the CAS version (unknown-key-tolerant both ways across upgrades).
type prefsFileDoc struct {
	BrowserPrefs
	Version uint64 `json:"version"`
}

// sanitizePrefs normalizes a decoded doc (nil slices/maps → empty
// containers, entries without a writer identity dropped) so callers never
// see nil containers or unorderable records.
func sanitizePrefs(p BrowserPrefs) BrowserPrefs {
	if p.PinnedWorkspaces == nil {
		p.PinnedWorkspaces = []string{}
	}
	if p.PinnedSessions == nil {
		p.PinnedSessions = []string{}
	}
	if p.Todos == nil {
		p.Todos = map[string]string{}
	}
	if p.Entries == nil {
		p.Entries = PrefsEntries{}
	} else {
		for k, e := range p.Entries {
			if k == "" || e.Site == "" {
				delete(p.Entries, k)
			}
		}
	}
	return p
}

// clonePrefs deep-copies a doc so stored state is never aliased by
// callers mutating what they received.
func clonePrefs(p BrowserPrefs) BrowserPrefs {
	todos := make(map[string]string, len(p.Todos))
	for k, v := range p.Todos {
		todos[k] = v
	}
	fePrefs := make(FePrefs, len(p.FePrefs))
	for k, v := range p.FePrefs {
		fePrefs[k] = v
	}
	entries := make(PrefsEntries, len(p.Entries))
	for k, v := range p.Entries {
		entries[k] = v
	}
	return sanitizePrefs(BrowserPrefs{
		Entries:          entries,
		PinnedWorkspaces: append([]string(nil), p.PinnedWorkspaces...),
		PinnedSessions:   append([]string(nil), p.PinnedSessions...),
		Todos:            todos,
		FePrefs:          fePrefs,
	})
}

// Prefs returns a deep copy of the browser prefs doc plus its current
// version (a consistent pair under one lock; empty doc when the hub has
// never received one).
func (h *Hub) Prefs() (BrowserPrefs, uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return clonePrefs(h.prefs), h.prefsVersion
}

// SetPrefs folds a browser prefs write into the stored doc and persists it
// to prefs.json.
//
// `entries` is the source of truth: the write is MERGED per key (newest
// (At, Site) record wins), so a stale writer contributes nothing it hasn't
// actually touched and no version can be "too old". The stored snapshot is
// always recomputed from the merged entries, never taken from the request.
//
// An accepted write bumps the version and is broadcast to browser
// subscribers as `prefs_changed` (doc + version) so other browsers merge it
// live. A write that changes nothing (a client re-pushing state the hub
// already has) is dropped without bumping the version or broadcasting —
// otherwise every reconnect would churn the doc.
func (h *Hub) SetPrefs(prefs BrowserPrefs) (uint64, error) {
	cp := clonePrefs(prefs) // clonePrefs already sanitizes

	h.mu.Lock()
	doc, newVersion, changed := mergePrefsDoc(h.prefs, h.prefsVersion, cp)
	if !changed {
		// Nothing moved: keep the version, don't write, don't broadcast.
		h.mu.Unlock()
		return newVersion, nil
	}
	persist := h.prefsFile != ""
	var payload []byte
	if persist {
		b, err := json.Marshal(prefsFileDoc{BrowserPrefs: doc, Version: newVersion})
		if err != nil {
			h.mu.Unlock()
			return 0, fmt.Errorf("marshal prefs: %w", err)
		}
		payload = b
	}
	h.prefsVersion = newVersion
	h.prefs = doc
	h.broadcastToUser("root", prefsChanged(clonePrefs(doc), newVersion))
	h.mu.Unlock()

	if persist {
		if err := writeFileAtomic(h.prefsFile, payload); err != nil {
			log.Printf("[capri-hub] prefs persist: %v", err)
		}
	}
	return newVersion, nil
}

// mergePrefsDoc folds incoming into current and returns the merged document,
// its new version and whether anything changed. Callers hold h.mu when the
// current document is shared state.
func mergePrefsDoc(current BrowserPrefs, currentVersion uint64, incoming BrowserPrefs) (BrowserPrefs, uint64, bool) {
	cp := clonePrefs(incoming)
	next := PrefsEntries{}
	mergePrefsEntries(next, current.Entries)
	mergePrefsEntries(next, cp.Entries)
	prunePrefsTombstones(next, time.Now())
	if samePrefsEntries(current.Entries, next) {
		return clonePrefs(current), currentVersion, false
	}
	doc := cp
	doc.Entries = next
	applyPrefsProjection(&doc)
	return doc, currentVersion + 1, true
}

// prefsChanged builds the prefs broadcast event (hub-level, no hostId —
// browsers apply it regardless of the selected host). Carries the doc's
// new version so clean clients track their CAS base without re-pulling.
func prefsChanged(prefs BrowserPrefs, version uint64) Event {
	return Event{"type": "prefs_changed", "params": map[string]any{"prefs": prefs, "version": version}}
}
