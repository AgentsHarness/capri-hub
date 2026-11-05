package hub

import (
	"encoding/json"
	"log"
	"os"
)

// 每个普通用户一份独立的 prefs 文档。root（FE_TOKEN 管理员）仍使用
// prefs.json；普通用户落在 prefs-users.json。这样用户之间看不到彼此的
// 置顶会话、待办状态和外观偏好。
const userPrefsFileVersion = 1

type userPrefsState struct {
	Prefs   BrowserPrefs
	Version uint64
}

type userPrefsRecord struct {
	Prefs   BrowserPrefs `json:"prefs"`
	Version uint64       `json:"version"`
}

type userPrefsFileDoc struct {
	Version int                        `json:"version"`
	Users   map[string]userPrefsRecord `json:"users"`
}

func (h *Hub) loadUserPrefs() {
	b, err := os.ReadFile(h.userPrefsFile)
	if err != nil {
		return
	}
	var doc userPrefsFileDoc
	if json.Unmarshal(b, &doc) != nil {
		log.Printf("[capri-hub] prefs-users: ignoring unreadable %s", h.userPrefsFile)
		return
	}
	if h.userPrefs == nil {
		h.userPrefs = make(map[string]userPrefsState)
	}
	for id, rec := range doc.Users {
		prefs := sanitizePrefs(rec.Prefs)
		if len(prefs.Entries) == 0 {
			prefs.Entries = entriesFromSnapshot(prefs, nowStamp().UnixMilli())
		}
		h.userPrefs[id] = userPrefsState{Prefs: prefs, Version: rec.Version}
	}
}

func (h *Hub) userPrefsPayloadLocked() ([]byte, bool) {
	if h.userPrefsFile == "" {
		return nil, false
	}
	doc := userPrefsFileDoc{
		Version: userPrefsFileVersion,
		Users:   make(map[string]userPrefsRecord, len(h.userPrefs)),
	}
	for id, st := range h.userPrefs {
		doc.Users[id] = userPrefsRecord{Prefs: clonePrefs(st.Prefs), Version: st.Version}
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, false
	}
	return b, true
}

func (h *Hub) persistUserPrefsNow() {
	h.userPrefsPersistMu.Lock()
	defer h.userPrefsPersistMu.Unlock()
	h.mu.Lock()
	payload, ok := h.userPrefsPayloadLocked()
	h.mu.Unlock()
	if !ok {
		return
	}
	if err := writeFileAtomic(h.userPrefsFile, payload); err != nil {
		log.Printf("[capri-hub] prefs-users persist: %v", err)
	}
}

// PrefsFor returns the prefs document for one owner. "root" maps to the
// legacy single prefs.json; every other id maps to its own document. A user
// that has never written prefs gets an empty document with version 0.
func (h *Hub) PrefsFor(ownerID string) (BrowserPrefs, uint64) {
	if hostOwnerOrDefault(ownerID) == "root" {
		return h.Prefs()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	st, ok := h.userPrefs[ownerID]
	if !ok {
		return BrowserPrefs{PinnedWorkspaces: []string{}, PinnedSessions: []string{}, Todos: map[string]string{}}, 0
	}
	return clonePrefs(st.Prefs), st.Version
}

// SetPrefsFor folds one user's prefs write into that user's document and
// broadcasts prefs_changed only to that user's live subscribers.
func (h *Hub) SetPrefsFor(ownerID string, prefs BrowserPrefs) (uint64, error) {
	if hostOwnerOrDefault(ownerID) == "root" {
		return h.SetPrefs(prefs)
	}
	h.mu.Lock()
	st := h.userPrefs[ownerID]
	doc, newVersion, changed := mergePrefsDoc(st.Prefs, st.Version, prefs)
	if !changed {
		h.mu.Unlock()
		return newVersion, nil
	}
	h.userPrefs[ownerID] = userPrefsState{Prefs: doc, Version: newVersion}
	h.broadcastToUser(ownerID, prefsChanged(clonePrefs(doc), newVersion))
	h.mu.Unlock()

	h.persistUserPrefsNow()
	return newVersion, nil
}
