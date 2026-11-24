package hub

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// ── persistence ───────────────────────────────────────────────────────

type persistFile struct {
	Tokens map[string]string      `json:"tokens"`
	Hosts  map[string]persistHost `json:"hosts"`
}

type persistHost struct {
	HostID   string `json:"hostId"`
	HostName string `json:"hostName"`
	OwnerID  string `json:"ownerId,omitempty"`
	Ready    bool   `json:"ready"`
	Port     int    `json:"port,omitempty"`
	Version  string `json:"version,omitempty"`
}

// hostOwnerOrDefault normalizes an old hub.json entry (no ownerId) to the
// deployment admin. Every host created before multi-user belongs to root.
func hostOwnerOrDefault(ownerID string) string {
	if strings.TrimSpace(ownerID) == "" {
		return "root"
	}
	return ownerID
}

func (h *Hub) load() {
	b, err := os.ReadFile(h.dataFile)
	if err != nil {
		return
	}
	var pf persistFile
	if json.Unmarshal(b, &pf) != nil {
		return
	}
	for hid, ph := range pf.Hosts {
		id := ph.HostID
		if id == "" {
			id = hid
		}
		ownerID := hostOwnerOrDefault(ph.OwnerID)
		h.hosts[id] = &hostState{
			info: HostInfo{
				HostID: id, HostName: ph.HostName, OwnerID: ownerID,
				Ready: ph.Ready, Port: ph.Port, Version: ph.Version,
			},
			ownerID: ownerID,
		}
	}
	// Restore tokens and hostState.token so re-pair after restart can
	// revoke the previous credential (delete by hs.token + by hostId).
	for tok, hid := range pf.Tokens {
		if tok == "" || hid == "" {
			continue
		}
		h.tokens[tok] = hid
		if hs := h.hosts[hid]; hs != nil {
			// Last token wins as the "current" field; revokeTokensForHost
			// still clears every map entry for the hostId.
			hs.token = tok
		} else {
			// Orphan token without a hosts entry — synthesize a minimal host
			// so the token remains usable and re-pair can still revoke it.
			h.hosts[hid] = &hostState{
				info:    HostInfo{HostID: hid, OwnerID: "root"},
				ownerID: "root",
				token:   tok,
			}
		}
	}
}

// snapshotLocked returns a deep copy of the persistence snapshot; the
// caller must hold h.mu. The copy is safe to marshal after releasing the
// lock — never alias h.tokens / live host maps.
func (h *Hub) snapshotLocked() persistFile {
	pf := persistFile{
		Tokens: make(map[string]string, len(h.tokens)),
		Hosts:  make(map[string]persistHost, len(h.hosts)),
	}
	for tok, hid := range h.tokens {
		pf.Tokens[tok] = hid
	}
	for hid, hs := range h.hosts {
		pf.Hosts[hid] = persistHost{
			HostID:   hid,
			HostName: hs.info.HostName,
			OwnerID:  hostOwnerOrDefault(hs.ownerID),
			Ready:    hs.info.Ready,
			Port:     hs.info.Port,
			Version:  hs.info.Version,
		}
	}
	return pf
}

// persistNow snapshots the registry and writes hub.json, serialized against
// every other hub.json writer.
//
// The lock is load-bearing: snapshotting under h.mu and writing outside it
// means two concurrent Pair/Rename/Unpair/port updates can otherwise rename
// their temp files out of order, and the OLDER snapshot wins — losing a
// pairing or a port update that is already applied in memory. persistMu
// makes the snapshot and its write one ordered unit, so the file always
// ends on the newest state. Same shape and lock order as guestPersistMu →
// h.mu in guests.go (never the reverse). The disk write stays outside h.mu
// so a slow disk cannot stall the hub.
func (h *Hub) persistNow() {
	if h.dataFile == "" {
		return
	}
	h.persistMu.Lock()
	defer h.persistMu.Unlock()
	h.mu.Lock()
	snap := h.snapshotLocked()
	h.mu.Unlock()
	h.writePersist(snap)
}

// writePersist writes a snapshot to disk (unique temp + rename, mode 0600).
// It never takes h.mu: slow or flaky disk must not stall the whole hub.
// Callers go through persistNow, which serializes snapshot + write with
// persistMu; the unique temp file remains as a safety net against a stray
// direct caller clobbering another's .tmp.
func (h *Hub) writePersist(pf persistFile) {
	if h.dataFile == "" {
		return
	}
	b, err := json.Marshal(pf)
	if err != nil {
		return
	}
	if err := writeFileAtomic(h.dataFile, b); err != nil {
		log.Printf("[capri-hub] persist: %v", err)
	}
}

// writeFileAtomic writes b to path via unique temp + rename (mode 0600).
// Shared by hub.json (pairing state — secrets live here, never world
// readable) and prefs.json. Same concurrency contract as writePersist:
// never called while holding h.mu, and concurrent callers get their own
// temp file so renames cannot race.
func writeFileAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	f, err := os.CreateTemp(dir, "hub-*.tmp")
	if err != nil {
		return fmt.Errorf("temp: %w", err)
	}
	tmpName := f.Name()
	// Tokens live in hub.json — never world/group readable.
	_ = f.Chmod(0o600)
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename: %w", err)
	}
	_ = os.Chmod(path, 0o600)
	return nil
}
