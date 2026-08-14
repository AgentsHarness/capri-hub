// Package hub implements the acp-hub relay core: host pairing (pairing
// code → token), the host registry, event fan-out to browsers, and the
// browser ↔ host request relay.
//
// Transport model (WebSocket + HTTP API):
//
//	Browser (acp-fe) ──WS /ws/fe + HTTP /api/*──▶ acp-hub ──WS /ws/host──▶ acp-host × N ──stdio──▶ grok
//
// Hosts connect OUTBOUND to the hub (NAT-friendly): one WebSocket carries
// relayed browser requests down and host events / responds up. Browsers
// open /ws/fe for the aggregated live event stream; REST APIs stay on HTTP.
package hub

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// PairingCodeTTL is how long a pairing code stays valid.
	PairingCodeTTL = 15 * time.Minute
	// pairingCodeCheckInterval is how often the maintainer looks for an
	// expired pairing code to rotate.
	pairingCodeCheckInterval = 30 * time.Second
	// RelayTimeout caps how long the hub waits for a host to answer a
	// relayed request (mirrors the host's 30-minute prompt timeout).
	RelayTimeout = 45 * time.Minute
	// eventBufCap bounds per-host buffered events for gap-pull.
	eventBufCap = 4000
	// MaxHosts caps the registry so unbounded pair spam cannot grow
	// memory / hub.json without limit.
	MaxHosts = 256
	// Max lengths for pair fields (reject, do not truncate).
	maxHostIDLen   = 128
	maxHostNameLen = 256
)

// EventBufGrace is how long after a host disconnect we keep its gap-pull
// buffer so a short blip can still be filled via GET /api/events. Zero
// clears immediately (tests may shrink this).
var EventBufGrace = 60 * time.Second

var (
	// ErrCodeInvalid: the pairing code is wrong or expired.
	ErrCodeInvalid = errors.New("配对码无效或已过期")
	// ErrHostUnknown: hostId was never paired.
	ErrHostUnknown = errors.New("host 未配对")
	// ErrNoHost: nothing paired at all.
	ErrNoHost = errors.New("没有已配对的 host")
	// ErrHostLimit: registry is full (see MaxHosts).
	ErrHostLimit = errors.New("已达 host 数量上限")
)

// BrowserPrefs is the durable UI preferences for host conversations:
// pinned workspaces (cwd paths), pinned sessions, and per-session todo
// status ('todo' / 'completed'; absence = no record). The hub keeps ONE
// such document (prefs.json) for all browsers; the FE mirrors it in
// localStorage (offline cache) and writes it here (debounced) so
// pins/todos survive browser data clearing. Records are keyed by
// sessionId/cwd only — session ids are host-assigned UUIDs, so a doc is
// effectively per host conversation without an explicit hostId scope.
type BrowserPrefs struct {
	PinnedWorkspaces []string          `json:"pinnedWorkspaces"`
	PinnedSessions   []string          `json:"pinnedSessions"`
	Todos            map[string]string `json:"todos,omitempty"`
}

// RelayError carries an HTTP status code for relay failures.
type RelayError struct {
	Status  int
	Message string
}

func (e *RelayError) Error() string { return e.Message }

// Event is a host event relayed to browsers; the hub tags it with the
// host's hostId/hostName before fan-out.
type Event map[string]any

// HostInfo is the public registry entry (GET /api/hosts).
type HostInfo struct {
	HostID   string    `json:"hostId"`
	HostName string    `json:"hostName"`
	Online   bool      `json:"online"`
	Ready    bool      `json:"ready"`
	LastSeen time.Time `json:"lastSeen"`
	Local    bool      `json:"local,omitempty"`
}

// RelayRequest is pushed to a host over its WebSocket.
type RelayRequest struct {
	V      int             `json:"v"`
	Type   string          `json:"type"` // always "request"
	ReqID  string          `json:"reqId"`
	HostID string          `json:"hostId"` // 目标 host，host 端据此校验请求归属
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body,omitempty"`
}

// RelayResponse is the host's answer (WS type:"respond").
type RelayResponse struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body,omitempty"`
}

// streamConn is one host's live WebSocket (hub ↔ host). The hub
// writes relayed request / subscribers frames to it.
type streamConn struct {
	id    int64
	write func(payload []byte) error
}

type pendingReq struct {
	resp chan RelayResponse
	done chan struct{}
}

type hostState struct {
	info  HostInfo
	token string
	conn  *streamConn

	// seq is the last event sequence number seen from this host
	// (host-assigned, monotonic per host process). evBuf is a bounded
	// ring of recent events (with seq injected) so browsers can pull
	// gaps: GET /api/events?host=X&after=SEQ.
	seq   uint64
	evBuf []Event
	// evBufEpoch is bumped on disconnect (schedule clear) and reconnect
	// (cancel clear). A delayed clear only runs if the epoch still matches.
	evBufEpoch uint64
}

// Hub is the relay core. All methods are safe for concurrent use.
type Hub struct {
	mu sync.Mutex

	pairingCode string
	codeExpires time.Time

	tokens map[string]string // token → hostId
	hosts  map[string]*hostState

	subscribers map[chan Event]struct{}
	pending     map[string]map[string]*pendingReq

	nextReq    atomic.Int64
	nextConnID atomic.Int64

	dataFile string
	// prefsFile holds the browser prefs document (prefs.json, sibling of
	// hub.json). Written on SetPrefs only.
	prefsFile string
	prefs     BrowserPrefs
}

// codeAlphabet avoids look-alike characters (no I/L/O/0/1).
const codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// New returns a Hub that persists pairing state under ~/.acp-hub.
func New() *Hub {
	return NewWithDir(defaultDataDir())
}

// NewWithDir returns a Hub persisting to dir/hub.json; pass "" to disable
// persistence (used by tests).
func NewWithDir(dir string) *Hub {
	h := &Hub{
		tokens:      make(map[string]string),
		hosts:       make(map[string]*hostState),
		subscribers: make(map[chan Event]struct{}),
		pending:     make(map[string]map[string]*pendingReq),
		prefs:       BrowserPrefs{PinnedWorkspaces: []string{}, PinnedSessions: []string{}, Todos: map[string]string{}},
	}
	if dir != "" {
		h.dataFile = filepath.Join(dir, "hub.json")
		h.load()
		h.prefsFile = filepath.Join(dir, "prefs.json")
		h.loadPrefs()
	}
	h.rotateCode()
	return h
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".acp-hub")
}

// ── persistence ───────────────────────────────────────────────────────

type persistFile struct {
	Tokens map[string]string      `json:"tokens"`
	Hosts  map[string]persistHost `json:"hosts"`
}

type persistHost struct {
	HostID   string `json:"hostId"`
	HostName string `json:"hostName"`
	Ready    bool   `json:"ready"`
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
		h.hosts[id] = &hostState{
			info: HostInfo{HostID: id, HostName: ph.HostName, Ready: ph.Ready},
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
				info:  HostInfo{HostID: hid},
				token: tok,
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
		pf.Hosts[hid] = persistHost{HostID: hid, HostName: hs.info.HostName, Ready: hs.info.Ready}
	}
	return pf
}

// writePersist writes a snapshot to disk (unique temp + rename, mode 0600).
// It never takes h.mu: slow or flaky disk must not stall the whole hub.
// Concurrent callers each get their own temp file so they cannot clobber
// one another's .tmp or race on rename.
func (h *Hub) writePersist(pf persistFile) {
	if h.dataFile == "" {
		return
	}
	b, err := json.Marshal(pf)
	if err != nil {
		return
	}
	if err := writeFileAtomic(h.dataFile, b); err != nil {
		log.Printf("[acp-hub] persist: %v", err)
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

// ── browser preferences (pins / todos) ────────────────────────────────

// loadPrefs reads prefs.json into h.prefs. A missing file starts empty;
// an unreadable one is ignored (rebuilt on the next write).
func (h *Hub) loadPrefs() {
	b, err := os.ReadFile(h.prefsFile)
	if err != nil {
		return
	}
	var raw BrowserPrefs
	if json.Unmarshal(b, &raw) != nil {
		log.Printf("[acp-hub] prefs: ignoring unreadable %s", h.prefsFile)
		return
	}
	h.prefs = sanitizePrefs(raw)
}

// sanitizePrefs normalizes a decoded doc (nil slices → empty, nil todos →
// empty map) so callers never see nil containers.
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
	return p
}

// clonePrefs deep-copies a doc so stored state is never aliased by
// callers mutating what they received.
func clonePrefs(p BrowserPrefs) BrowserPrefs {
	todos := make(map[string]string, len(p.Todos))
	for k, v := range p.Todos {
		todos[k] = v
	}
	return sanitizePrefs(BrowserPrefs{
		PinnedWorkspaces: append([]string(nil), p.PinnedWorkspaces...),
		PinnedSessions:   append([]string(nil), p.PinnedSessions...),
		Todos:            todos,
	})
}

// Prefs returns a deep copy of the browser prefs doc (empty when the hub
// has never received one).
func (h *Hub) Prefs() BrowserPrefs {
	h.mu.Lock()
	defer h.mu.Unlock()
	return clonePrefs(h.prefs)
}

// SetPrefs replaces the browser prefs doc and persists it to prefs.json.
// The snapshot is taken under the lock; the file write runs outside it
// (same pattern as pairing state). The doc is small (pins + todos), so
// no size cap is enforced. Every accepted doc is broadcast to browser
// subscribers as `prefs_changed` (hub-level event, no hostId) so OTHER
// browsers apply the change live — one end's edit syncs to every end.
func (h *Hub) SetPrefs(prefs BrowserPrefs) error {
	cp := sanitizePrefs(clonePrefs(prefs))
	h.mu.Lock()
	persist := h.prefsFile != ""
	var payload []byte
	if persist {
		b, err := json.Marshal(cp)
		if err != nil {
			h.mu.Unlock()
			return fmt.Errorf("marshal prefs: %w", err)
		}
		payload = b
	}
	h.prefs = cp
	h.broadcastLocked(prefsChanged(cp))
	h.mu.Unlock()

	if persist {
		if err := writeFileAtomic(h.prefsFile, payload); err != nil {
			log.Printf("[acp-hub] prefs persist: %v", err)
		}
	}
	return nil
}

// prefsChanged builds the prefs broadcast event (hub-level, no hostId —
// browsers apply it regardless of the selected host).
func prefsChanged(prefs BrowserPrefs) Event {
	return Event{"type": "prefs_changed", "params": map[string]any{"prefs": prefs}}
}

// ── pairing ───────────────────────────────────────────────────────────

// PairingCode returns the current pairing code and its expiry. If the
// code has already expired it is rotated first so callers never see a
// dead code advertised as current.
func (h *Hub) PairingCode() (code string, expiresAt time.Time) {
	return h.ensureFreshPairingCode()
}

func (h *Hub) rotateCode() {
	h.pairingCode = randomString(codeAlphabet, 6)
	h.codeExpires = time.Now().Add(PairingCodeTTL)
}

// ensureFreshPairingCode rotates when expired; returns the live code.
func (h *Hub) ensureFreshPairingCode() (code string, expiresAt time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if time.Now().After(h.codeExpires) {
		h.rotateCode()
		log.Printf("[acp-hub] pairing code auto-rotated (expired): %s (expires %s)",
			h.pairingCode, h.codeExpires.Format("15:04:05"))
	}
	return h.pairingCode, h.codeExpires
}

// RotatePairingCode replaces the pairing code (old one stops working).
func (h *Hub) RotatePairingCode() (code string, expiresAt time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.rotateCode()
	log.Printf("[acp-hub] pairing code rotated: %s (expires %s)", h.pairingCode, h.codeExpires.Format("15:04:05"))
	return h.pairingCode, h.codeExpires
}

// StartPairingCodeMaintainer periodically rotates expired pairing codes
// until ctx is cancelled. Safe to call once per Hub.
func (h *Hub) StartPairingCodeMaintainer(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(pairingCodeCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.ensureFreshPairingCode()
			}
		}
	}()
}

// Pair exchanges a pairing code for a host token. Re-pairing an existing
// hostId revokes every previous token for that host (not only hs.token),
// so a restart that left multiple map entries cannot keep old credentials
// alive. State is snapshotted under the lock but written to disk outside
// it, so flaky storage never stalls the hub.
func (h *Hub) Pair(code, hostID, hostName string) (string, error) {
	h.mu.Lock()
	if strings.ToUpper(strings.TrimSpace(code)) != h.pairingCode {
		h.mu.Unlock()
		return "", ErrCodeInvalid
	}
	if time.Now().After(h.codeExpires) {
		h.mu.Unlock()
		return "", ErrCodeInvalid
	}
	hostID = strings.TrimSpace(hostID)
	hostName = strings.TrimSpace(hostName)
	if hostID == "" {
		h.mu.Unlock()
		return "", errors.New("hostId 不能为空")
	}
	if len(hostID) > maxHostIDLen {
		h.mu.Unlock()
		return "", fmt.Errorf("hostId 过长（上限 %d）", maxHostIDLen)
	}
	if len(hostName) > maxHostNameLen {
		h.mu.Unlock()
		return "", fmt.Errorf("hostName 过长（上限 %d）", maxHostNameLen)
	}
	if hs, ok := h.hosts[hostID]; ok {
		// Revoke every token for this hostId (covers multi-token legacy
		// after a pre-fix restart load).
		h.revokeTokensForHostLocked(hostID)
		hs.info.HostName = hostName
		hs.info.LastSeen = time.Now()
	} else {
		if len(h.hosts) >= MaxHosts {
			h.mu.Unlock()
			return "", ErrHostLimit
		}
		h.hosts[hostID] = &hostState{
			info: HostInfo{HostID: hostID, HostName: hostName, LastSeen: time.Now()},
		}
	}
	token := randomToken()
	h.tokens[token] = hostID
	h.hosts[hostID].token = token
	// Snapshot while holding the lock; write the file after releasing it.
	var snap persistFile
	persist := h.dataFile != ""
	if persist {
		snap = h.snapshotLocked()
	}
	h.mu.Unlock()

	if persist {
		h.writePersist(snap)
	}
	log.Printf("[acp-hub] host paired: %s (%s)", hostID, hostName)
	return token, nil
}

// Unpair removes a host from the registry: revokes all its tokens, fails
// in-flight relayed requests, drops its stream registration, and persists.
// An active transport is left to close itself (auth is already revoked;
// further events/dispatches for this hostId fail).
func (h *Hub) Unpair(hostID string) error {
	hostID = strings.TrimSpace(hostID)
	h.mu.Lock()
	hs := h.hosts[hostID]
	if hs == nil {
		h.mu.Unlock()
		return ErrHostUnknown
	}
	h.revokeTokensForHostLocked(hostID)
	h.failPendingLocked(hostID)
	hs.conn = nil
	hs.evBuf = nil
	delete(h.hosts, hostID)
	var snap persistFile
	persist := h.dataFile != ""
	if persist {
		snap = h.snapshotLocked()
	}
	h.broadcastLocked(hostsChanged())
	h.mu.Unlock()

	if persist {
		h.writePersist(snap)
	}
	log.Printf("[acp-hub] host unpaired: %s", hostID)
	return nil
}

// RenameHost updates a paired host's display name only — no token
// revocation, no connection teardown (unlike re-pairing via /api/pair,
// which would kick the host offline). Broadcasts hosts_changed so
// browsers refresh the registry live.
func (h *Hub) RenameHost(hostID, hostName string) error {
	hostID = strings.TrimSpace(hostID)
	hostName = strings.TrimSpace(hostName)
	if hostID == "" {
		return errors.New("hostId 不能为空")
	}
	if hostName == "" {
		return errors.New("hostName 不能为空")
	}
	if len(hostName) > maxHostNameLen {
		return fmt.Errorf("hostName 过长（上限 %d）", maxHostNameLen)
	}
	h.mu.Lock()
	hs := h.hosts[hostID]
	if hs == nil {
		h.mu.Unlock()
		return ErrHostUnknown
	}
	hs.info.HostName = hostName
	var snap persistFile
	persist := h.dataFile != ""
	if persist {
		snap = h.snapshotLocked()
	}
	h.broadcastLocked(hostsChanged())
	h.mu.Unlock()

	if persist {
		h.writePersist(snap)
	}
	log.Printf("[acp-hub] host renamed: %s → %s", hostID, hostName)
	return nil
}

// revokeTokensForHostLocked removes every token → hostID mapping and
// clears hostState.token. Caller must hold h.mu.
func (h *Hub) revokeTokensForHostLocked(hostID string) {
	for tok, hid := range h.tokens {
		if hid == hostID {
			delete(h.tokens, tok)
		}
	}
	if hs := h.hosts[hostID]; hs != nil {
		hs.token = ""
	}
}

// HostIDForToken resolves a host token to its hostId.
func (h *Hub) HostIDForToken(token string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	hid, ok := h.tokens[token]
	return hid, ok
}

// ── host connections ──────────────────────────────────────────────────

// ConnectStream registers the host's outbound stream; the returned stop
// func must be called when the connection ends (it fails all pending
// relayed requests for that host when this conn is still current).
//
// If the host already has a live stream, the new connection supersedes
// it: in-flight pending requests are failed immediately so they do not
// hang until RelayTimeout (the old stop is a no-op once superseded).
func (h *Hub) ConnectStream(hostID string, write func(payload []byte) error) (*streamConn, func(), error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	hs := h.hosts[hostID]
	if hs == nil {
		return nil, nil, ErrHostUnknown
	}
	// Supersede: fail requests that were written to the previous stream
	// (or still waiting) — the old connection's stop will not clear them.
	if hs.conn != nil {
		h.failPendingLocked(hostID)
	}
	// Cancel any pending grace-period buffer clear from a prior disconnect.
	hs.evBufEpoch++
	conn := &streamConn{id: h.nextConnID.Add(1), write: write}
	hs.conn = conn
	hs.info.Online = true
	hs.info.LastSeen = time.Now()
	h.broadcastLocked(hostsChanged())
	return conn, func() { h.disconnectStream(hostID, conn) }, nil
}

func (h *Hub) disconnectStream(hostID string, conn *streamConn) {
	h.mu.Lock()
	hs := h.hosts[hostID]
	if hs == nil || hs.conn != conn {
		h.mu.Unlock()
		return // superseded by a newer connection
	}
	hs.conn = nil
	hs.info.Online = false
	// Keep evBuf for EventBufGrace so short disconnects can still be
	// gap-pulled; schedule a clear that no-ops if the host reconnects.
	hs.evBufEpoch++
	epoch := hs.evBufEpoch
	h.failPendingLocked(hostID)
	h.broadcastLocked(hostsChanged())
	grace := EventBufGrace
	h.mu.Unlock()

	if grace <= 0 {
		h.mu.Lock()
		if hs := h.hosts[hostID]; hs != nil && hs.conn == nil && hs.evBufEpoch == epoch {
			hs.evBuf = nil
		}
		h.mu.Unlock()
		return
	}
	time.AfterFunc(grace, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		hs := h.hosts[hostID]
		if hs == nil || hs.conn != nil || hs.evBufEpoch != epoch {
			return
		}
		hs.evBuf = nil
	})
}

// IsCurrentConn reports whether connID is the host's live stream.
// Transport loops check it before processing each uplink frame: after a
// reconnect — or a duplicate host process pairing under the same hostId
// — the superseded connection must not keep feeding the hub, or its
// events would interleave with the new connection's seq space (both
// count from 1) and the stale-seq gate would drop events from whichever
// arrives later. The stale transport drops itself on its next frame.
func (h *Hub) IsCurrentConn(hostID string, conn *streamConn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	hs := h.hosts[hostID]
	return hs != nil && hs.conn == conn
}

// failPendingLocked closes and drops every pending request for hostID.
// Caller must hold h.mu.
func (h *Hub) failPendingLocked(hostID string) {
	for reqID, pr := range h.pending[hostID] {
		close(pr.done)
		delete(h.pending[hostID], reqID)
	}
	delete(h.pending, hostID)
}

// evSeq normalizes an event's seq across Go-native (uint64, direct
// RegisterEvent callers) and JSON-decoded (float64, wire frames) values.
func evSeq(ev Event) uint64 {
	switch s := ev["seq"].(type) {
	case float64:
		if s > 0 {
			return uint64(s)
		}
	case uint64:
		return s
	case int:
		if s > 0 {
			return uint64(s)
		}
	}
	return 0
}

// SetHostReady updates Ready from a control-plane host_status frame (no
// seq). Always refreshes LastSeen; if ready flips, updates Ready and
// broadcasts hosts_changed. Returns false for unknown hosts. Does not
// advance the per-host event seq or touch the transcript buffer.
func (h *Hub) SetHostReady(hostID string, ready bool) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	hs := h.hosts[hostID]
	if hs == nil {
		return false
	}
	hs.info.LastSeen = time.Now()
	if ready != hs.info.Ready {
		hs.info.Ready = ready
		h.broadcastLocked(hostsChanged())
	}
	return true
}

// ResetHostSeq clears the per-host event counter and gap-pull buffer.
// Used when a host process restarts: bridge seq restarts at 1 while the
// hub still holds the previous process's LastSeq — without a reset, the
// hub would skip fan-out for every new event with s <= old LastSeq.
// Does not change Ready/Online or fire hosts_changed.
func (h *Hub) ResetHostSeq(hostID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	hs := h.hosts[hostID]
	if hs == nil {
		return false
	}
	prev := hs.seq
	hs.seq = 0
	hs.evBuf = nil
	hs.info.LastSeen = time.Now()
	if prev > 0 {
		log.Printf("[acp-hub] host %s seq reset (was %d) — host process restart", hostID, prev)
	}
	return true
}

// RegisterEvent accepts a host event: tags it with the host's id/name,
// assigns a sequence number (host-provided when present, else hub-side),
// buffers it for gap-pull, updates liveness (and ready for host_status
// events), then fans it out to browser subscribers. Returns false for
// unknown hosts.
//
// When the host provides a seq s > 0 that is not strictly greater than
// the already-seen max (s <= hs.seq), LastSeen is still refreshed but
// the event is neither buffered nor broadcast — reconnect residual +
// replay must not re-fan-out duplicates to the FE. The counter never
// regresses.
func (h *Hub) RegisterEvent(hostID string, ev Event) bool {
	if ev == nil {
		// A malformed frame (e.g. {"events":[null]}) must never panic the
		// process — the QUIC path runs without net/http's recover.
		return false
	}
	// Shallow-copy before tagging/buffering/broadcast: the caller's map
	// must never gain injected keys, and the same map must not be shared
	// between the replay buffer, every subscriber channel, and
	// EventsAfter callers (one consumer mutating it would leak into all
	// the others).
	cp := make(Event, len(ev))
	for k, v := range ev {
		cp[k] = v
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	hs := h.hosts[hostID]
	if hs == nil {
		return false
	}
	hs.info.LastSeen = time.Now()
	// Host-provided seq (events frames carry per-event seq); fall back to
	// hub-side assignment for direct RegisterEvent callers (tests).
	if s := evSeq(cp); s > 0 {
		// Skip fan-out for duplicate/stale seqs (reconnect residual +
		// replay). Counter must never move backwards.
		if s <= hs.seq {
			if s < hs.seq {
				log.Printf("[acp-hub] host %s event seq regressed: got %d, last %d (skip fan-out)", hostID, s, hs.seq)
			}
			return true
		}
		hs.seq = s
	} else {
		hs.seq++
		cp["seq"] = hs.seq
	}
	hs.evBuf = append(hs.evBuf, cp)
	if len(hs.evBuf) > eventBufCap {
		// Copy into a fresh slice so the discarded prefix (and its Event
		// maps) are not retained by the underlying array — a plain reslice
		// would pin up to eventBufCap extra events until the next realloc.
		n := eventBufCap
		trimmed := make([]Event, n)
		copy(trimmed, hs.evBuf[len(hs.evBuf)-n:])
		hs.evBuf = trimmed
	}
	// Back-compat: old hosts still send host_status inside events frames.
	if t, _ := cp["type"].(string); t == "host_status" {
		if r, ok := cp["ready"].(bool); ok && r != hs.info.Ready {
			hs.info.Ready = r
			h.broadcastLocked(hostsChanged())
		}
	}
	cp["hostId"] = hostID
	cp["hostName"] = hs.info.HostName
	h.broadcastLocked(cp)
	return true
}

// LastSeq returns the last event sequence number seen from hostID
// (0 when unknown / nothing seen yet).
func (h *Hub) LastSeq(hostID string) uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if hs := h.hosts[hostID]; hs != nil {
		return hs.seq
	}
	return 0
}

// SeqByHost returns the last event seq for every known host (for the FE
// hello frame so browsers can detect what they missed while offline).
func (h *Hub) SeqByHost() map[string]uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]uint64, len(h.hosts))
	for id, hs := range h.hosts {
		out[id] = hs.seq
	}
	return out
}

// EventsAfter returns buffered events for hostID whose seq > after, in
// ascending order. The returned slice shares storage with the hub buffer;
// callers must not mutate the events.
func (h *Hub) EventsAfter(hostID string, after uint64) []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	if hs := h.hosts[hostID]; hs != nil {
		out := make([]Event, 0, 8)
		for _, ev := range hs.evBuf {
			if evSeq(ev) > after {
				out = append(out, ev)
			}
		}
		return out
	}
	return nil
}

// ── request relay ─────────────────────────────────────────────────────

// Dispatch relays a browser request to a host and waits for its answer.
// The host must have a live stream; otherwise a *RelayError is returned.
func (h *Hub) Dispatch(hostID, method, path string, body json.RawMessage) (RelayResponse, error) {
	reqID := fmt.Sprintf("%d", h.nextReq.Add(1))

	h.mu.Lock()
	hs := h.hosts[hostID]
	if hs == nil {
		h.mu.Unlock()
		return RelayResponse{}, &RelayError{Status: 404, Message: ErrHostUnknown.Error()}
	}
	conn := hs.conn
	if conn == nil {
		h.mu.Unlock()
		return RelayResponse{}, &RelayError{Status: 503, Message: fmt.Sprintf("host %s 当前离线", hostID)}
	}
	pr := &pendingReq{resp: make(chan RelayResponse, 1), done: make(chan struct{})}
	if h.pending[hostID] == nil {
		h.pending[hostID] = make(map[string]*pendingReq)
	}
	h.pending[hostID][reqID] = pr
	h.mu.Unlock()

	payload, err := json.Marshal(RelayRequest{V: 1, Type: "request", ReqID: reqID, HostID: hostID, Method: method, Path: path, Body: body})
	if err != nil {
		h.dropPending(hostID, reqID)
		return RelayResponse{}, &RelayError{Status: 500, Message: err.Error()}
	}
	if err := conn.write(payload); err != nil {
		h.dropPending(hostID, reqID)
		return RelayResponse{}, &RelayError{Status: 503, Message: fmt.Sprintf("host %s 已断开", hostID)}
	}

	timer := time.NewTimer(RelayTimeout)
	defer timer.Stop()
	// A response that already arrived must win over a concurrently
	// firing timeout: select would otherwise pick the timer branch at
	// random and drop an answer that is already here.
	select {
	case resp := <-pr.resp:
		return resp, nil
	default:
	}
	select {
	case resp := <-pr.resp:
		return resp, nil
	case <-pr.done:
		return RelayResponse{}, &RelayError{Status: 503, Message: fmt.Sprintf("host %s 已断开", hostID)}
	case <-timer.C:
		h.dropPending(hostID, reqID)
		return RelayResponse{}, &RelayError{Status: 504, Message: "中继超时"}
	}
}

func (h *Hub) dropPending(hostID, reqID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if m := h.pending[hostID]; m != nil {
		delete(m, reqID)
		if len(m) == 0 {
			delete(h.pending, hostID)
		}
	}
}

// Respond resolves a relayed request with the host's answer.
func (h *Hub) Respond(hostID, reqID string, resp RelayResponse) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	m := h.pending[hostID]
	if m == nil {
		return false
	}
	pr, ok := m[reqID]
	if !ok {
		return false
	}
	delete(m, reqID)
	if len(m) == 0 {
		delete(h.pending, hostID)
	}
	if hs := h.hosts[hostID]; hs != nil {
		hs.info.LastSeen = time.Now()
	}
	pr.resp <- resp
	return true
}

// ── registry / browsers ───────────────────────────────────────────────

// ListHosts returns the registry, online hosts first, most recently seen
// first.
func (h *Hub) ListHosts() []HostInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]HostInfo, 0, len(h.hosts))
	for _, hs := range h.hosts {
		out = append(out, hs.info)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Online != out[j].Online {
			return out[i].Online
		}
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].HostID < out[j].HostID
	})
	return out
}

// DefaultHostID picks the host for requests that don't name one: the most
// recently seen online host, else the most recently seen one overall.
func (h *Hub) DefaultHostID() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var best string
	for _, hs := range h.hosts {
		if hs.info.Online {
			if best == "" || hs.info.LastSeen.After(h.hosts[best].info.LastSeen) {
				best = hs.info.HostID
			}
		}
	}
	if best != "" {
		return best
	}
	for _, hs := range h.hosts {
		if best == "" || hs.info.LastSeen.After(h.hosts[best].info.LastSeen) {
			best = hs.info.HostID
		}
	}
	return best
}

// Subscribe returns a buffered channel of relayed events; call the
// returned func to unsubscribe.
//
// Subscribe/unsubscribe notify connected hosts of the browser subscriber
// count so they can pause event upload when nobody is listening (heartbeat
// host_status still runs on the host side).
func (h *Hub) Subscribe() (ch chan Event, unsubscribe func()) {
	ch, unsub, _ := h.TrySubscribe(0) // 0 = unlimited
	return ch, unsub
}

// TrySubscribe is Subscribe with a subscriber cap: when max > 0 and the
// hub already has max live browser subscribers, it returns ok=false
// instead of registering another. Each subscriber costs a 512-event
// channel plus the caller's goroutines, so the /ws/fe endpoint uses this
// as a resource guard when it is open to unauthenticated clients.
func (h *Hub) TrySubscribe(max int) (ch chan Event, unsubscribe func(), ok bool) {
	// Larger than the old SSE path: WS fan-out still drops on a full buffer,
	// but 512 absorbs short FE write stalls without losing a turn of chunks.
	ch = make(chan Event, 512)
	h.mu.Lock()
	if max > 0 && len(h.subscribers) >= max {
		h.mu.Unlock()
		return nil, nil, false
	}
	h.subscribers[ch] = struct{}{}
	h.mu.Unlock()
	h.notifyHostsSubscribers()
	return ch, func() {
		h.mu.Lock()
		delete(h.subscribers, ch)
		h.mu.Unlock()
		for {
			select {
			case <-ch:
			default:
				goto drained
			}
		}
	drained:
		h.notifyHostsSubscribers()
	}, true
}

// SubscriberCount is the number of live browser /ws/fe clients.
func (h *Hub) SubscriberCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subscribers)
}

// notifyHostsSubscribers pushes {v:1, type:"subscribers", count:N} to every
// online host WebSocket. Hosts use count==0 to stop uploading bridge events
// (they still send host_status heartbeats). Writes run outside h.mu so a
// slow host cannot stall the hub lock.
func (h *Hub) notifyHostsSubscribers() {
	h.mu.Lock()
	count := len(h.subscribers)
	writes := make([]func([]byte) error, 0, len(h.hosts))
	for _, hs := range h.hosts {
		if hs.conn != nil {
			writes = append(writes, hs.conn.write)
		}
	}
	h.mu.Unlock()
	if len(writes) == 0 {
		return
	}
	payload, err := json.Marshal(map[string]any{"v": 1, "type": "subscribers", "count": count})
	if err != nil {
		return
	}
	// Fire-and-forget per host: writes carry a multi-second timeout each,
	// so one half-open host must not stall the caller (subscribe /
	// unsubscribe) — the count frames are absolute notifications, a
	// briefly delayed one is harmless.
	for _, write := range writes {
		go func(w func([]byte) error) {
			_ = w(payload)
		}(write)
	}
}

// Broadcast fans an event out to browser subscribers (drops for slow
// consumers). Callers typically use RegisterEvent instead.
func (h *Hub) Broadcast(ev Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.broadcastLocked(ev)
}

func (h *Hub) broadcastLocked(ev Event) {
	for ch := range h.subscribers {
		select {
		case ch <- ev:
		default:
			// Slow FE /ws/fe: drop this event for that subscriber only.
			// Host-assigned seqs may then look gapped on that client
			// (e.g. 1 then 3). Expected: FE uses GET /api/events?after=
			// gap-pull and (hostId,seq) dedup; do not block the hub
			// lock or invent continuous seqs here.
		}
	}
}

func hostsChanged() Event {
	return Event{"type": "hosts_changed", "params": map[string]any{}}
}

// ── helpers ───────────────────────────────────────────────────────────

func randomString(alphabet string, n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// Never block pairing on a broken RNG.
		now := time.Now().UnixNano()
		for i := range b {
			now = now*6364136223846793005 + 1442695040888963407
			b[i] = alphabet[int(now>>33)%len(alphabet)]
		}
		return string(b)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
