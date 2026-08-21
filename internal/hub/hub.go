// Package hub implements the capri-hub relay core: host pairing (pairing
// code → token), the host registry, event fan-out to browsers, and the
// browser ↔ host request relay.
//
// Transport model (WebSocket + HTTP API):
//
//	Browser (capri-fe) ──WS /ws/fe + HTTP /api/*──▶ capri-hub ──WS /ws/host──▶ capri-host × N ──stdio──▶ grok
//
// Hosts connect OUTBOUND to the hub (NAT-friendly): one WebSocket carries
// relayed browser requests down and host events / responds up. Browsers
// open /ws/fe for the aggregated live event stream; REST APIs stay on HTTP.
package hub

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
	// evBufHighWater is where RegisterEvent compacts the buffer back down
	// to eventBufCap. Compacting on every overflow instead would copy the
	// whole buffer per event (see RegisterEvent); the slack makes it
	// amortized O(1) at the cost of at most 2× the buffer.
	evBufHighWater = 2 * eventBufCap
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

// FePrefs is the FE-side appearance preferences (e.g. scrollback toolcall
// group folding). The hub stores and relays the map verbatim — it never
// interprets keys/values, so the FE can extend it without a hub release.
type FePrefs map[string]any

// BrowserPrefs is the durable UI preferences for host conversations:
// pinned workspaces (cwd paths), pinned sessions, per-session todo
// status ('todo' / 'completed'; absence = no record) and FE-side
// appearance prefs (fePrefs). The hub keeps ONE such document
// (prefs.json) for all browsers; the FE mirrors it in localStorage
// (offline cache) and writes it here (debounced) so pins/todos survive
// browser data clearing. Records are keyed by sessionId/cwd only — session
// ids are host-assigned UUIDs, so a doc is effectively per host
// conversation without an explicit hostId scope.
type BrowserPrefs struct {
	PinnedWorkspaces []string          `json:"pinnedWorkspaces"`
	PinnedSessions   []string          `json:"pinnedSessions"`
	Todos            map[string]string `json:"todos,omitempty"`
	FePrefs          FePrefs           `json:"fePrefs,omitempty"`
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

	// mu guards seq/evBuf ONLY (the per-host data plane). The global h.mu
	// protects the registry (hosts/tokens maps, conn, info, pending) —
	// event ingestion no longer serializes every host behind it. Lock
	// order is always h.mu → hs.mu; nothing takes them the other way.
	mu sync.Mutex

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

	// subs is the browser-subscriber set as a copy-on-write slice behind
	// an atomic pointer: fan-out reads the snapshot lock-free, and
	// subscribe/unsubscribe swap in a new slice under h.mu. Churn is rare
	// (browser connect/disconnect) while fan-out runs per event, so
	// readers never contend on h.mu.
	subs    atomic.Pointer[[]*feSubscriber]
	pending map[string]map[string]*pendingReq

	nextReq    atomic.Int64
	nextConnID atomic.Int64
	// subsGen stamps every subscriber-count frame so hosts can discard an
	// out-of-order delivery (see notifyHostsSubscribers).
	subsGen atomic.Uint64
	// lastNotifiedSubs is the count carried by the last notification
	// (nil = never notified), used to skip no-op resends.
	lastNotifiedSubs *int

	dataFile string
	// prefsFile holds the browser prefs document (prefs.json, sibling of
	// hub.json). Written on SetPrefs only.
	prefsFile string
	prefs     BrowserPrefs
}

// codeAlphabet avoids look-alike characters (no I/L/O/0/1).
const codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// New returns a Hub that persists pairing state under ~/.capri-hub.
func New() *Hub {
	return NewWithDir(defaultDataDir())
}

// NewWithDir returns a Hub persisting to dir/hub.json; pass "" to disable
// persistence (used by tests).
func NewWithDir(dir string) *Hub {
	emptySubs := []*feSubscriber{}
	h := &Hub{
		tokens:  make(map[string]string),
		hosts:   make(map[string]*hostState),
		pending: make(map[string]map[string]*pendingReq),
		prefs:   BrowserPrefs{PinnedWorkspaces: []string{}, PinnedSessions: []string{}, Todos: map[string]string{}},
	}
	h.subs.Store(&emptySubs)
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
	return filepath.Join(home, ".capri-hub")
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
		log.Printf("[capri-hub] prefs: ignoring unreadable %s", h.prefsFile)
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
	fePrefs := make(FePrefs, len(p.FePrefs))
	for k, v := range p.FePrefs {
		fePrefs[k] = v
	}
	return sanitizePrefs(BrowserPrefs{
		PinnedWorkspaces: append([]string(nil), p.PinnedWorkspaces...),
		PinnedSessions:   append([]string(nil), p.PinnedSessions...),
		Todos:            todos,
		FePrefs:          fePrefs,
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
	h.broadcast(prefsChanged(cp))
	h.mu.Unlock()

	if persist {
		if err := writeFileAtomic(h.prefsFile, payload); err != nil {
			log.Printf("[capri-hub] prefs persist: %v", err)
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
		log.Printf("[capri-hub] pairing code auto-rotated (expired): %s (expires %s)",
			h.pairingCode, h.codeExpires.Format("15:04:05"))
	}
	return h.pairingCode, h.codeExpires
}

// RotatePairingCode replaces the pairing code (old one stops working).
func (h *Hub) RotatePairingCode() (code string, expiresAt time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.rotateCode()
	log.Printf("[capri-hub] pairing code rotated: %s (expires %s)", h.pairingCode, h.codeExpires.Format("15:04:05"))
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
	// Constant-time compare: the pairing code is a short-lived secret and
	// POST /api/pair is internet-reachable, so the comparison must not
	// leak how many leading bytes matched. (subtle.ConstantTimeCompare
	// still returns 0 immediately for differing lengths — the code length
	// is fixed public knowledge, so that leak is harmless.)
	if subtle.ConstantTimeCompare([]byte(strings.ToUpper(strings.TrimSpace(code))), []byte(h.pairingCode)) != 1 {
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
	log.Printf("[capri-hub] host paired: %s (%s)", hostID, hostName)
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
	delete(h.hosts, hostID)
	hs.mu.Lock()
	hs.evBuf = nil
	hs.mu.Unlock()
	var snap persistFile
	persist := h.dataFile != ""
	if persist {
		snap = h.snapshotLocked()
	}
	h.broadcast(hostsChanged())
	h.mu.Unlock()

	if persist {
		h.writePersist(snap)
	}
	log.Printf("[capri-hub] host unpaired: %s", hostID)
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
	h.broadcast(hostsChanged())
	h.mu.Unlock()

	if persist {
		h.writePersist(snap)
	}
	log.Printf("[capri-hub] host renamed: %s → %s", hostID, hostName)
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
	h.broadcast(hostsChanged())
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
	h.broadcast(hostsChanged())
	grace := EventBufGrace
	h.mu.Unlock()

	if grace <= 0 {
		h.mu.Lock()
		hs := h.hosts[hostID]
		if hs != nil && hs.conn == nil && hs.evBufEpoch == epoch {
			hs.mu.Lock()
			hs.evBuf = nil
			hs.mu.Unlock()
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
		hs.mu.Lock()
		hs.evBuf = nil
		hs.mu.Unlock()
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

// EvSeq is the exported form of evSeq (used by cmd/capri-hub's frame-level
// seqStart validation).
func EvSeq(ev Event) uint64 { return evSeq(ev) }

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
		h.broadcast(hostsChanged())
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
	hs := h.hosts[hostID]
	if hs == nil {
		h.mu.Unlock()
		return false
	}
	hs.info.LastSeen = time.Now()
	h.mu.Unlock()
	hs.mu.Lock()
	prev := hs.seq
	hs.seq = 0
	hs.evBuf = nil
	hs.mu.Unlock()
	if prev > 0 {
		log.Printf("[capri-hub] host %s seq reset (was %d) — host process restart", hostID, prev)
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
	// Global lock only for the registry lookup + liveness; the seq /
	// buffer update runs under the per-host lock and fan-out is
	// lock-free, so one host's event ingest cannot serialize every other
	// host behind h.mu (see hostState.mu).
	h.mu.Lock()
	hs := h.hosts[hostID]
	if hs == nil {
		h.mu.Unlock()
		return false
	}
	hs.info.LastSeen = time.Now()
	hostName := hs.info.HostName
	h.mu.Unlock()

	if fanout := hs.appendEvent(cp, hostID, hostName); fanout != nil {
		// Back-compat: old hosts still send host_status inside events
		// frames — flip Ready (and fire hosts_changed) via the same
		// control-plane path WS host_status uses.
		if t, _ := cp["type"].(string); t == "host_status" {
			if r, ok := cp["ready"].(bool); ok {
				h.SetHostReady(hostID, r)
			}
		}
		h.broadcast(fanout)
	}
	return true
}

// appendEvent is RegisterEvent's per-host data-plane section: seq gating
// (host-provided preserved, stale/duplicate skipped, hub-side assignment
// otherwise), hostId/hostName tagging, gap-pull buffering and amortized
// compaction. Returns the tagged event to fan out, or nil when the event
// was stale/duplicate (accepted, LastSeen already refreshed — same
// contract as before). Runs under hs.mu only.
func (hs *hostState) appendEvent(cp Event, hostID, hostName string) Event {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if s := evSeq(cp); s > 0 {
		// Skip fan-out for duplicate/stale seqs (reconnect residual +
		// replay). Counter must never move backwards.
		if s <= hs.seq {
			if s < hs.seq {
				log.Printf("[capri-hub] host %s event seq regressed: got %d, last %d (skip fan-out)", hostID, s, hs.seq)
			}
			return nil
		}
		hs.seq = s
	} else {
		hs.seq++
		cp["seq"] = hs.seq
	}
	cp["hostId"] = hostID
	cp["hostName"] = hostName
	hs.evBuf = append(hs.evBuf, cp)
	if len(hs.evBuf) > evBufHighWater {
		// Amortized compaction (see RegisterEvent history / evBufHighWater):
		// one fresh array per eventBufCap events instead of a reallocating
		// copy per event. The copy (not a reslice) keeps the dropped Event
		// maps from staying reachable via the old backing array.
		trimmed := make([]Event, eventBufCap, evBufHighWater)
		copy(trimmed, hs.evBuf[len(hs.evBuf)-eventBufCap:])
		hs.evBuf = trimmed
	}
	return cp
}

// ── raw (pre-encoded) event fast path ─────────────────────────────────
//
// Events arriving over the wire used to be fully decoded into Event maps
// (one map + one allocation per leaf value per event — chunk storms burn
// most of the hub's CPU there) and then re-encoded per FE on fan-out. The
// raw path instead keeps the event body as json.RawMessage end-to-end:
// only the fields the hub itself needs (seq/type/ready) are shallow
// parsed, and the FE-bound wire bytes are produced once by splicing the
// hub's hostId/hostName tags into the original bytes.
//
// rawWireKey is the reserved Event key under which the canonical wire
// bytes travel through the fan-out channel and the gap-pull buffer. An
// Event carrying it is opaque: consumers must serialize it via
// MarshalEvent (which returns the bytes verbatim) instead of
// json.Marshal. The key starts with NUL so it can never collide with a
// wire field name. Alongside the raw bytes the map carries the few
// shallow fields hub/FE code inspects: type, seq, hostId, hostName.
const rawWireKey = "\x00wire"

// MarshalEvent serializes one event to its canonical wire bytes: the
// pre-encoded bytes verbatim for raw-path events, a plain marshal for
// legacy map events.
func MarshalEvent(ev Event) ([]byte, error) {
	if raw, ok := ev[rawWireKey].(json.RawMessage); ok {
		return raw, nil
	}
	return json.Marshal(ev)
}

// rawEventMeta is the shallow header the hub needs from every raw event.
type rawEventMeta struct {
	Seq   uint64 `json:"seq"`
	Type  string `json:"type"`
	Ready bool   `json:"ready"`
}

// spliceRawEvent builds the FE-bound wire bytes for one raw event by
// appending the hub's tags before the closing brace of the original
// object. Appending (rather than prepending) preserves the legacy
// RegisterEvent semantics under duplicate keys — the hub's hostId /
// hostName / injected seq always win (encoding/json keeps the LAST
// occurrence). Returns nil when raw is not a JSON object (caller skips).
func spliceRawEvent(raw, idJSON, nameJSON []byte, seq uint64, injectSeq bool) json.RawMessage {
	r := bytes.TrimRight(raw, " \t\r\n")
	if len(r) < 2 || r[0] != '{' || r[len(r)-1] != '}' {
		return nil
	}
	out := make([]byte, 0, len(r)+len(idJSON)+len(nameJSON)+48)
	out = append(out, r[:len(r)-1]...)
	if len(out) > 1 { // non-empty object: separate from existing members
		out = append(out, ',')
	}
	if injectSeq {
		out = append(out, `"seq":`...)
		out = strconv.AppendUint(out, seq, 10)
		out = append(out, ',')
	}
	out = append(out, `"hostId":`...)
	out = append(out, idJSON...)
	out = append(out, `,"hostName":`...)
	out = append(out, nameJSON...)
	out = append(out, '}')
	return json.RawMessage(out)
}

// RegisterRawEvents is RegisterEvent for events still in their original
// wire form (host events frames): each body stays json.RawMessage, only
// seq/type/ready are shallow-parsed, and the FE-bound bytes are spliced
// once instead of decode-map + re-encode per subscriber. Semantics match
// RegisterEvent exactly: seq gating / hub-side assignment, gap-pull
// buffering, host_status ready flip, hostId/hostName tagging. Non-object
// entries (e.g. null) are skipped. Returns false only for unknown hosts.
func (h *Hub) RegisterRawEvents(hostID string, raws []json.RawMessage) bool {
	// Same locking shape as RegisterEvent: global lock for lookup +
	// liveness only; seq/buffer under the per-host lock; fan-out
	// lock-free (see hostState.mu).
	h.mu.Lock()
	hs := h.hosts[hostID]
	if hs == nil {
		h.mu.Unlock()
		return false
	}
	hs.info.LastSeen = time.Now()
	hostName := hs.info.HostName
	h.mu.Unlock()

	idJSON, _ := json.Marshal(hostID)
	nameJSON, _ := json.Marshal(hostName)
	for _, raw := range raws {
		// Validate shape BEFORE consuming a seq from the counter.
		r := bytes.TrimRight(raw, " \t\r\n")
		if len(r) < 2 || r[0] != '{' || r[len(r)-1] != '}' {
			log.Printf("[capri-hub] host %s non-object event skipped", hostID)
			continue
		}
		var meta rawEventMeta
		if err := json.Unmarshal(r, &meta); err != nil {
			continue
		}
		hs.mu.Lock()
		// Same seq gating as appendEvent: preserve host seqs, skip
		// stale/duplicate, fall back to hub-side assignment.
		if meta.Seq > 0 {
			if meta.Seq <= hs.seq {
				if meta.Seq < hs.seq {
					log.Printf("[capri-hub] host %s event seq regressed: got %d, last %d (skip fan-out)", hostID, meta.Seq, hs.seq)
				}
				hs.mu.Unlock()
				continue
			}
			hs.seq = meta.Seq
		} else {
			hs.seq++
		}
		wire := spliceRawEvent(r, idJSON, nameJSON, hs.seq, meta.Seq == 0)
		if wire == nil {
			hs.mu.Unlock()
			log.Printf("[capri-hub] host %s non-object event skipped", hostID)
			continue
		}
		ev := Event{
			rawWireKey: wire,
			"type":     meta.Type,
			"seq":      float64(hs.seq),
			"hostId":   hostID,
			"hostName": hostName,
		}
		hs.evBuf = append(hs.evBuf, ev)
		if len(hs.evBuf) > evBufHighWater {
			trimmed := make([]Event, eventBufCap, evBufHighWater)
			copy(trimmed, hs.evBuf[len(hs.evBuf)-eventBufCap:])
			hs.evBuf = trimmed
		}
		hs.mu.Unlock()
		// Back-compat: old hosts still send host_status inside events
		// frames (see RegisterEvent).
		if meta.Type == "host_status" {
			h.SetHostReady(hostID, meta.Ready)
		}
		h.broadcast(ev)
	}
	return true
}

// LastSeq returns the last event sequence number seen from hostID
// (0 when unknown / nothing seen yet).
func (h *Hub) LastSeq(hostID string) uint64 {
	h.mu.Lock()
	hs := h.hosts[hostID]
	h.mu.Unlock()
	if hs == nil {
		return 0
	}
	hs.mu.Lock()
	defer hs.mu.Unlock()
	return hs.seq
}

// SeqByHost returns the last event seq for every known host (for the FE
// hello frame so browsers can detect what they missed while offline).
func (h *Hub) SeqByHost() map[string]uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]uint64, len(h.hosts))
	for id, hs := range h.hosts {
		hs.mu.Lock()
		out[id] = hs.seq
		hs.mu.Unlock()
	}
	return out
}

// EventsAfter returns buffered events for hostID whose seq > after, in
// ascending order. The returned slice shares storage with the hub buffer;
// callers must not mutate the events.
func (h *Hub) EventsAfter(hostID string, after uint64) []Event {
	h.mu.Lock()
	hs := h.hosts[hostID]
	h.mu.Unlock()
	if hs == nil {
		return nil
	}
	hs.mu.Lock()
	defer hs.mu.Unlock()
	// evBuf is append-only in strictly increasing seq order (RegisterEvent
	// drops anything <= the watermark), so the cut point can be found by
	// binary search instead of scanning up to evBufHighWater events on
	// every reconnect gap-pull.
	i := sort.Search(len(hs.evBuf), func(i int) bool {
		return evSeq(hs.evBuf[i]) > after
	})
	if i >= len(hs.evBuf) {
		return nil
	}
	out := make([]Event, len(hs.evBuf)-i)
	copy(out, hs.evBuf[i:])
	return out
}

// ── request relay ─────────────────────────────────────────────────────

// Dispatch relays a browser request to a host and waits for its answer.
// The host must have a live stream; otherwise a *RelayError is returned.
//
// ctx is the BROWSER's request context. When it is cancelled (tab closed,
// navigation, mobile network drop) the wait is abandoned and the pending
// slot freed immediately. Without that, an abandoned request pinned a
// goroutine, a pending map entry and a 45-minute timer (RelayTimeout) for
// the full timeout — a flaky client retrying prompts accumulates them until
// the hub runs out of room. Cancelling the WAIT deliberately does NOT
// cancel the host-side work: the prompt keeps running on the agent (that is
// the point of the server-authoritative design) and its output still
// reaches browsers over the event stream.
func (h *Hub) Dispatch(ctx context.Context, hostID, method, path string, body json.RawMessage) (RelayResponse, error) {
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
	case <-ctx.Done():
		// Browser gone: stop waiting and release the pending slot. The host
		// keeps executing; its late respond simply finds no pending entry.
		h.dropPending(hostID, reqID)
		return RelayResponse{}, &RelayError{Status: 499, Message: "客户端已取消"}
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

// feSubscriber is one browser /ws/fe registration. The channel is the
// fan-out queue; per-subscriber pressure state (drop counters, T5) hangs
// off this struct so the copy-on-write list stays a plain slice.
type feSubscriber struct {
	ch chan Event
}

// subscribeLocked registers s in the copy-on-write subscriber list. The
// caller must hold h.mu; readers (broadcast) see the old or new slice,
// never a torn one.
func (h *Hub) subscribeLocked(s *feSubscriber) {
	var next []*feSubscriber
	if cur := h.subs.Load(); cur != nil {
		next = make([]*feSubscriber, 0, len(*cur)+1)
		next = append(next, *cur...)
	} else {
		next = make([]*feSubscriber, 0, 1)
	}
	next = append(next, s)
	h.subs.Store(&next)
}

// unsubscribe removes s (copy-on-write, under h.mu).
func (h *Hub) unsubscribe(s *feSubscriber) {
	var cur []*feSubscriber
	if p := h.subs.Load(); p != nil {
		cur = *p
	}
	next := make([]*feSubscriber, 0, len(cur))
	for _, sub := range cur {
		if sub != s {
			next = append(next, sub)
		}
	}
	h.subs.Store(&next)
}

// TrySubscribe is Subscribe with a subscriber cap: when max > 0 and the
// hub already has max live browser subscribers, it returns ok=false
// instead of registering another. Each subscriber costs a 512-event
// channel plus the caller's goroutines, so the /ws/fe endpoint uses this
// as a resource guard when it is open to unauthenticated clients.
func (h *Hub) TrySubscribe(max int) (ch chan Event, unsubscribe func(), ok bool) {
	// Larger than the old SSE path: WS fan-out still drops on a full buffer,
	// but 512 absorbs short FE write stalls without losing a turn of chunks.
	s := &feSubscriber{ch: make(chan Event, 512)}
	h.mu.Lock()
	if cur := h.subs.Load(); cur != nil && max > 0 && len(*cur) >= max {
		h.mu.Unlock()
		return nil, nil, false
	}
	h.subscribeLocked(s)
	h.mu.Unlock()
	h.notifyHostsSubscribers()
	return s.ch, func() {
		h.mu.Lock()
		h.unsubscribe(s)
		h.mu.Unlock()
		for {
			select {
			case <-s.ch:
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
	if cur := h.subs.Load(); cur != nil {
		return len(*cur)
	}
	return 0
}

// notifyHostsSubscribers pushes {v:1, type:"subscribers", count:N, gen:G} to
// every online host WebSocket. Hosts use count==0 to stop uploading bridge
// events (they still send host_status heartbeats). Writes run outside h.mu so
// a slow host cannot stall the hub lock.
//
// `gen` is a hub-monotonic generation stamp and it is load-bearing: the
// frames are ABSOLUTE state, they are written from one fire-and-forget
// goroutine per host, and a slow write can therefore deliver them OUT OF
// ORDER. Without the stamp a browser refresh (unsubscribe → count 0,
// resubscribe → count 1, microseconds apart) can land as 1 then 0, leaving
// the host convinced nobody is watching: it stops uploading bridge events
// while host_status heartbeats keep it "online", so the freshly reloaded
// page shows a live-looking but permanently frozen session. Hosts keep the
// highest gen seen and ignore anything older.
//
// A count that has not changed since the last notification is not resent
// (browser churn on a multi-tab hub is otherwise a per-host write storm);
// a lost frame is repaired by the periodic re-assert on the host ping.
func (h *Hub) notifyHostsSubscribers() {
	h.mu.Lock()
	var count int
	if cur := h.subs.Load(); cur != nil {
		count = len(*cur)
	}
	if h.lastNotifiedSubs != nil && *h.lastNotifiedSubs == count {
		h.mu.Unlock()
		return
	}
	h.lastNotifiedSubs = &count
	gen := h.subsGen.Add(1)
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
	payload, err := json.Marshal(map[string]any{
		"v": 1, "type": "subscribers", "count": count, "gen": gen,
	})
	if err != nil {
		return
	}
	// Fire-and-forget per host: writes carry a multi-second timeout each,
	// so one half-open host must not stall the caller (subscribe /
	// unsubscribe). Ordering across goroutines is handled by `gen`.
	for _, write := range writes {
		go func(w func([]byte) error) {
			_ = w(payload)
		}(write)
	}
}

// SubscribersState returns the live browser subscriber count together with
// a fresh monotonic generation stamp, for transports that re-assert the
// count on their periodic host ping. Re-asserting makes the subscriber
// count self-healing: a `subscribers` frame lost to a write error or a
// superseded connection is corrected within one ping interval instead of
// leaving the host paused until the next browser connect/disconnect.
func (h *Hub) SubscribersState() (count int, gen uint64) {
	h.mu.Lock()
	if cur := h.subs.Load(); cur != nil {
		count = len(*cur)
	}
	h.mu.Unlock()
	return count, h.subsGen.Add(1)
}

// Broadcast fans an event out to browser subscribers (drops for slow
// consumers). Callers typically use RegisterEvent instead.
func (h *Hub) Broadcast(ev Event) {
	h.broadcast(ev)
}

// broadcast fans an event out to every browser subscriber against a
// lock-free copy-on-write snapshot of the subscriber list: registration
// churn (browser connect/disconnect) swaps the slice under h.mu, while
// this hot path — per host event — never touches the global lock.
func (h *Hub) broadcast(ev Event) {
	cur := h.subs.Load()
	if cur == nil {
		return
	}
	for _, s := range *cur {
		select {
		case s.ch <- ev:
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
