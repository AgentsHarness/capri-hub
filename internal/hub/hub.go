// Package hub implements the capri-hub relay core: host pairing (pairing
// code → token), the host registry, event fan-out to browsers, and the
// browser ↔ host request relay.
//
// Transport model (WebSocket + QUIC + HTTP API):
//
//	Browser (capri-fe) ──WS /ws/fe + HTTP /api/*──▶ capri-hub ──WS|QUIC──▶ capri-host × N ──stdio──▶ grok
//
// Hosts connect OUTBOUND to the hub (NAT-friendly) and speak the v2 session
// protocol (capri-wire/PROTOCOL-V2.md): relayed browser requests and absolute
// audience state down, events / relays up, all with one seq space per
// direction. Browsers open /ws/fe for the aggregated live event stream; REST
// APIs stay on HTTP.
package hub

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
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

	"github.com/AgentsHarness/capri-wire"
)

const (
	// PairingCodeTTL is how long a pairing code stays valid.
	PairingCodeTTL = 15 * time.Minute
	// pairingCodeCheckInterval is how often the maintainer looks for an
	// expired pairing code to rotate.
	pairingCodeCheckInterval = 30 * time.Second
	// RelayTimeout caps how long the hub waits for a host's answer once its
	// request frame was delivered. It is the relay layer's ceiling: long
	// running endpoints (history, file reads, agent-style RPCs) legitimately
	// need this order of magnitude. Delivery itself has its own, much
	// shorter deadline (requestAckDeadline in session.go, three heartbeats).
	RelayTimeout = 45 * time.Minute
	// eventBufCap bounds per-host buffered events for gap-pull. It MUST
	// stay ≥ the host's replay ring (capri-host internal/hub replayCap =
	// 1000): after a long disconnect the host replays up to its whole
	// ring, and a smaller hub buffer would compact away the oldest of
	// those events — the FE's gap-pull could then never fill the hole and
	// its ordered-delivery buffer would wait on a predecessor that no
	// longer exists on either side. 1500 keeps a margin above the host
	// constant. The byte cap (evBufByteCap) can still cut below this count
	// for huge events; that is a memory bound, and the FE falls back to
	// host history for the dropped range.
	eventBufCap = 1500
	// evBufHighWater is where bufferEventLocked compacts the buffer back down
	// to eventBufCap. Compacting on every overflow instead would copy the
	// whole buffer per event (see bufferEventLocked); the slack makes it
	// amortized O(1) at the cost of at most 2× the buffer.
	evBufHighWater = 2 * eventBufCap
	// MaxHosts caps the registry so unbounded pair spam cannot grow
	// memory / hub.json without limit.
	MaxHosts = 256
	// Max lengths for pair fields (reject, do not truncate).
	maxHostIDLen   = 128
	maxHostNameLen = 256
)

// evBufByteCap bounds the per-host gap-pull buffer by bytes, not just by
// event count: eventBufCap events of 8MB each would be 12GB. Oldest events
// are dropped first — they are the ones a FE gap-pull can also rebuild from
// host history — and the delivery watermark is not touched. A var so tests
// can shrink it.
var evBufByteCap = 64 << 20

// maxPendingRelayPerHost caps how many relayed requests may be in flight to
// one host. Each may buffer a 28MB response while chunk frames assemble, so
// the pending table is a per-host memory commitment; 16 keeps a busy UI
// (parallel session-history pages, prompts, settings) working while bounding
// the worst case. A var so tests can shrink it.
var maxPendingRelayPerHost = 16

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
	// Entries is the source of truth: one last-write-wins record per
	// preference item, deletions included (as tombstones). See prefs.go.
	Entries PrefsEntries `json:"entries,omitempty"`
	// The four fields below are a PROJECTION of Entries — what FEs render.
	// The hub recomputes them from Entries on every write; a request's own
	// values are ignored.
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

// HostInfo is the public registry entry (GET /api/hosts). busy/booting/
// pendingCount are the host's live snapshot (the hb.status field) —
// transient, never persisted. Port is the host's local HTTP listen port (so
// the browser can try 127.0.0.1:<port>); it is persisted. LastSeen is the
// last attach/detach activity and only orders the host list: online is
// derived from the attachment, never from this timestamp.
type HostInfo struct {
	HostID   string `json:"hostId"`
	HostName string `json:"hostName"`
	Online   bool   `json:"online"`
	Ready    bool   `json:"ready"`
	// Busy: any session has a turn in flight (thinking / working).
	Busy bool `json:"busy,omitempty"`
	// Booting: agent process has not finished booting.
	Booting bool `json:"booting,omitempty"`
	// PendingCount: pending client requests (permits / x.ai questions).
	PendingCount int `json:"pendingCount,omitempty"`
	// Port: host's local HTTP listen port (e.g. 8765). FE probes
	// http://127.0.0.1:<port> for a same-machine shortcut.
	Port     int       `json:"port,omitempty"`
	LastSeen time.Time `json:"lastSeen"`
	Local    bool      `json:"local,omitempty"`
}

// RelayResponse is the host's answer (WS type:"respond").
type RelayResponse struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body,omitempty"`
}

// pendingReq is one relayed request waiting for the host's answer.
type pendingReq struct {
	resp chan RelayResponse
	done chan struct{}

	// Chunked relay response assembly (see Hub.RespondChunk). A body over
	// the host's relay chunk size arrives as several `respond` frames of
	// base64; chunks accumulates the decoded bytes and chunkStatus is the
	// status reported by the first frame. Guarded by Hub.mu, like the map
	// entry itself.
	chunks         []byte
	chunkStatus    int
	chunkStatusSet bool
}

// hostState is one paired host. Lock order is always h.mu → hs.mu; nothing
// takes them the other way.
type hostState struct {
	info  HostInfo
	token string

	// Attachment, guarded by h.mu. online is derived: a host is online while
	// a session is attached. proto is the (hostId, epoch) protocol state; it
	// outlives the transport so a same-epoch reconnect resumes at the same
	// watermarks, and a new epoch replaces it.
	session *session
	proto   *sessionProto
	// epoch mirrors proto.epoch for the event ingest fast path, which checks
	// it under hs.mu so a superseded epoch's frames cannot land in the new
	// epoch's buffers. It also validates queued fan-out items, which are
	// enqueued after that check has been released (fanoutItem.epoch).
	epoch atomic.Uint64
	// upAcked mirrors the proto's up watermark for LastSeq / SeqByHost, which
	// must answer while the host is offline too.
	upAcked atomic.Uint64

	// audienceGen stamps every absolute audience snapshot for this host and
	// is never reset by an epoch change; audienceKey dedupes an unchanged
	// snapshot. Guarded by h.mu.
	audienceGen uint64
	audienceKey string

	// mu guards evBuf only (the per-host data plane). The global h.mu
	// protects the registry; event ingestion does not serialize every host
	// behind it.
	mu sync.Mutex

	// evBuf is a bounded ring of recent events (with seq injected) so browsers
	// can pull gaps: GET /api/events?host=X&after=SEQ.
	evBuf []Event
	// evBufBytes is the byte weight of evBuf (raw wire bytes on the raw
	// path). Count alone is not a memory bound — one giant tool result can
	// be 8MB — so the gap-pull ring is also capped by evBufByteCap.
	evBufBytes int
	// evBufFuseLogged keeps the over-cap trim from logging on every event.
	evBufFuseLogged bool
	// evBufEpoch is bumped on detach (schedule clear) and attach (cancel
	// clear). A delayed clear only runs if the epoch still matches.
	evBufEpoch uint64

	// fanout decouples uplink ingestion from browser fan-out. The session
	// loop only appends here (bounded, never blocks); a per-host goroutine
	// drains it into the subscriber broadcast.
	fanout     chan fanoutItem
	fanoutOnce sync.Once
	// fanoutDropped counts events dropped because the fan-out queue was
	// full. The event is already in evBuf, so a FE's (hostId,seq) gap-pull
	// recovers it — this is not a loss, just deferred delivery. Read by the
	// diagnostics snapshot (Hub.Stats); never reset.
	fanoutDropped atomic.Uint64
}

// fanoutDropCount is the read side of fanoutDropped for diagnostics.
func (hs *hostState) fanoutDropCount() uint64 {
	return hs.fanoutDropped.Load()
}

// lastSeq is the highest applied up seq, i.e. the delivery watermark.
func (hs *hostState) lastSeq() uint64 { return hs.upAcked.Load() }

// eventBufferLen is the current gap-pull buffer depth (safe for the
// diagnostics path; the registry itself stays private).
func (hs *hostState) eventBufferLen() int {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	return len(hs.evBuf)
}

// eventBufferBytes is the current gap-pull buffer byte weight.
func (hs *hostState) eventBufferBytes() int {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	return hs.evBufBytes
}

// fanoutDepth is the current fan-out backlog depth (diagnostics only).
func (hs *hostState) fanoutDepth() int {
	hs.mu.Lock()
	f := hs.fanout
	hs.mu.Unlock()
	if f == nil {
		return 0
	}
	return len(f)
}

// hostFanoutCap bounds the per-host pre-fan-out backlog. Overflow is
// recoverable (see fanoutDropped): subscribers see a seq gap and pull the
// event back out of evBuf.
const hostFanoutCap = 2048

// fanoutReady reports whether this host already has a fan-out queue, i.e.
// whether an event can be sitting in front of the one about to be enqueued.
func (hs *hostState) fanoutReady() bool {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	return hs.fanout != nil
}

// fanoutItem is one queued event plus the host it was buffered for. The host
// is explicit so a control frame that carries no hostId of its own (the
// epoch-reset `subscribed`) is still delivered to exactly that host's
// subscribers, without being dressed up as a host event.
//
// epoch is the sequence space the event was gated on when it was buffered.
// Ingest gates an event on hs.epoch under hs.mu, then enqueues it outside the
// lock; an attach that installs a new epoch in between leaves that item
// tagged with the retired epoch. The drain side drops it, so a stale
// high-seq frame can never be delivered behind the reset that moved the FE's
// watermark (see fanoutItemCurrent).
type fanoutItem struct {
	hostID string
	ev     Event
	epoch  uint64
}

// fanoutItemCurrent reports whether item still belongs to the host's live
// sequence space. The epoch-reset item is tagged with the new epoch, so it is
// delivered; anything staged for a retired epoch is not.
func (hs *hostState) fanoutItemCurrent(item fanoutItem) bool {
	return item.epoch == hs.epoch.Load()
}

// enqueueFanout hands one already-gated, already-buffered event to this
// host's fan-out goroutine. Never blocks: a slow browser must not stall the
// host read loop (see hostState.fanout). epoch is the value the caller gated
// the event on.
func (hs *hostState) enqueueFanout(h *Hub, hostID string, ev Event, epoch uint64) {
	ch := hs.fanoutQueue(h)
	select {
	case ch <- fanoutItem{hostID: hostID, ev: ev, epoch: epoch}:
	default:
		hs.fanoutDropped.Add(1)
	}
}

// fanoutQueue returns the host's fan-out channel, starting its goroutine on
// first use. The channel is published under hs.mu so the diagnostics readers
// (fanoutDepth, fanoutReady) never observe a half-installed queue.
func (hs *hostState) fanoutQueue(h *Hub) chan fanoutItem {
	hs.fanoutOnce.Do(func() {
		ch := make(chan fanoutItem, hostFanoutCap)
		hs.mu.Lock()
		hs.fanout = ch
		hs.mu.Unlock()
		go func() {
			for item := range ch {
				if !hs.fanoutItemCurrent(item) {
					continue
				}
				h.broadcastHost(item.hostID, item.ev)
			}
		}()
	})
	hs.mu.Lock()
	defer hs.mu.Unlock()
	return hs.fanout
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

	nextReq atomic.Int64
	// nextSubID stamps each browser subscriber with a stable id so the
	// admin's subscriber panel can point at one row (hello carries it).
	nextSubID atomic.Int64
	// lastViewWidenLog rate-limits the "widened to all" warning (guarded
	// by h.mu).
	lastViewWidenLog time.Time
	// lastFESubs is the browser subscriber total last pushed to FE pages
	// (see notifySubscribersCount); subsSeen marks whether any push
	// happened yet. The top bar renders this number, so a reconnect storm
	// that leaves it unchanged must not re-broadcast.
	lastFESubs int
	subsSeen   bool

	dataFile string
	// prefsFile holds the browser prefs document (prefs.json, sibling of
	// hub.json). Written on SetPrefs only.
	prefsFile string
	prefs     BrowserPrefs
	// guestsFile holds the guest-token table (guests.json, sibling of
	// hub.json, 0600). guests is the in-memory copy; every write persists
	// it atomically. guestPersistedAt throttles lastUsedAt rewrites.
	guestsFile       string
	guests           []GuestToken
	guestPersistedAt time.Time
	// guestPersistMu serializes guests.json snapshots so concurrent writers
	// cannot rename an older table over a newer one (lock order:
	// guestPersistMu → h.mu, never the reverse).
	guestPersistMu sync.Mutex
	// persistMu is the hub.json counterpart of guestPersistMu: it
	// serializes "snapshot + write" so a slow writer cannot rename an
	// older registry snapshot over a newer one (a lost pairing or port
	// update). Lock order: persistMu → h.mu, never the reverse.
	persistMu sync.Mutex
	// feStats holds process-wide FE backpressure counters: events dropped
	// for slow subscribers and resync frames actually handed to a
	// subscriber's channel. Per-subscriber and per-host counters stay
	// where the drop happens; these exist so GET /api/stats can show
	// whether the "gap-pull will repair it" claim is holding.
	feStats feDropStats
	// lateRelayChunks counts chunked `respond` frames whose reqId has no
	// pending entry — normally a chunk that arrived after the browser gave
	// up. Harmless by design, but a rising count means large answers are
	// outliving their request.
	lateRelayChunks atomic.Uint64
	// startedAt stamps process start for the uptime in GET /api/stats.
	startedAt time.Time
	// hubBoot identifies this hub process. The relay request-id counter
	// restarts at 0 on every process start, so a reqId only names one request
	// inside one hubBoot; hello_ack carries it and the host scopes its relay
	// memo by it. Minted once in NewWithDir.
	hubBoot uint64
	// guestChildren maps a subagent child session (and its subagent id) to the
	// parent session that spawned it, per host. Learned from the
	// subagent_spawned typed event, so a guest token may follow the transcript
	// of a child whose PARENT is whitelisted. Readers (fan-out filter, HTTP
	// relay) load the snapshot lock-free; writes replace it under h.mu.
	// In-memory only: after a hub restart the map refills as subagents spawn.
	guestChildren atomic.Pointer[map[string]string]
	// guestChildKeys is the FIFO used to bound guestChildren (guarded by h.mu).
	guestChildKeys []string
	// prefsVersion is the CAS version of prefs: bumped on every accepted
	// write, persisted in prefs.json, and echoed in GET/broadcast so FEs
	// can make conditional (baseVersion) writes. 0 = never written.
	prefsVersion uint64
}

// codeAlphabet avoids look-alike characters (no I/L/O/0/1).
const codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// New returns a Hub that persists pairing state under HUB_DATA_DIR when
// set, else ~/.capri-hub.
func New() *Hub {
	return NewWithDir(defaultDataDir())
}

// NewWithDir returns a Hub persisting to dir/hub.json; pass "" to disable
// persistence (used by tests).
func NewWithDir(dir string) *Hub {
	emptySubs := []*feSubscriber{}
	boot, err := wire.NewEpoch()
	if err != nil {
		// A non-zero timestamp still satisfies the protocol's "per-process,
		// non-zero" requirement; a hub with a zero boot id could not write a
		// valid hello_ack at all.
		boot = uint64(time.Now().UnixNano()) | 1
		log.Printf("[capri-hub] 无法生成随机 hubBoot（%v），使用时间戳 %d", err, boot)
	}
	h := &Hub{
		tokens:    make(map[string]string),
		hosts:     make(map[string]*hostState),
		pending:   make(map[string]map[string]*pendingReq),
		prefs:     BrowserPrefs{PinnedWorkspaces: []string{}, PinnedSessions: []string{}, Todos: map[string]string{}},
		startedAt: time.Now(),
		hubBoot:   boot,
	}
	h.subs.Store(&emptySubs)
	if dir != "" {
		h.dataFile = filepath.Join(dir, "hub.json")
		h.load()
		h.prefsFile = filepath.Join(dir, "prefs.json")
		h.loadPrefs()
		h.guestsFile = filepath.Join(dir, "guests.json")
		h.loadGuests()
	}
	h.rotateCode()
	return h
}

// defaultDataDir resolves where hub.json / prefs.json live.
//
// HUB_DATA_DIR wins when set: a container has no meaningful home
// directory, and relying on $HOME to redirect state is fragile (it also
// moves anything else that reads the home dir). An explicit override
// lets the deployment mount one volume at one known path.
func defaultDataDir() string {
	if dir := strings.TrimSpace(os.Getenv("HUB_DATA_DIR")); dir != "" {
		return dir
	}
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
	Port     int    `json:"port,omitempty"`
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
			info: HostInfo{HostID: id, HostName: ph.HostName, Ready: ph.Ready, Port: ph.Port},
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
		pf.Hosts[hid] = persistHost{HostID: hid, HostName: hs.info.HostName, Ready: hs.info.Ready, Port: hs.info.Port}
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
	now := time.Now()

	h.mu.Lock()
	next := PrefsEntries{}
	mergePrefsEntries(next, h.prefs.Entries)
	mergePrefsEntries(next, cp.Entries)
	prunePrefsTombstones(next, now)
	if samePrefsEntries(h.prefs.Entries, next) {
		// Nothing moved: keep the version, don't write, don't broadcast.
		v := h.prefsVersion
		h.mu.Unlock()
		return v, nil
	}
	doc := cp
	doc.Entries = next
	applyPrefsProjection(&doc)
	persist := h.prefsFile != ""
	var payload []byte
	if persist {
		b, err := json.Marshal(prefsFileDoc{BrowserPrefs: doc, Version: h.prefsVersion + 1})
		if err != nil {
			h.mu.Unlock()
			return 0, fmt.Errorf("marshal prefs: %w", err)
		}
		payload = b
	}
	h.prefsVersion++
	newVersion := h.prefsVersion
	h.prefs = doc
	h.broadcast(prefsChanged(clonePrefs(doc), newVersion))
	h.mu.Unlock()

	if persist {
		if err := writeFileAtomic(h.prefsFile, payload); err != nil {
			log.Printf("[capri-hub] prefs persist: %v", err)
		}
	}
	return newVersion, nil
}

// prefsChanged builds the prefs broadcast event (hub-level, no hostId —
// browsers apply it regardless of the selected host). Carries the doc's
// new version so clean clients track their CAS base without re-pulling.
func prefsChanged(prefs BrowserPrefs, version uint64) Event {
	return Event{"type": "prefs_changed", "params": map[string]any{"prefs": prefs, "version": version}}
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
//
// Optional port (variadic): when the first extra arg is in 1..65535 it is
// stored as HostInfo.Port (local HTTP listen port for FE localhost probe).
// Omitted or out of range leaves any existing Port untouched on re-pair.
func (h *Hub) Pair(code, hostID, hostName string, port ...int) (string, error) {
	listenPort := 0
	if len(port) > 0 {
		listenPort = port[0]
	}
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
		if listenPort > 0 && listenPort <= 65535 {
			hs.info.Port = listenPort
		}
	} else {
		if len(h.hosts) >= MaxHosts {
			h.mu.Unlock()
			return "", ErrHostLimit
		}
		info := HostInfo{HostID: hostID, HostName: hostName, LastSeen: time.Now()}
		if listenPort > 0 && listenPort <= 65535 {
			info.Port = listenPort
		}
		h.hosts[hostID] = &hostState{info: info}
	}
	token := randomToken()
	h.tokens[token] = hostID
	h.hosts[hostID].token = token
	h.mu.Unlock()

	h.persistNow()
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
	if hs.session != nil {
		// The transport is left to unwind on its own; its detach finds the
		// host gone and does nothing.
		hs.session.requestStop(wire.CloseAuth)
		hs.session = nil
	}
	delete(h.hosts, hostID)
	hs.mu.Lock()
	hs.evBuf = nil
	hs.evBufBytes = 0
	hs.mu.Unlock()
	h.broadcast(hostsChanged())
	h.mu.Unlock()

	h.persistNow()
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
	h.broadcast(hostsChanged())
	h.mu.Unlock()

	h.persistNow()
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

// ── host sessions ─────────────────────────────────────────────────────

// attach installs a hello's session in the registry and returns the hello_ack
// it must answer with. old is the session this one supersedes (same host, any
// epoch); its loop is stopped by the caller.
//
// A same-epoch reconnect resumes the existing protocol state, so the peer's
// unacked log is replayed against the same watermarks and resume.up is
// ignored: the hub's ackUp is authoritative there. resume.down is adopted as
// the down watermark, so the hub does not replay frames the host already
// applied. A new epoch starts from the host's declared baseline (resume.up —
// the retired high-water mark of its event bus), resets the gap-pull buffer,
// starts the down sender at zero, tells /ws/fe subscribers the same baseline
// via subscribed{seq:baseline} before any new-epoch event, and leaves the
// per-host audience generation increasing.
func (h *Hub) attach(hostID string, epoch, resumeUp, resumeDown uint64, deflate bool) (s *session, old *session, ack wire.HelloAck, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	hs := h.hosts[hostID]
	if hs == nil {
		return nil, nil, wire.HelloAck{}, ErrHostUnknown
	}
	old = hs.session
	if hs.proto == nil || hs.proto.epoch != epoch {
		// Requests dispatched in the old sequence space can never be
		// answered there; the new epoch's sender starts from zero, so fail
		// them instead of leaving the browser waiting for RelayTimeout.
		if hs.proto != nil {
			h.failPendingLocked(hostID)
		}
		hs.proto = newSessionProto(epoch, resumeUp, SessionLimits.ResumeWindow)
		hs.epoch.Store(epoch)
		hs.upAcked.Store(resumeUp)
		hs.mu.Lock()
		hs.evBuf = nil
		hs.evBufBytes = 0
		hs.mu.Unlock()
		// The FE watermark is per host, so it must be told about the restart
		// before it sees an event numbered in the new space. The baseline is
		// the new coordinate's origin, not necessarily 0. The reset rides the
		// fan-out queue: it must not jump ahead of queued work, and items of
		// the retired epoch that are still queued are dropped when the drain
		// reaches them (see fanoutItemCurrent).
		h.announceEpochReset(hs, resumeUp)
	} else if resumeDown > 0 {
		// The host already applied everything up to resume.down; advancing the
		// down sender's ack drops those entries instead of replaying them, and
		// releases the requests they proved delivered. A stale or smaller
		// value never moves the watermark backwards.
		hs.proto.ackDown(resumeDown)
	}
	s = &session{
		h:      h,
		hostID: hostID,
		epoch:  epoch,
		proto:  hs.proto,
		wake:   make(chan struct{}, 1),
		stop:   make(chan struct{}),
	}
	hs.session = s
	hs.info.Online = true
	hs.info.LastSeen = time.Now()
	// A pending grace-period clear of the gap-pull buffer must not run while
	// this session is attached.
	hs.evBufEpoch++

	aud, _ := h.audienceLocked(hostID)
	liveness := SessionLiveness
	limits := SessionLimits
	caps := wire.Caps{Deflate: deflate}
	ack = wire.HelloAck{
		Epoch:    epoch,
		HubBoot:  h.hubBoot,
		AckUp:    hs.proto.upAcked(),
		AckDown:  hs.proto.downAcked(),
		Audience: &aud,
		Liveness: &liveness,
		Limits:   &limits,
		Caps:     &caps,
	}
	h.broadcast(hostsChanged())
	return s, old, ack, nil
}

// detach clears the attachment. A superseded session (a newer one already
// holds the host) must not touch the registry or the pending table; the
// replacement owns both from the moment it attached.
func (h *Hub) detach(s *session) {
	h.mu.Lock()
	hs := h.hosts[s.hostID]
	if hs == nil || hs.session != s {
		h.mu.Unlock()
		return
	}
	hs.session = nil
	hs.info.Online = false
	hs.info.LastSeen = time.Now()
	hs.evBufEpoch++
	epoch := hs.evBufEpoch
	h.failPendingLocked(s.hostID)
	h.broadcast(hostsChanged())
	h.mu.Unlock()

	// Keep the gap-pull buffer for EventBufGrace: a browser can still fill a
	// hole left by a short disconnect.
	h.scheduleEvBufClear(s.hostID, epoch)
}

// scheduleEvBufClear clears hostID's replay buffer after EventBufGrace unless
// the host has reattached (or the epoch moved on) in the meantime.
func (h *Hub) scheduleEvBufClear(hostID string, epoch uint64) {
	clear := func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		hs := h.hosts[hostID]
		if hs == nil || hs.session != nil || hs.evBufEpoch != epoch {
			return
		}
		hs.mu.Lock()
		hs.evBuf = nil
		hs.evBufBytes = 0
		hs.mu.Unlock()
	}
	grace := EventBufGrace
	if grace <= 0 {
		clear()
		return
	}
	time.AfterFunc(grace, clear)
}

// noteUpAck mirrors the receiver's watermark for readers that outlive the
// session (LastSeq, SeqByHost, the FE hello).
func (h *Hub) noteUpAck(s *session, ack uint64) {
	h.mu.Lock()
	if hs := h.hosts[s.hostID]; hs != nil && hs.session == s {
		if ack > hs.upAcked.Load() {
			hs.upAcked.Store(ack)
		}
	}
	h.mu.Unlock()
}

// heartbeatStatus snapshots the registry view a heartbeat carries. The shared
// envelope gives hb a status field in both directions; on the way down it is
// informational — the host's own last report, never a command.
func (h *Hub) heartbeatStatus(hostID string) wire.HeartbeatStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	hs := h.hosts[hostID]
	if hs == nil {
		return wire.HeartbeatStatus{}
	}
	return wire.HeartbeatStatus{
		Ready:        hs.info.Ready,
		Busy:         hs.info.Busy,
		Booting:      hs.info.Booting,
		PendingCount: hs.info.PendingCount,
		Port:         hs.info.Port,
	}
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

// failRequest fails one pending relayed request with an HTTP status. It is the
// session's per-request deadline path (a dispatch the host never acked), so
// other requests and the session itself are untouched.
func (h *Hub) failRequest(hostID, reqID string, status int, message string) {
	h.mu.Lock()
	pr := h.takePendingLocked(hostID, reqID)
	h.mu.Unlock()
	if pr == nil {
		return
	}
	pr.chunks = nil
	body, _ := json.Marshal(map[string]any{"ok": false, "error": message})
	pr.resp <- RelayResponse{Status: status, Body: body}
}

// evSeq normalizes an event's seq across Go-native (uint64) and
// JSON-decoded (float64) values.
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

// HostStatusPatch carries the registry fields an hb status snapshot may
// update. Fields absent from the snapshot arrive as nil and leave the current
// value untouched; hosts_changed fires when any field flips.
type HostStatusPatch struct {
	Ready        *bool
	Busy         *bool
	Booting      *bool
	PendingCount *int
	Port         *int
}

// UpdateHostStatus applies the status snapshot carried by a host heartbeat.
// On any visible-field flip it updates the registry entry and broadcasts
// hosts_changed. Returns false for unknown hosts. Does not touch the
// transcript buffer. Port flips are also persisted (the FE may need the port
// after a hub restart before the next heartbeat).
func (h *Hub) UpdateHostStatus(hostID string, p HostStatusPatch) bool {
	h.mu.Lock()
	hs := h.hosts[hostID]
	if hs == nil {
		h.mu.Unlock()
		return false
	}
	changed := false
	portChanged := false
	if p.Ready != nil && *p.Ready != hs.info.Ready {
		hs.info.Ready = *p.Ready
		changed = true
	}
	if p.Busy != nil && *p.Busy != hs.info.Busy {
		hs.info.Busy = *p.Busy
		changed = true
	}
	if p.Booting != nil && *p.Booting != hs.info.Booting {
		hs.info.Booting = *p.Booting
		changed = true
	}
	if p.PendingCount != nil && *p.PendingCount != hs.info.PendingCount {
		hs.info.PendingCount = *p.PendingCount
		changed = true
	}
	if p.Port != nil {
		port := *p.Port
		if port > 0 && port <= 65535 && port != hs.info.Port {
			hs.info.Port = port
			changed = true
			portChanged = true
		}
	}
	persist := portChanged && h.dataFile != ""
	if changed {
		h.broadcast(hostsChanged())
	}
	h.mu.Unlock()
	if persist {
		h.persistNow()
	}
	return true
}

// eventBytes is one buffered event's byte weight: the canonical wire bytes
// on the raw path (the only one production uses), else the marshaled map.
func eventBytes(ev Event) int {
	if raw, ok := ev[rawWireKey].(json.RawMessage); ok {
		return len(raw)
	}
	if b, err := json.Marshal(ev); err == nil {
		return len(b)
	}
	return 0
}

// eventsBytes is the total byte weight of a buffer slice.
func eventsBytes(evs []Event) int {
	n := 0
	for _, ev := range evs {
		n += eventBytes(ev)
	}
	return n
}

// bufferEventLocked appends ev to the gap-pull ring, keeping the ring in
// ascending seq order, and compacts at the high-water mark. The receiver
// delivers events in contiguous runs, so appends are the common path; the
// splice keeps the ring ordered for EventsAfter's binary search even if a
// caller ever hands over a non-monotonic batch. The copy (not a reslice)
// keeps dropped Event maps from staying reachable via the old backing array.
//
// The ring is bounded by evBufByteCap as well as by eventBufCap: one giant
// tool result must not pin hundreds of MB per host. Over the byte cap the
// OLDEST events are dropped. That touches only the gap-pull copy — the
// delivery watermark keeps advancing and a FE that missed the dropped range
// rebuilds it from host history. The caller must hold hs.mu.
func (hs *hostState) bufferEventLocked(hostID string, ev Event) {
	hs.evBufBytes += eventBytes(ev)
	if n := len(hs.evBuf); n == 0 || evSeq(hs.evBuf[n-1]) < evSeq(ev) {
		hs.evBuf = append(hs.evBuf, ev)
	} else {
		at := sort.Search(n, func(i int) bool { return evSeq(hs.evBuf[i]) > evSeq(ev) })
		hs.evBuf = append(hs.evBuf, Event{})
		copy(hs.evBuf[at+1:], hs.evBuf[at:])
		hs.evBuf[at] = ev
	}
	if len(hs.evBuf) > evBufHighWater {
		trimmed := make([]Event, eventBufCap, evBufHighWater)
		copy(trimmed, hs.evBuf[len(hs.evBuf)-eventBufCap:])
		hs.evBuf = trimmed
		hs.evBufBytes = eventsBytes(trimmed)
	}
	if hs.evBufBytes > evBufByteCap {
		cut := 0
		for cut < len(hs.evBuf) && hs.evBufBytes > evBufByteCap {
			hs.evBufBytes -= eventBytes(hs.evBuf[cut])
			cut++
		}
		kept := make([]Event, len(hs.evBuf)-cut)
		copy(kept, hs.evBuf[cut:])
		hs.evBuf = kept
		if !hs.evBufFuseLogged {
			hs.evBufFuseLogged = true
			log.Printf("[capri-hub] host %s: gap-pull buffer over %d bytes, dropping its oldest events (a FE rebuilds those from host history)",
				hostID, evBufByteCap)
		}
	}
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
// hub-level events (hosts_changed, prefs_changed, resync).
func MarshalEvent(ev Event) ([]byte, error) {
	if raw, ok := ev[rawWireKey].(json.RawMessage); ok {
		return raw, nil
	}
	return json.Marshal(ev)
}

// rawEventMeta is the shallow header the hub needs from every raw event.
type rawEventMeta struct {
	Seq  uint64 `json:"seq"`
	Type string `json:"type"`
	// SessionID is lifted for the guest whitelist filter: raw events keep
	// their original bytes (see rawWireKey), so the map itself has no
	// sessionId member to filter on.
	SessionID string `json:"sessionId"`
	// Only tool_call_update has a payload member here; every other event
	// type leaves it zero. Read for the drop-tier decision (criticalEvent) —
	// the alternative is decoding the body per subscriber.
	ToolCallUpdate struct {
		Status string `json:"status"`
	} `json:"toolCallUpdate"`
}

// spawnMeta is decoded only for subagent_spawned frames (see
// noteSpawnFromRaw): carrying `update` in rawEventMeta would make every raw
// event pay a full decode of its payload, including tool outputs.
type spawnMeta struct {
	SessionID string `json:"sessionId"`
	Update    struct {
		ChildSessionID string `json:"child_session_id"`
		SubagentID     string `json:"subagent_id"`
	} `json:"update"`
}

// noteSpawnFromRaw records the child/parent relation of one raw
// subagent_spawned frame (see noteGuestChild).
func (h *Hub) noteSpawnFromRaw(hostID string, raw json.RawMessage) {
	var m spawnMeta
	if json.Unmarshal(raw, &m) != nil {
		return
	}
	h.noteGuestChild(hostID, m.SessionID, m.Update.ChildSessionID, m.Update.SubagentID)
}

// rawSessionKey carries the shallow-parsed sessionId of a raw event through
// the fan-out path without touching the wire bytes (MarshalEvent returns the
// original bytes verbatim, so this key never reaches a browser).
const rawSessionKey = "\x00sessionId"

// eventSessionID reads an event's top-level sessionId (map path or the
// lifted raw-path copy).
func eventSessionID(ev Event) string {
	if s, ok := ev["sessionId"].(string); ok && s != "" {
		return s
	}
	s, _ := ev[rawSessionKey].(string)
	return s
}

// ── 子代理子会话台账 ──────────────────────────────────────────────────
//
// 访客白名单按「host + session」授权。子代理是独立会话，事件与
// updates.jsonl 都挂在子会话 id 下，白名单里通常只有父会话。这里记录
// subagent_spawned 给出的父子关系，让白名单父会话的访客能读到该子代理的
// 时间线（WS 事件 + /api/session-updates），只跟一层：子代理再派出的子代理
// 不自动继承，授权范围保持与管理员分享的那条会话一致。

// guestChildCap bounds the relation table (FIFO). Spawns are rare; the cap
// exists so a long-lived hub cannot grow without limit.
const guestChildCap = 4096

// noteGuestChild records that childSID (and its subagent id, when it differs)
// belongs to parentSID on hostID.
func (h *Hub) noteGuestChild(hostID, parentSID, childSID, subagentID string) {
	if hostID == "" || parentSID == "" || childSID == "" || parentSID == childSID {
		return
	}
	h.mu.Lock()
	next := make(map[string]string, guestChildCap)
	if cur := h.guestChildren.Load(); cur != nil {
		for k, v := range *cur {
			next[k] = v
		}
	}
	ids := []string{childSID}
	if subagentID != "" && subagentID != childSID {
		ids = append(ids, subagentID)
	}
	for _, id := range ids {
		key := GuestSessionKey(hostID, id)
		if _, ok := next[key]; ok {
			continue
		}
		next[key] = parentSID
		h.guestChildKeys = append(h.guestChildKeys, key)
	}
	if over := len(h.guestChildKeys) - guestChildCap; over > 0 {
		for _, key := range h.guestChildKeys[:over] {
			delete(next, key)
		}
		h.guestChildKeys = append([]string(nil), h.guestChildKeys[over:]...)
	}
	h.guestChildren.Store(&next)
	h.mu.Unlock()
}

// guestParentOf returns the parent session recorded for (host, session), or "".
// Lock-free: readers get the whole map snapshot.
func (h *Hub) guestParentOf(hostID, sessionID string) string {
	cur := h.guestChildren.Load()
	if cur == nil || sessionID == "" {
		return ""
	}
	return (*cur)[GuestSessionKey(hostID, sessionID)]
}

// GuestChildAllowed reports whether sessionID on hostID is a subagent child of
// a session the token was granted. The whitelist itself stays read-only: this
// only widens the READ scope to the child transcripts of shared sessions.
func (h *Hub) GuestChildAllowed(g GuestToken, hostID, sessionID string) bool {
	parent := h.guestParentOf(hostID, sessionID)
	if parent == "" {
		return false
	}
	return GuestAllowsSession(g, hostID, parent)
}

// GuestParentOf is GuestChildAllowed's building block: the parent session
// recorded for a child, "" when unknown.
func (h *Hub) GuestParentOf(hostID, sessionID string) string {
	return h.guestParentOf(hostID, sessionID)
}

// NoteHistoryChildren learns parent/child links from a session history page
// relayed to a guest. Live spawns fill the same table from
// subagent_spawned events; this covers subagents that spawned before the
// guest's page opened (or before a hub restart), which is exactly when the
// timeline is fetched from disk. fallbackParent is the session the page was
// requested for (envelopes of older hosts may omit params.sessionId).
//
// Cheap by construction: no "subagent_spawned" substring ⇒ nothing is
// unmarshalled.
func (h *Hub) NoteHistoryChildren(hostID, fallbackParent string, body []byte) {
	if hostID == "" || !bytes.Contains(body, []byte(`subagent_spawned`)) {
		return
	}
	var page struct {
		Updates []struct {
			Params struct {
				SessionID string `json:"sessionId"`
				Update    struct {
					SessionUpdate  string `json:"sessionUpdate"`
					ChildSessionID string `json:"child_session_id"`
					SubagentID     string `json:"subagent_id"`
				} `json:"update"`
			} `json:"params"`
		} `json:"updates"`
	}
	if json.Unmarshal(body, &page) != nil {
		return
	}
	for _, u := range page.Updates {
		if u.Params.Update.SessionUpdate != "subagent_spawned" {
			continue
		}
		parent := u.Params.SessionID
		if parent == "" {
			parent = fallbackParent
		}
		h.noteGuestChild(hostID, parent, u.Params.Update.ChildSessionID, u.Params.Update.SubagentID)
	}
}

// NoteRunningSubagents learns parent/child links from a subagent registry
// response relayed to a guest (`x.ai/subagent/list_running` →
// {ok, result:{subagents:[{subagentId, childSessionId, parentSessionId}]}}).
// Spawn events and history pages feed the same table; the registry is the
// source that still knows a child whose spawn envelope is missing from the
// history page the guest happened to load.
func (h *Hub) NoteRunningSubagents(hostID, fallbackParent string, body []byte) {
	if hostID == "" || !bytes.Contains(body, []byte(`subagents`)) {
		return
	}
	var doc struct {
		Result struct {
			Subagents []struct {
				SubagentID      string `json:"subagentId"`
				ChildSessionID  string `json:"childSessionId"`
				ParentSessionID string `json:"parentSessionId"`
			} `json:"subagents"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return
	}
	for _, row := range doc.Result.Subagents {
		parent := row.ParentSessionID
		if parent == "" {
			parent = fallbackParent
		}
		h.noteGuestChild(hostID, parent, row.ChildSessionID, row.SubagentID)
	}
}

// spliceRawEvent builds the FE-bound wire bytes for one raw event by
// appending the hub's tags before the closing brace of the original
// object. Appending (rather than prepending) means duplicate keys resolve
// in the hub's favor — hostId / hostName always win (encoding/json keeps
// the LAST occurrence). Returns nil when raw is not a JSON object (caller
// skips).
func spliceRawEvent(raw, idJSON, nameJSON []byte) json.RawMessage {
	r := bytes.TrimRight(raw, " \t\r\n")
	if len(r) < 2 || r[0] != '{' || r[len(r)-1] != '}' {
		return nil
	}
	out := make([]byte, 0, len(r)+len(idJSON)+len(nameJSON)+48)
	out = append(out, r[:len(r)-1]...)
	if len(out) > 1 { // non-empty object: separate from existing members
		out = append(out, ',')
	}
	out = append(out, `"hostId":`...)
	out = append(out, idJSON...)
	out = append(out, `,"hostName":`...)
	out = append(out, nameJSON...)
	out = append(out, '}')
	return json.RawMessage(out)
}

// ingestRawEvents applies one contiguous run of host events in their original
// wire form: each body stays json.RawMessage, only the fields the hub needs are
// shallow-parsed, and the FE-bound bytes are spliced once instead of
// decode-map + re-encode per subscriber.
//
// The receiver has already validated that the run is gapless and in order
// (wire.ValidateEvents), so seqs are used verbatim and nothing here may skip
// one. Returns false when s is no longer the host's session: its epoch was
// superseded while the frame was parked, and the events must not be applied to
// the new epoch's buffer.
func (h *Hub) ingestRawEvents(s *session, raws []json.RawMessage) bool {
	h.mu.Lock()
	hs := h.hosts[s.hostID]
	if hs == nil || hs.session != s {
		h.mu.Unlock()
		return false
	}
	hostName := hs.info.HostName
	h.mu.Unlock()

	idJSON, _ := json.Marshal(s.hostID)
	nameJSON, _ := json.Marshal(hostName)
	for _, raw := range raws {
		r := bytes.TrimRight(raw, " \t\r\n")
		if len(r) < 2 || r[0] != '{' || r[len(r)-1] != '}' {
			Verbosef("[capri-hub] host %s non-object event skipped", s.hostID)
			continue
		}
		var meta rawEventMeta
		if err := json.Unmarshal(r, &meta); err != nil {
			continue
		}
		wireBytes := spliceRawEvent(r, idJSON, nameJSON)
		if wireBytes == nil {
			Verbosef("[capri-hub] host %s non-object event skipped", s.hostID)
			continue
		}
		ev := Event{
			rawWireKey: wireBytes,
			"type":     meta.Type,
			"seq":      meta.Seq,
			"hostId":   s.hostID,
			"hostName": hostName,
		}
		if meta.SessionID != "" {
			ev[rawSessionKey] = meta.SessionID
		}
		switch meta.ToolCallUpdate.Status {
		case "completed", "failed":
			ev[terminalToolUpdateKey] = true
		}
		hs.mu.Lock()
		if hs.epoch.Load() != s.epoch {
			hs.mu.Unlock()
			return false
		}
		hs.bufferEventLocked(s.hostID, ev)
		hs.mu.Unlock()
		// 子代理派发：记下子会话归属，访客才能顺着白名单父会话读到这条
		// 时间线（见 noteGuestChild）。同一事件既带顶层 sessionId（父）也带
		// update 里的 child_session_id（子）。放在入环/扇出之前：该事件本身
		// 是父会话的（白名单直接放行），但紧跟着到达的子会话事件要能命中。
		if meta.Type == "subagent_spawned" {
			h.noteSpawnFromRaw(s.hostID, r)
		}
		// The epoch gate above is released before the enqueue, so an attach
		// may install a new epoch right here. Tagging the item with the epoch
		// it was gated on lets the drain drop it instead of delivering a
		// retired-epoch seq behind the new epoch's reset. Dropping it is safe:
		// the FE rebuilds from host history.
		hs.enqueueFanout(h, s.hostID, ev, s.epoch)
	}
	return true
}

// LastSeq returns the delivery watermark for hostID: the highest N for which
// 1..N all arrived (0 when unknown / nothing seen yet). It is the only number
// a wire field may present as an ack; a higher one would erase the replay
// copies of events the hub never received.
func (h *Hub) LastSeq(hostID string) uint64 {
	h.mu.Lock()
	hs := h.hosts[hostID]
	h.mu.Unlock()
	if hs == nil {
		return 0
	}
	return hs.lastSeq()
}

// SeqByHost returns the per-host delivery watermark (see LastSeq) for the FE
// hello frame, so a browser works on the same gapless coordinate as the hub.
func (h *Hub) SeqByHost() map[string]uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]uint64, len(h.hosts))
	for id, hs := range h.hosts {
		out[id] = hs.upAcked.Load()
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
	// evBuf is append-only in strictly increasing seq order (appendEvent
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
	sess := hs.session
	if sess == nil {
		h.mu.Unlock()
		return RelayResponse{}, &RelayError{Status: 503, Message: fmt.Sprintf("host %s 当前离线", hostID)}
	}
	// Each in-flight request can buffer up to a full 28MB answer chunked
	// across frames, so an unbounded pending table is an unbounded memory
	// commitment per host. Refuse new work with 429 instead of queueing it:
	// the browser sees a retryable error, existing requests keep running.
	if len(h.pending[hostID]) >= maxPendingRelayPerHost {
		h.mu.Unlock()
		return RelayResponse{}, &RelayError{Status: 429, Message: "host 在途中继请求过多"}
	}
	pr := &pendingReq{
		resp: make(chan RelayResponse, 1),
		done: make(chan struct{}),
	}
	if h.pending[hostID] == nil {
		h.pending[hostID] = make(map[string]*pendingReq)
	}
	h.pending[hostID][reqID] = pr
	h.mu.Unlock()

	// Delivery is the session's problem: the frame is logged and retransmitted
	// until the host's cumulative ack covers it. A frame that stays unacked
	// past the request ack deadline fails this request alone (see session.run).
	if err := sess.dispatch(reqID, method, path, body); err != nil {
		h.dropPending(hostID, reqID)
		return RelayResponse{}, &RelayError{Status: 503, Message: fmt.Sprintf("host %s 已断开", hostID)}
	}

	timer := time.NewTimer(RelayTimeout)
	defer timer.Stop()
	// A response that already arrived must win over a concurrently firing
	// timeout: select would otherwise pick the timer branch at random and drop
	// an answer that is already here.
	select {
	case resp := <-pr.resp:
		return resp, nil
	default:
	}
	for {
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
	pr := h.takePendingLocked(hostID, reqID)
	if pr == nil {
		return false
	}
	pr.resp <- resp
	return true
}

// takePendingLocked removes one pending request and reports it, or nil when
// the host/reqId is unknown (a late or duplicate respond). Callers hold h.mu.
func (h *Hub) takePendingLocked(hostID, reqID string) *pendingReq {
	m := h.pending[hostID]
	if m == nil {
		return nil
	}
	pr, ok := m[reqID]
	if !ok {
		return nil
	}
	delete(m, reqID)
	if len(m) == 0 {
		delete(h.pending, hostID)
	}
	return pr
}

// failRelayRequestLocked drops one pending request and answers it with a 502
// JSON error. Unlike failPendingLocked it does not touch the host's other
// requests or the session: one oversized or malformed answer must not fail
// everything else in flight. Callers hold h.mu.
func (h *Hub) failRelayRequestLocked(hostID, reqID, reason string) {
	pr := h.takePendingLocked(hostID, reqID)
	if pr == nil {
		return
	}
	pr.chunks = nil
	body, _ := json.Marshal(map[string]any{"ok": false, "error": reason})
	pr.resp <- RelayResponse{Status: 502, Body: body}
}

// maxChunkedRelayBody caps the assembled size of a chunked relay response.
// The host already refuses to relay a local body over its own 28MB ceiling,
// so anything larger here is a broken or hostile chunk stream; dropping the
// request keeps hub memory bounded instead of buffering without limit. A var
// so tests can shrink it.
var maxChunkedRelayBody = 28 << 20

// RespondChunk feeds one chunk of a chunked relay response (the host splits
// bodies over its relay chunk size into base64 frames; see the host's
// respondChunked). It returns true when the chunk belonged to a pending
// request — including the case where it failed that request — and false for
// an unknown reqId, which is logged and counted but otherwise ignored: a
// chunk can legitimately arrive after the browser gave up and the pending
// entry was dropped.
//
// The assembled bytes are handed to the waiting relay caller as a normal
// RelayResponse, so the browser and FE never see the split.
func (h *Hub) RespondChunk(hostID, reqID string, status int, encoding, chunk string, more bool) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	pr := h.pending[hostID][reqID]
	if pr == nil {
		h.lateRelayChunks.Add(1)
		return false
	}
	// The only encoding defined today. An empty encoding with a chunk is a
	// protocol error too: guessing would hand raw bytes to the response
	// writer as if they were the body.
	if encoding != "base64" {
		log.Printf("[capri-hub] host %s req %s: respond chunk encoding %q unsupported", hostID, reqID, encoding)
		h.failRelayRequestLocked(hostID, reqID, fmt.Sprintf("中继响应分块编码不受支持: %q", encoding))
		return true
	}
	decoded, err := base64.StdEncoding.DecodeString(chunk)
	if err != nil {
		log.Printf("[capri-hub] host %s req %s: respond chunk base64 decode: %v", hostID, reqID, err)
		h.failRelayRequestLocked(hostID, reqID, "中继响应分块无法解码")
		return true
	}
	if len(pr.chunks)+len(decoded) > maxChunkedRelayBody {
		log.Printf("[capri-hub] host %s req %s: chunked relay body over %d bytes, failing this request only",
			hostID, reqID, maxChunkedRelayBody)
		h.failRelayRequestLocked(hostID, reqID, fmt.Sprintf("中继响应超过 %dMB 上限", maxChunkedRelayBody>>20))
		return true
	}
	if !pr.chunkStatusSet {
		pr.chunkStatus = status
		pr.chunkStatusSet = true
	}
	pr.chunks = append(pr.chunks, decoded...)
	if more {
		return true
	}
	body := pr.chunks
	if !json.Valid(body) {
		// The host wraps non-JSON bodies as JSON strings, so invalid bytes
		// here are a protocol bug. A 502 is better than handing the FE
		// bytes its JSON writer would choke on.
		log.Printf("[capri-hub] host %s req %s: assembled relay body is not valid JSON (%d bytes)", hostID, reqID, len(body))
		h.failRelayRequestLocked(hostID, reqID, "拼接后的中继响应不是合法 JSON")
		return true
	}
	pr = h.takePendingLocked(hostID, reqID)
	if pr == nil {
		return true // raced with a dropPending; the browser is gone
	}
	pr.chunks = body
	pr.resp <- RelayResponse{Status: pr.chunkStatus, Body: body}
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
// count so they can pause event upload when nobody is listening (the
// heartbeat and the registry it feeds keep running on the host side).
func (h *Hub) Subscribe() (ch chan Event, unsubscribe func()) {
	ch, unsub, _ := h.TrySubscribe(0) // 0 = unlimited
	return ch, unsub
}

// feDropStats is the hub-level aggregate of the per-subscriber drop path
// (see feSubscriber.noteDrop / pump). Atomics because both are touched on
// the fan-out/pump hot path, where a lock is forbidden.
type feDropStats struct {
	dropped atomic.Uint64
	resyncs atomic.Uint64
}

// feSubscriber is one browser /ws/fe registration. The channel is the
// fan-out queue; per-subscriber pressure state hangs off this struct so
// the copy-on-write list stays a plain slice.
//
// Delivery model: deliver() only appends to the per-subscriber ring (never
// blocks), and this subscriber's own pump goroutine owns every write to ch.
// A wedged browser therefore stalls nothing but its own pump — not the
// host read loop that feeds fan-out, and not the other browsers watching
// the same host (before the ring, a wedged subscriber's full channel was
// waited on inline, on the shared fan-out path).
type feSubscriber struct {
	ch chan Event

	// id is this subscriber's registration stamp (hub-monotonic). The admin
	// subscriber panel lists rows by it, and a page learns its own id from
	// the hello it receives, so the panel can mark "this page".
	id int64
	// connectedAt is when TrySubscribe registered this socket. Reported to
	// the admin panel as "how long has this page been open".
	connectedAt time.Time
	// info is the browser-supplied identity (IP as seen by the hub minus
	// port, User-Agent, role label). Set before the subscriber is published
	// to the list and never mutated afterwards, so readers of the
	// copy-on-write snapshot see a complete value.
	info SubscriberInfo

	// host is this subscriber's event filter: a host ID fans out only
	// that host's events, the empty string (or nothing stored) fans out
	// every host — the behaviour pre-filtering FE clients get. Written by
	// the /ws/fe reader when the page switches hosts and read lock-free
	// per event by broadcast, hence the atomic.
	host atomic.Value // string

	// session is the session the page currently displays (the `subscribe`
	// control frame). Admin pages report it too — the subscriber panel
	// shows which transcript each tab is looking at, and it is the input to
	// the host's uplink filter (see viewingSetLocked).
	session atomic.Value // string

	// viewDeclared is set the first time this page sends the explicit
	// `viewing` control frame (even with an empty session). It separates two
	// states that look identical on the wire: "an FE that speaks the viewing
	// protocol and currently displays nothing" (contributes no session to the
	// host's filter) and "an FE too old to ever send one" (the host must not
	// filter at all). The `subscribe` frame deliberately does not set it.
	viewDeclared atomic.Bool

	// Guest subscribers (a browser authenticated with a guest token) are
	// additionally scoped to a whitelist: hub-level events, hosts outside
	// allowedHosts and events whose top-level sessionId is outside
	// allowedSessions never reach them. The maps are built once at
	// subscribe time and never mutated, so the fan-out path reads them
	// without a lock.
	guest           bool
	guestTokenID    string
	allowedHosts    map[string]bool
	allowedSessions map[string]bool
	// guestParentOf resolves a subagent child session to the parent that
	// spawned it (see Hub.noteGuestChild). A guest may read a child whose
	// parent is whitelisted — the subagent timeline lives under the child id.
	// Nil for admin subscribers.
	guestParentOf func(hostID, sessionID string) string

	// kicked is closed when the guest token behind this subscriber is
	// revoked or deleted, so /ws/fe can close the socket immediately
	// instead of waiting for the next request to be rejected.
	kicked   chan struct{}
	kickOnce sync.Once

	// dropped counts events dropped (or dropped-eligible) for this slow
	// subscriber. Once it reaches resyncDropThreshold a resync frame is
	// pushed and the counter resets — one resync per threshold worth of
	// drops, so a permanently stuck FE cannot trigger a resync storm.
	dropped atomic.Int32
	// stats points at the hub-wide counters (nil for subscribers built
	// directly by tests). Incremented without any lock on the drop path;
	// see GET /api/stats.
	stats *feDropStats

	mu       sync.Mutex
	ring     []Event
	head     int
	n        int
	pending  *Event // one queued resync frame, delivered ahead of the ring
	wake     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

const (
	// subRingCap bounds a subscriber's droppable backlog in front of its
	// channel. Overflow drops (recoverable: the FE gap-pulls the seq hole).
	subRingCap = 2048
	// subRingCriticalSlack reserves ring room for critical events so a
	// droppable flood can never displace a terminal state.
	subRingCriticalSlack = 512
)

// newFeSubscriber registers the ring/pump for one browser subscriber.
// chCap is the consumer-facing buffer (the /ws/fe writer's queue).
func newFeSubscriber(chCap int) *feSubscriber {
	s := &feSubscriber{
		ch:   make(chan Event, chCap),
		ring: make([]Event, subRingCap+subRingCriticalSlack),
		wake: make(chan struct{}, 1),
		done: make(chan struct{}),
	}
	go s.pump()
	return s
}

// stop ends this subscriber's pump (unsubscribe path).
func (s *feSubscriber) stop() {
	s.stopOnce.Do(func() { close(s.done) })
}

// enqueue appends ev to the ring. Droppable events drop once the droppable
// ceiling is reached; critical events may use the reserved slack. Never
// blocks — the caller is the fan-out path.
func (s *feSubscriber) enqueue(ev Event, critical bool) {
	limit := subRingCap
	if critical {
		limit = len(s.ring)
	}
	s.mu.Lock()
	if s.n >= limit {
		s.mu.Unlock()
		s.noteDrop(ev, critical)
		return
	}
	s.ring[(s.head+s.n)%len(s.ring)] = ev
	s.n++
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// pump delivers this subscriber's ring in order. Droppable events are
// dropped the moment ch is full (transient jitter the FE repairs);
// critical events — and a queued resync, which is flushed ahead of the ring —
// wait for a free slot instead, so a terminal state is never lost while the
// subscriber is live.
func (s *feSubscriber) pump() {
	for {
		s.mu.Lock()
		if s.pending != nil {
			ev := *s.pending
			s.pending = nil
			s.mu.Unlock()
			ok := s.send(ev)
			if ok && s.stats != nil && ev["type"] == "resync" {
				s.stats.resyncs.Add(1)
			}
			if !ok {
				return
			}
			continue
		}
		if s.n == 0 {
			s.mu.Unlock()
			select {
			case <-s.wake:
				continue
			case <-s.done:
				return
			}
		}
		ev := s.ring[s.head]
		s.mu.Unlock()

		if criticalEvent(ev) {
			if !s.send(ev) {
				return
			}
		} else if !s.trySend(ev) {
			if s.stopped() {
				return
			}
			s.noteDrop(ev, false)
		}

		s.mu.Lock()
		s.ring[s.head] = nil
		s.head = (s.head + 1) % len(s.ring)
		s.n--
		s.mu.Unlock()
	}
}

// send blocks until ev is handed to the consumer or the subscriber stops.
func (s *feSubscriber) send(ev Event) bool {
	select {
	case s.ch <- ev:
		return true
	case <-s.done:
		return false
	}
}

// trySend is send without waiting.
func (s *feSubscriber) trySend(ev Event) bool {
	select {
	case s.ch <- ev:
		return true
	default:
		return false
	}
}

func (s *feSubscriber) stopped() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// noteDrop records one event lost to this subscriber and decides whether to
// escalate to a resync frame.
//
// A dropped CRITICAL event escalates immediately instead of waiting for the
// threshold: the FE would otherwise sit on a turn that already ended (or a
// permission card that will never paint) with no later event to reveal the
// gap — the (hostId,seq) gap-pull only fires when a higher seq arrives, and
// a terminal event is usually the last one of its turn.
//
// The frame is QUEUED in a dedicated slot, not pushed: noteDrop runs on the
// fan-out path, where blocking is forbidden (a full channel must never stall
// the host read loop), and a push would be lost exactly when the consumer is
// behind — the moment the resync matters. The pump flushes it ahead of the
// ring backlog as soon as the consumer drains.
func (s *feSubscriber) noteDrop(ev Event, critical bool) {
	if s.stats != nil {
		s.stats.dropped.Add(1)
	}
	n := s.dropped.Add(1)
	if !critical && n < resyncDropThreshold {
		return
	}
	s.dropped.Store(0)
	s.queueResync(resyncFrame(ev))
}

// queueResync parks one control frame for the pump. It never blocks and never
// competes with the ring for room; a newer resync replaces a still-pending
// one (both mean "rebuild", and the FE only ever advances its watermark, so
// keeping the newest boundary is the safe choice).
func (s *feSubscriber) queueResync(ev Event) {
	s.mu.Lock()
	s.pending = &ev
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// hostFilter is the subscriber's current host filter ("" = every host).
func (s *feSubscriber) hostFilter() string {
	if v, ok := s.host.Load().(string); ok {
		return v
	}
	return ""
}

// watches reports whether an event tagged evHost reaches this subscriber.
// Hub-level events (no hostId — hosts_changed, prefs_changed, the FE
// hello) pass for admin subscribers: every browser needs the registry
// whichever host it displays. Guest subscribers never see hub-level
// events — their shell renders from /api/access-role instead.
func (s *feSubscriber) watches(evHost string) bool {
	if evHost == "" {
		return !s.guest
	}
	if s.guest && !s.allowedHosts[evHost] {
		return false
	}
	f := s.hostFilter()
	return f == "" || f == evHost
}

// watchesEvent is watches plus the guest session whitelist: a guest only
// receives an event whose top-level sessionId is one of the sessions its
// token was granted — or a subagent child of one (the child transcript is
// part of what the shared session is doing). Events without a top-level
// sessionId are dropped for guests (the hub can only judge by that field —
// subagent metadata keeps reaching guests through /api/subagent/get).
func (s *feSubscriber) watchesEvent(ev Event) bool {
	evHost, _ := ev["hostId"].(string)
	if !s.watches(evHost) {
		return false
	}
	if !s.guest {
		return true
	}
	sid := eventSessionID(ev)
	if sid == "" {
		return false
	}
	if s.allowedSessions[GuestSessionKey(evHost, sid)] {
		return true
	}
	if s.guestParentOf == nil {
		return false
	}
	parent := s.guestParentOf(evHost, sid)
	return parent != "" && s.allowedSessions[GuestSessionKey(evHost, parent)]
}

// kick ends a guest subscriber's socket (token revoked or deleted).
func (s *feSubscriber) kick() {
	s.kickOnce.Do(func() { close(s.kicked) })
}

// Drop-tier policy for a full subscriber queue. Terminal / control events
// must never be lost to backpressure: a FE that misses "done" or a
// client_request waits on a turn that already ended. Bulk streaming
// events (chunk/thought and everything else) are droppable — the FE's
// (hostId,seq) gap-pull repairs them.
//
// The set MUST cover every event the FE treats as a turn terminal or a
// pending-interaction transition (see capri-fe store/chat/turnLifecycle.ts
// TURN_TERMINAL_TYPES + events/turnEnd.ts): dropping "cancelled" /
// "prompt_complete" leaves the composer stuck on "Responding…" with no
// later event to reveal the gap, and a dropped session-scoped "error"
// hides the failure entirely.
var criticalEventTypes = map[string]struct{}{
	"done":                    {},
	"turn_completed":          {},
	"cancelled":               {},
	"prompt_complete":         {},
	"error":                   {},
	"client_request":          {},
	"client_request_resolved": {},
}

// terminalToolUpdateKey flags the raw-path Event of a tool call's terminal
// update. Host events reach the hub as opaque bytes (see rawWireKey), so
// criticalEvent cannot see the nested status unless ingest lifts it. The
// NUL-prefixed key follows the rawWireKey convention: an Event carrying it
// also carries rawWireKey, and MarshalEvent returns those bytes verbatim,
// so the flag can never leak onto the FE wire.
const terminalToolUpdateKey = "\x00terminalToolUpdate"

const (
	// resyncDropThreshold is the dropped-event count that triggers one
	// {"type":"resync",fromSeq:N} frame (counter then resets). A dropped
	// critical event escalates immediately instead of waiting for it.
	resyncDropThreshold = 32
)

// criticalEvent reports whether ev is a never-drop event type. A
// tool_call_update counts only when it carries the call's terminal status:
// losing that one update leaves the FE spinning a "Running" block until the
// turn-end settle, while the in_progress argument/output deltas for the same
// call stay droppable (gap-pull refills them).
func criticalEvent(ev Event) bool {
	if ev[terminalToolUpdateKey] == true {
		return true
	}
	t, _ := ev["type"].(string)
	_, ok := criticalEventTypes[t]
	return ok
}

// deliver is one subscriber's fan-out step: a non-blocking append to this
// subscriber's ring, drained in order by its pump. It must never block —
// deliver runs on the host fan-out path, and waiting inline on a wedged
// browser's full channel used to slow every other browser watching that host
// (and, before the per-host queue, the host read loop itself). Drop
// accounting and resync escalation live in noteDrop.
func (s *feSubscriber) deliver(ev Event) {
	s.enqueue(ev, criticalEvent(ev))
}

// resyncFrame builds the slow-consumer recovery frame for one dropped
// event. Event seq counters are PER HOST, so the frame has to name the host
// that tripped it: an untagged resync from host B's drop storm was applied
// to whichever host the page happened to watch, jumping that host's
// watermark to B's sequence and silently dropping every event below it.
// Hub-level events carry no hostId and stay untagged.
func resyncFrame(ev Event) Event {
	out := Event{"type": "resync", "fromSeq": evSeq(ev)}
	if hostID, _ := ev["hostId"].(string); hostID != "" {
		out["hostId"] = hostID
	}
	return out
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

// TrySubscribe is Subscribe with no host filter. TrySubscribeHost adds one.
func (h *Hub) TrySubscribe(max int) (ch chan Event, unsubscribe func(), ok bool) {
	return h.TrySubscribeHost(max, "")
}

// TrySubscribeHost is Subscribe with a subscriber cap and an initial host
// filter ("" = every host): when max > 0 and the hub already has max live
// browser subscribers, it returns ok=false instead of registering another.
// Each subscriber costs a 512-event channel plus the caller's goroutines,
// so the /ws/fe endpoint uses this as a resource guard when it is open to
// unauthenticated clients.
func (h *Hub) TrySubscribeHost(max int, hostID string) (ch chan Event, unsubscribe func(), ok bool) {
	return h.TrySubscribeHostInfo(max, hostID, SubscriberInfo{})
}

// TrySubscribeHostInfo is TrySubscribeHost with the browser identity the
// admin subscriber panel shows (remote IP, User-Agent, role). The info is
// display-only bookkeeping; it takes no part in filtering.
func (h *Hub) TrySubscribeHostInfo(max int, hostID string, info SubscriberInfo) (
	ch chan Event, unsubscribe func(), ok bool,
) {
	ch, unsub, _, ok := h.trySubscribe(max, hostID, nil, info)
	return ch, unsub, ok
}

// TrySubscribeGuest is TrySubscribeHost for a guest token's browser: the
// subscriber additionally carries the token's whitelist (hosts + sessions),
// and it is automatically kicked (kicked closed) when that token is revoked
// or deleted.
func (h *Hub) TrySubscribeGuest(max int, hostID string, guest GuestToken) (
	ch chan Event, unsubscribe func(), kicked <-chan struct{}, ok bool,
) {
	return h.TrySubscribeGuestInfo(max, hostID, guest, SubscriberInfo{})
}

// TrySubscribeGuestInfo is TrySubscribeGuest with the browser identity for
// the admin subscriber panel.
func (h *Hub) TrySubscribeGuestInfo(max int, hostID string, guest GuestToken, info SubscriberInfo) (
	ch chan Event, unsubscribe func(), kicked <-chan struct{}, ok bool,
) {
	ch, unsubscribe, sock, ok := h.trySubscribe(max, hostID, &guest, info)
	if !ok || sock == nil {
		return ch, unsubscribe, nil, ok
	}
	return ch, unsubscribe, sock.kicked, true
}

func (h *Hub) trySubscribe(max int, hostID string, guest *GuestToken, info SubscriberInfo) (
	ch chan Event, unsubscribe func(), sub *feSubscriber, ok bool,
) {
	// 512 absorbs short FE write stalls; the subscriber's own pump (see
	// feSubscriber) makes the fan-out path never wait on it.
	s := newFeSubscriber(512)
	s.id = h.nextSubID.Add(1)
	s.stats = &h.feStats
	s.connectedAt = nowStamp()
	s.info = info
	if hostID != "" {
		s.host.Store(hostID)
	}
	if guest != nil {
		s.guest = true
		s.guestTokenID = guest.ID
		s.kicked = make(chan struct{})
		s.allowedHosts = make(map[string]bool, len(guest.Sessions))
		s.allowedSessions = make(map[string]bool, len(guest.Sessions))
		for _, gs := range guest.Sessions {
			s.allowedHosts[gs.HostID] = true
			s.allowedSessions[GuestSessionKey(gs.HostID, gs.SessionID)] = true
		}
		s.guestParentOf = h.guestParentOf
	}
	h.mu.Lock()
	if cur := h.subs.Load(); cur != nil && max > 0 && len(*cur) >= max {
		h.mu.Unlock()
		s.stop()
		return nil, nil, nil, false
	}
	h.subscribeLocked(s)
	h.mu.Unlock()
	h.notifyAudience()
	// The newcomer learns the total from its hello; only the pages already
	// open need the push.
	h.notifySubscribersCount(s)
	return s.ch, func() {
		h.mu.Lock()
		h.unsubscribe(s)
		h.mu.Unlock()
		s.stop()
		for {
			select {
			case <-s.ch:
			default:
				goto drained
			}
		}
	drained:
		h.notifyAudience()
		h.notifySubscribersCount(nil)
	}, s, true
}

// SetSubscriberHost retargets a live subscriber's host filter, identifying
// the subscriber by the channel TrySubscribe handed back — channel values
// are comparable and every subscriber owns a distinct one, so no extra
// handle type is needed on the hot path. hostID "" restores the
// watch-every-host default.
//
// The change is a fan-out change for TWO hosts (the one the page left and
// the one it joined), so it re-notifies hosts: the abandoned host drops to
// zero viewers and pauses its event upload, the new one wakes up. Returns
// false when ch is not (or no longer) a live subscriber.
func (h *Hub) SetSubscriberHost(ch chan Event, hostID string) bool {
	h.mu.Lock()
	var found bool
	if cur := h.subs.Load(); cur != nil {
		for _, s := range *cur {
			if s.ch == ch {
				s.host.Store(hostID)
				found = true
				break
			}
		}
	}
	h.mu.Unlock()
	if !found {
		return false
	}
	h.notifyAudience()
	return true
}

// HostStat is one host's data-plane snapshot for GET /api/stats. It is a
// read-only diagnostic: nothing here feeds a delivery decision.
type HostStat struct {
	HostID  string `json:"hostId"`
	LastSeq uint64 `json:"lastSeq"`
	Online  bool   `json:"online"`
	// Epoch identifies the host's current sequence space; an epoch change is
	// a host process restart, and the per-host FE watermark resets with it.
	Epoch         uint64 `json:"epoch,omitempty"`
	FanoutDropped uint64 `json:"fanoutDropped"`
	// FanoutLen is the current pre-fan-out backlog depth.
	FanoutLen   int `json:"fanoutLen,omitempty"`
	Subscribers int `json:"subscribers"`
	EvBufLen    int `json:"evBufLen"`
	// EvBufBytes is the gap-pull buffer's byte weight; evBufByteCap bounds
	// it, and over the cap the oldest events are dropped.
	EvBufBytes int `json:"evBufBytes,omitempty"`
	// DownUnacked is how many down frames the host has not acked yet; a
	// number that stays high means its uplink ack is not landing.
	DownUnacked int `json:"downUnacked,omitempty"`
}

// Stats is the process-wide diagnostic snapshot behind GET /api/stats.
// FE drops and resyncs are counters since process start: they are the
// evidence that a host's replay storm was actually repaired by gap-pull
// instead of silently lost.
type Stats struct {
	Hosts       []HostStat `json:"hosts"`
	PairedHosts int        `json:"pairedHosts"`
	Subscribers int        `json:"subscribers"`
	FEDropped   uint64     `json:"feDropped"`
	FEResyncs   uint64     `json:"feResyncs"`
	// LateRelayChunks counts chunked respond frames for an unknown reqId
	// (dropped by design; see RespondChunk).
	LateRelayChunks uint64 `json:"lateRelayChunks,omitempty"`
	UptimeSeconds   int64  `json:"uptimeSeconds"`
}

// Stats snapshots the registry and the process counters. Per-host data is
// read through hostState accessors so the registry itself stays private
// (lock order h.mu → hs.mu, as everywhere else).
func (h *Hub) Stats() Stats {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := Stats{
		Hosts:           make([]HostStat, 0, len(h.hosts)),
		PairedHosts:     len(h.hosts),
		FEDropped:       h.feStats.dropped.Load(),
		FEResyncs:       h.feStats.resyncs.Load(),
		LateRelayChunks: h.lateRelayChunks.Load(),
	}
	if cur := h.subs.Load(); cur != nil {
		out.Subscribers = len(*cur)
	}
	if !h.startedAt.IsZero() {
		out.UptimeSeconds = int64(time.Since(h.startedAt) / time.Second)
	}
	for id, hs := range h.hosts {
		st := HostStat{
			HostID:        id,
			LastSeq:       hs.upAcked.Load(),
			Online:        hs.info.Online,
			Epoch:         hs.epoch.Load(),
			FanoutDropped: hs.fanoutDropCount(),
			FanoutLen:     hs.fanoutDepth(),
			Subscribers:   h.subscriberCountForLocked(id),
			EvBufLen:      hs.eventBufferLen(),
			EvBufBytes:    hs.eventBufferBytes(),
		}
		if s := hs.session; s != nil {
			st.DownUnacked = s.proto.downLen()
		}
		out.Hosts = append(out.Hosts, st)
	}
	sort.Slice(out.Hosts, func(i, j int) bool { return out.Hosts[i].HostID < out.Hosts[j].HostID })
	return out
}

// SubscriberCount is the number of live browser /ws/fe clients, whatever
// host each of them watches.
func (h *Hub) SubscriberCount() int {
	if cur := h.subs.Load(); cur != nil {
		return len(*cur)
	}
	return 0
}

// SubscriberCountFor is the number of live browser subscribers that
// actually RECEIVE hostID's events: those filtered to hostID plus every
// watch-all subscriber. Hosts gate event upload on this figure — a page
// showing host A is not an audience for host B, so B can pause its uplink
// instead of streaming into a fan-out that drops it. hostID "" is the
// watch-all audience, i.e. every subscriber.
func (h *Hub) SubscriberCountFor(hostID string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.subscriberCountForLocked(hostID)
}

// subscriberCountForLocked runs the per-subscriber filter test. Callers
// hold h.mu.
func (h *Hub) subscriberCountForLocked(hostID string) int {
	var n int
	if cur := h.subs.Load(); cur != nil {
		for _, s := range *cur {
			if s.watches(hostID) {
				n++
			}
		}
	}
	return n
}

// viewingSet is the resolved "who is looking at what" for one host.
type viewingSet struct {
	// all means the audience cannot be narrowed: at least one subscriber
	// receiving this host's events has not declared a session.
	all      bool
	sessions map[string]bool
}

// maxViewingSessionIDLen bounds one session id in the viewing set. Host
// session ids are agent-issued UUIDs (~36 bytes); 128 is comfortably above
// real ids while keeping arbitrary page-supplied strings out of the frames
// and the dedupe key.
const maxViewingSessionIDLen = 128

// maxViewingSessions bounds the emitted set. Beyond it the audience is
// widened to all:true — the safe direction, because the host then trims
// nothing.
const maxViewingSessions = 64

// viewingSetLocked resolves the viewing set for hostID. Returns nil when
// nobody receives this host's events (the host's uplink is paused on that
// condition anyway, so the caller sends nothing).
//
// Callers hold h.mu.
func (h *Hub) viewingSetLocked(hostID string) *viewingSet {
	cur := h.subs.Load()
	if cur == nil {
		return nil
	}
	var (
		watchers int
		all      bool
		sessions = map[string]bool{}
	)
	// add records one session id, reporting whether the set must widen to
	// All: an oversized id (page-supplied, never a real host id) or more
	// distinct sessions than the cap. Widening is always the safe answer.
	add := func(sid string) {
		if sid == "" {
			return
		}
		if len(sid) > maxViewingSessionIDLen {
			all = true
			h.logViewingWidenLocked(hostID, "oversized session id")
			return
		}
		if sessions[sid] {
			return
		}
		if len(sessions) >= maxViewingSessions {
			all = true
			h.logViewingWidenLocked(hostID, "session cap reached")
			return
		}
		sessions[sid] = true
	}
	for _, s := range *cur {
		if !s.watches(hostID) {
			continue
		}
		watchers++
		sid, _ := s.session.Load().(string)
		if !s.viewDeclared.Load() {
			// This page has not declared a session yet (its socket is new, so
			// its first `viewing` frame is still in flight). Until it does,
			// its page could display anything, so the host must not filter.
			all = true
			continue
		}
		if sid == "" {
			// Declared "nothing displayed" (e.g. between hosts). Contributes
			// no session, but does not widen the set either.
			continue
		}
		add(sid)
	}
	if watchers == 0 {
		return nil
	}
	if all {
		return &viewingSet{all: true}
	}
	// Follow one level into subagent children, exactly like the guest
	// whitelist: the child's stream feeds the parent page's mini scrollback.
	if kids := h.guestChildren.Load(); kids != nil {
		for key, parent := range *kids {
			if !sessions[parent] {
				continue
			}
			if host, sid, ok := splitGuestSessionKey(key); ok && host == hostID {
				add(sid)
				if all {
					break
				}
			}
		}
	}
	if all {
		return &viewingSet{all: true}
	}
	return &viewingSet{sessions: sessions}
}

// logViewingWidenLocked rate-limits the diagnostic for a set widened to
// All (oversized id or size cap). Caller holds h.mu.
func (h *Hub) logViewingWidenLocked(hostID, reason string) {
	if time.Since(h.lastViewWidenLog) < time.Minute {
		return
	}
	h.lastViewWidenLog = time.Now()
	log.Printf("[capri-hub] host %s: viewing set widened to all (%s)", hostID, reason)
}

// ── audience (absolute viewer state, one frame) ───────────────────────

// Audience is the absolute viewer state for one host: how many browsers
// receive its events and which sessions they display. One frame carries both,
// with one generation, one ack path and one retransmit entry — the host pauses
// its upload on watchers==0 and filters nothing when all is set.
//
// The snapshot is built under h.mu from the live subscriber list, so it is
// always the newest state and wins over anything still in flight by gen.

// audienceKey renders the parts of a snapshot that decide whether it changed.
// gen is excluded: an identical payload must keep its old generation so the
// host can discard the duplicate.
func audienceKey(a wire.Audience) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d|%t|", a.Watchers, a.All)
	for _, s := range a.Sessions {
		b.WriteString(s)
		b.WriteByte(0)
	}
	return b.String()
}

// audienceLocked snapshots hostID's audience and assigns it the current
// per-host generation, minting the first one (gen 1) for a host that never had
// one. Callers hold h.mu.
func (h *Hub) audienceLocked(hostID string) (wire.Audience, bool) {
	hs := h.hosts[hostID]
	if hs == nil {
		return wire.Audience{}, false
	}
	a := wire.Audience{Watchers: h.subscriberCountForLocked(hostID)}
	if set := h.viewingSetLocked(hostID); set != nil {
		if set.all {
			a.All = true
		} else {
			a.Sessions = make([]string, 0, len(set.sessions))
			for sid := range set.sessions {
				a.Sessions = append(a.Sessions, sid)
			}
			sort.Strings(a.Sessions)
		}
	}
	key := audienceKey(a)
	changed := false
	switch {
	case hs.audienceGen == 0:
		hs.audienceGen = 1
		hs.audienceKey = key
	case key != hs.audienceKey:
		hs.audienceGen++
		hs.audienceKey = key
		changed = true
	}
	a.Gen = hs.audienceGen
	return a, changed
}

// notifyAudience pushes the current audience to every attached host whose
// snapshot changed. Called on subscriber connect/disconnect, host retarget and
// viewing changes; dedupe happens here, so a no-op reload storm costs nothing.
func (h *Hub) notifyAudience() {
	type send struct {
		s *session
		a wire.Audience
	}
	var todo []send
	h.mu.Lock()
	for id, hs := range h.hosts {
		if hs.session == nil {
			continue
		}
		a, changed := h.audienceLocked(id)
		if !changed {
			continue
		}
		todo = append(todo, send{s: hs.session, a: a})
	}
	h.mu.Unlock()
	for _, t := range todo {
		if err := t.s.pushAudience(t.a); err != nil {
			Verbosef("[capri-hub] host %s: audience push: %v", t.s.hostID, err)
		}
	}
}

// announceEpochReset tells the /ws/fe subscribers of hs that its sequence
// space restarted, so their per-host watermark resets before any new-epoch
// event. It is enqueued on the per-host fan-out queue, not delivered directly:
// the reset must not jump ahead of work already queued for this host. Items
// still tagged with the retired epoch are dropped by the drain instead of
// being delivered behind the reset; that is safe because the FE rebuilds the
// transcript from host history, and a stale seq behind the reset would
// otherwise be accepted and shadow every new-epoch event below it.
//
// Caller holds h.mu (attach). A host with no queue and no goroutine yet cannot
// have a pending event, so direct delivery is equivalent there.
func (h *Hub) announceEpochReset(hs *hostState, baseline uint64) {
	hostID := hs.info.HostID
	ev := Event{"v": 1, "type": "subscribed", "host": hostID, "seq": baseline}
	if hs.fanoutReady() {
		// Tagged with the new epoch: queued items of the retired epoch are
		// dropped at drain time (fanoutItemCurrent), while this reset is
		// delivered.
		hs.enqueueFanout(h, hostID, ev, hs.epoch.Load())
		return
	}
	if cur := h.subs.Load(); cur != nil {
		for _, s := range *cur {
			if s.watches(hostID) {
				s.deliver(ev)
			}
		}
	}
}

// notifySubscribersCount pushes {v:1, type:"subscribers_changed", count:N}
// to the browser subscribers when the total live /ws/fe client count
// changes. The FE top bar renders it next to the host block, so it is the
// raw browser total (every host's audience) — unlike the per-host
// `audience` frames, which drive the host upload gate.
//
// except is the page whose hello is about to carry the same figure (its own
// subscribe): skipping it keeps a freshly opened socket's channel empty
// until real host traffic arrives. Callers on the leave path pass nil.
//
// Hub-level, so it goes out unfiltered: a page watching host A still needs
// the global figure. An unchanged count is not re-sent; a missed frame is
// repaired by the next connect/disconnect (or the next page's hello).
func (h *Hub) notifySubscribersCount(except *feSubscriber) {
	h.mu.Lock()
	var cur []*feSubscriber
	if p := h.subs.Load(); p != nil {
		cur = *p
	}
	count := len(cur)
	if h.subsSeen && h.lastFESubs == count {
		h.mu.Unlock()
		return
	}
	h.subsSeen = true
	h.lastFESubs = count
	h.mu.Unlock()
	ev := Event{
		"type":  "subscribers_changed",
		"count": count,
	}
	for _, s := range cur {
		if s == except || !s.watchesEvent(ev) {
			continue
		}
		s.deliver(ev)
	}
}

func (h *Hub) Broadcast(ev Event) {
	h.broadcast(ev)
}

// broadcast fans an event out to the browser subscribers that watch its
// host, against a lock-free copy-on-write snapshot of the subscriber list:
// registration churn (browser connect/disconnect, host switch) swaps the
// slice under h.mu, while this hot path — per host event — never touches
// the global lock.
func (h *Hub) broadcast(ev Event) {
	cur := h.subs.Load()
	if cur == nil {
		return
	}
	// hostId is stamped on the Event map by both ingest paths
	// (appendEvent / RegisterRawEvents), so the filter is a map read, not
	// a decode. Guest subscribers additionally need the top-level
	// sessionId against their whitelist (see watchesEvent).
	for _, s := range *cur {
		if !s.watchesEvent(ev) {
			continue
		}
		s.deliver(ev)
	}
}

// broadcastHost fans one queued event out to the subscribers of hostID. An
// event that carries its own hostId (every uplinked transcript event) uses the
// full guest filter; a control frame without one — the epoch-reset
// `subscribed` — goes to every subscriber watching that host, guests included,
// because it carries no session to whitelist.
func (h *Hub) broadcastHost(hostID string, ev Event) {
	cur := h.subs.Load()
	if cur == nil {
		return
	}
	_, tagged := ev["hostId"].(string)
	for _, s := range *cur {
		if !s.watches(hostID) {
			continue
		}
		if tagged && !s.watchesEvent(ev) {
			continue
		}
		s.deliver(ev)
	}
}

// DropGuestSubscribers kicks every live subscriber authenticated with the
// given guest token (revoked / deleted). Closing the socket is what makes
// a revocation take effect on an already-open tab; the client's next
// request would be rejected anyway, but a read-only page makes none.
func (h *Hub) DropGuestSubscribers(tokenID string) {
	cur := h.subs.Load()
	if cur == nil || tokenID == "" {
		return
	}
	for _, s := range *cur {
		if s.guest && s.guestTokenID == tokenID {
			s.kick()
		}
	}
}

// SetSubscriberSession records which session a page currently displays, for
// the subscriber roster and — for guests — whitelist bookkeeping. It is the
// `subscribe` control frame and `?session=` bootstrap path.
//
// It deliberately does NOT mark the page as speaking the viewing protocol:
// a `subscribe` frame retargets the host filter and may carry a session for
// the roster, but only the explicit `viewing` frame declares what the page
// displays (see PROTOCOL.md §6.4). A page that only sends `subscribe` keeps
// the host's viewing set at all:true — otherwise its whole transcript would
// be trimmed.
//
// Reports false when ch is not (or no longer) a live subscriber.
func (h *Hub) SetSubscriberSession(ch chan Event, sessionID string) bool {
	return h.setSubscriberSession(ch, sessionID, false)
}

// SetSubscriberViewing records the session an admin page declares through
// the explicit `viewing` control frame. Unlike SetSubscriberSession it also
// marks the page as a viewing-protocol speaker (even when sessionID is
// empty = "currently displays nothing"), which is what lets the host narrow
// the uplink to the displayed sessions.
//
// Reports false when ch is not (or no longer) a live subscriber.
func (h *Hub) SetSubscriberViewing(ch chan Event, sessionID string) bool {
	return h.setSubscriberSession(ch, sessionID, true)
}

func (h *Hub) setSubscriberSession(ch chan Event, sessionID string, declared bool) bool {
	h.mu.Lock()
	cur := h.subs.Load()
	if cur == nil {
		h.mu.Unlock()
		return false
	}
	found := false
	for _, s := range *cur {
		if s.ch == ch {
			s.session.Store(sessionID)
			if declared {
				s.viewDeclared.Store(true)
			}
			found = true
			break
		}
	}
	h.mu.Unlock()
	if !found {
		return false
	}
	h.notifyAudience()
	return true
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
