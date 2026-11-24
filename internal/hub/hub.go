// Package hub implements the capri-hub relay core: host pairing (pairing
// code → token), the host registry, event fan-out to browsers, and the
// browser ↔ host request relay.
//
// Transport model (WebSocket + QUIC + HTTP API):
//
//	Browser (capri-fe) ──WS /ws/fe + HTTP /api/*──▶ capri-hub ──WS|QUIC──▶ capri-host × N ──stdio──▶ grok
//
// Hosts connect OUTBOUND to the hub (NAT-friendly) and speak the v3 session
// protocol (wire/PROTOCOL-V2.md; the filename is historical): relayed browser requests and absolute
// audience state down, events / relays up, all with one seq space per
// direction. Browsers open /ws/fe for the aggregated live event stream; REST
// APIs stay on HTTP.
package hub

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AgentsHarness/capri-hub/wire"
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
	// need this order of magnitude. capri-host's own relayTimeout (40m) is
	// deliberately shorter, so the host answers with a real error before this
	// 504 fires.
	//
	// Delivery itself has no ack deadline: a request frame stays in the down
	// log until the host's cumulative ack covers it, and a detached session
	// keeps its pending requests through pendingGrace so a same-epoch
	// reconnect can still deliver the answer.
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

// hostRelayChunkSize is the host's current relay chunk size (capri-host
// relayChunkSize). It is the assumed minimum chunk size when deriving how many
// parked chunks one maximum answer can produce.
const hostRelayChunkSize = 256 << 10

// Out-of-order relay chunks are parked per host until the gap fills. The
// bounds keep a broken or hostile chunk stream from turning the parked map
// into unbounded memory: over either bound the affected request fails with a
// 502 and an abort tombstone, while the session and other requests survive.
//
// They must not be so tight that a legitimate resume fails: a 28MiB answer at
// the host's 256KiB chunk size is ~112 chunks, so a lost first chunk parks the
// other 111. The count bound therefore holds two answers' worth (a resume can
// overlap another in-flight request), never below 256 chunks. Parked frames
// carry base64 chunks, so the byte bound allows the 4/3 encoding expansion for
// two answers plus one chunk of slack. Both are aggregate per host, not per
// request. They are derived from the default maxChunkedRelayBody at process
// start; tests that shrink the body cap override them explicitly.
var (
	maxParkedRelayChunksPerHost = max(256, 2*(maxChunkedRelayBody/hostRelayChunkSize+1))
	maxParkedRelayBytesPerHost  = 2 * (maxChunkedRelayBody*4/3 + hostRelayChunkSize)
)

// The ack table keeps a tombstone for every resolved or aborted request until
// the down-log request itself can no longer be replayed. A same-epoch reconnect
// may replay an unacked request for as long as RelayTimeout, so the tombstone
// must outlive that window plus the detach grace; a shorter TTL would let a
// late replay execute a request the browser was already told failed. Bounded by
// count and age.
var (
	maxRelayTombstonesPerHost = 1024
	relayTombstoneTTL         = RelayTimeout + time.Minute
)

// pendingGrace is how long a detached host's in-flight relayed requests stay
// pending before they are failed. A same-epoch reconnect inside the window
// replays the down log and can still deliver the answer, so a transport blip
// must not answer 503 for a request the host may already be executing. A new
// epoch fails them at attach instead: the host process restarted, so nothing
// in the old sequence space can be answered. A var so tests can shrink it.
var pendingGrace = 30 * time.Second

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
// appearance prefs (fePrefs). The deployment admin keeps root's document in
// prefs.json; every ordinary user has a separate document in
// prefs-users.json. The FE mirrors its document in localStorage (offline
// cache) and writes it here (debounced) so pins/todos survive browser data
// clearing. Records are keyed by sessionId/cwd only — session ids are
// host-assigned UUIDs, so a doc is effectively per host conversation
// without an explicit hostId scope.
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
// the browser can try 127.0.0.1:<port>); it is persisted. LastSeen is the last
// attach/detach activity, refreshed by every frame the host sends, and orders
// the host list: online is derived from the attachment, never from this
// timestamp. LastSeenAgeMs is computed on the hub clock for FE freshness
// checks — browsers must not subtract LastSeen from their own clock because
// the two machines' clocks are independent (and may be skewed by minutes).
type HostInfo struct {
	HostID   string `json:"hostId"`
	HostName string `json:"hostName"`
	// OwnerID is the user record that paired this host ("root" for the
	// deployment admin). The browser-facing handlers filter on it; the
	// field itself is harmless to expose because callers only ever see
	// hosts they own.
	OwnerID string `json:"ownerId,omitempty"`
	Online  bool   `json:"online"`
	Ready   bool   `json:"ready"`
	// Busy: any session has a turn in flight (thinking / working).
	Busy bool `json:"busy,omitempty"`
	// Booting: agent process has not finished booting.
	Booting bool `json:"booting,omitempty"`
	// PendingCount: pending client requests (permits / x.ai questions).
	PendingCount int `json:"pendingCount,omitempty"`
	// Port: host's local HTTP listen port (e.g. 8765). FE probes
	// http://127.0.0.1:<port> for a same-machine shortcut.
	Port int `json:"port,omitempty"`
	// Version: host binary build stamp (acp.Version), learned from its
	// heartbeat. Persisted so an offline host still shows its last known
	// version; empty for hosts that predate the field.
	Version       string    `json:"version,omitempty"`
	LastSeen      time.Time `json:"lastSeen"`
	LastSeenAgeMs int64     `json:"lastSeenAgeMs"`
	Local         bool      `json:"local,omitempty"`
}

// RelayResponse is the host's answer (WS type:"respond").
type RelayResponse struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body,omitempty"`
}

// pendingReq is one relayed request waiting for the host's answer.
//
// Answer assembly is ordered by the relay plane's per-request ChunkSeq:
// nextChunk is the highest contiguous chunk applied (0 = none), parked holds
// frames that arrived ahead of the gap, and finalChunk is the ChunkSeq that
// resolved the request. The hub acknowledges progress per request through
// relayAcks, independently of the session's cumulative seq.
type pendingReq struct {
	resp chan RelayResponse
	done chan struct{}

	// Ordered relay response assembly (see Hub.acceptRespond). A body over
	// the host's relay chunk size arrives as several `respond` frames of
	// base64; chunks accumulates the body bytes, chunkStatus is the status
	// from the first applied frame, and chunked marks a multi-frame answer.
	// Guarded by Hub.mu, like the map entry itself.
	nextChunk      uint64
	finalChunk     uint64
	parked         map[uint64]wire.Frame
	parkedBytes    int
	chunks         []byte
	chunkStatus    int
	chunkStatusSet bool
	chunked        bool
}

// relayTombstone remembers how a request ended after its pending entry is
// gone, so a reconnecting host learns which answers it may forget and a late
// or duplicate respond is answered with the right verdict.
type relayTombstone struct {
	ack wire.RelayAck
	at  time.Time
}

// hostState is one paired host. Lock order is always h.mu → hs.mu; nothing
// takes them the other way.
type hostState struct {
	info    HostInfo
	ownerID string // "root" or a users.json id
	token   string

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

	// pendingGraceToken invalidates the detach grace timer. attach and detach
	// increment it under h.mu; the timer only fails this host's pending table
	// when its captured token is still current and no session is attached.
	// Guarded by h.mu.
	pendingGraceToken uint64

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
	// userPairCodes holds the per-user pairing codes. Unlike the root code
	// above, these are lazily created when a logged-in user opens the pair
	// dialog. Keyed by the upper-case six-character code; userPairCodeByOwner
	// indexes the live code for each owner.
	userPairCodes       map[string]userPairCode
	userPairCodeByOwner map[string]string

	tokens map[string]string // token → hostId
	hosts  map[string]*hostState

	// subs is the browser-subscriber set as a copy-on-write slice behind
	// an atomic pointer: fan-out reads the snapshot lock-free, and
	// subscribe/unsubscribe swap in a new slice under h.mu. Churn is rare
	// (browser connect/disconnect) while fan-out runs per event, so
	// readers never contend on h.mu.
	subs    atomic.Pointer[[]*feSubscriber]
	pending map[string]map[string]*pendingReq
	// relayTombstones carries the terminal state of recently resolved or
	// aborted relay requests (hostId → reqId → tombstone). It feeds the ack
	// table in hello_ack and hb, so a host that reconnects in the same epoch
	// knows which answers it may drop and which requests were abandoned.
	// Guarded by h.mu; bounded by maxRelayTombstonesPerHost and
	// relayTombstoneTTL, and cleared on a new epoch or unpair.
	relayTombstones map[string]map[string]relayTombstone

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
	// hub.json). Written on SetPrefs only. It is the root admin's document;
	// ordinary users get their own entries in userPrefsFile.
	prefsFile string
	prefs     BrowserPrefs
	// userPrefsFile holds per-user prefs documents (prefs-users.json).
	// Keyed by users.json id so users never see each other's pinned
	// sessions, todos, or appearance flags.
	userPrefsFile      string
	userPrefs          map[string]userPrefsState
	userPrefsPersistMu sync.Mutex
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
	// usersFile holds the user-token table (users.json, sibling of
	// hub.json, 0600). Only SHA-256 hashes are persisted.
	usersFile       string
	users           []User
	userPersistedAt time.Time
	// userPersistMu serializes users.json snapshots (lock order:
	// userPersistMu → h.mu, never the reverse).
	userPersistMu sync.Mutex
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
	// lateRelayChunks counts `respond` frames whose reqId has no pending
	// entry — normally a chunk that arrived after the browser gave up or a
	// duplicate of an answer already delivered. Harmless by design, but a
	// rising count means large answers are outliving their request.
	lateRelayChunks atomic.Uint64
	// relayStats is the debug-only latency/error summary exposed through
	// GET /api/stats. It is aggregate state; per-request detail lives in the
	// [relay] log lines.
	relayStats relayStats
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
		userPairCodes:       make(map[string]userPairCode),
		userPairCodeByOwner: make(map[string]string),
		tokens:              make(map[string]string),
		hosts:               make(map[string]*hostState),
		pending:             make(map[string]map[string]*pendingReq),
		relayTombstones:     make(map[string]map[string]relayTombstone),
		prefs:               BrowserPrefs{PinnedWorkspaces: []string{}, PinnedSessions: []string{}, Todos: map[string]string{}},
		userPrefs:           make(map[string]userPrefsState),
		startedAt:           time.Now(),
		hubBoot:             boot,
	}
	h.subs.Store(&emptySubs)
	if dir != "" {
		h.dataFile = filepath.Join(dir, "hub.json")
		h.load()
		h.prefsFile = filepath.Join(dir, "prefs.json")
		h.loadPrefs()
		h.userPrefsFile = filepath.Join(dir, "prefs-users.json")
		h.loadUserPrefs()
		h.guestsFile = filepath.Join(dir, "guests.json")
		h.loadGuests()
		h.usersFile = filepath.Join(dir, "users.json")
		h.loadUsers()
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
