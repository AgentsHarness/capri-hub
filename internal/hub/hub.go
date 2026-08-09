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
	// RelayTimeout caps how long the hub waits for a host to answer a
	// relayed request (mirrors the host's 30-minute prompt timeout).
	RelayTimeout = 45 * time.Minute
	// eventBufCap bounds per-host buffered events for gap-pull.
	eventBufCap = 4000
)

var (
	// ErrCodeInvalid: the pairing code is wrong or expired.
	ErrCodeInvalid = errors.New("配对码无效或已过期")
	// ErrHostUnknown: hostId was never paired.
	ErrHostUnknown = errors.New("host 未配对")
	// ErrNoHost: nothing paired at all.
	ErrNoHost = errors.New("没有已配对的 host")
)

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
// writes relayed request / subscribers frames to it; `done` closes on disconnect.
type streamConn struct {
	id    int64
	write func(payload []byte) error
	done  chan struct{}
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
	}
	if dir != "" {
		h.dataFile = filepath.Join(dir, "hub.json")
		h.load()
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
	for tok, hid := range pf.Tokens {
		h.tokens[tok] = hid
	}
	for hid, ph := range pf.Hosts {
		h.hosts[hid] = &hostState{
			info: HostInfo{HostID: ph.HostID, HostName: ph.HostName, Ready: ph.Ready},
		}
	}
}

func (h *Hub) save() {
	if h.dataFile == "" {
		return
	}
	pf := persistFile{Tokens: h.tokens, Hosts: make(map[string]persistHost)}
	for hid, hs := range h.hosts {
		pf.Hosts[hid] = persistHost{HostID: hid, HostName: hs.info.HostName, Ready: hs.info.Ready}
	}
	b, err := json.Marshal(pf)
	if err != nil {
		return
	}
	dir := filepath.Dir(h.dataFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("[acp-hub] persist mkdir: %v", err)
		return
	}
	tmp := h.dataFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		log.Printf("[acp-hub] persist write: %v", err)
		return
	}
	if err := os.Rename(tmp, h.dataFile); err != nil {
		log.Printf("[acp-hub] persist rename: %v", err)
	}
}

// ── pairing ───────────────────────────────────────────────────────────

// PairingCode returns the current pairing code and its expiry.
func (h *Hub) PairingCode() (code string, expiresAt time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.pairingCode, h.codeExpires
}

func (h *Hub) rotateCode() {
	h.pairingCode = randomString(codeAlphabet, 6)
	h.codeExpires = time.Now().Add(PairingCodeTTL)
}

// RotatePairingCode replaces the pairing code (old one stops working).
func (h *Hub) RotatePairingCode() (code string, expiresAt time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.rotateCode()
	log.Printf("[acp-hub] pairing code rotated: %s (expires %s)", h.pairingCode, h.codeExpires.Format("15:04:05"))
	return h.pairingCode, h.codeExpires
}

// Pair exchanges a pairing code for a host token. Re-pairing an existing
// hostId revokes its previous token.
func (h *Hub) Pair(code, hostID, hostName string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if strings.ToUpper(strings.TrimSpace(code)) != h.pairingCode {
		return "", ErrCodeInvalid
	}
	if time.Now().After(h.codeExpires) {
		return "", ErrCodeInvalid
	}
	hostID = strings.TrimSpace(hostID)
	if hostID == "" {
		return "", errors.New("hostId 不能为空")
	}
	if hs, ok := h.hosts[hostID]; ok {
		// Revoke the previous token so the old one stops working.
		delete(h.tokens, hs.token)
		hs.info.HostName = hostName
		hs.info.LastSeen = time.Now()
	} else {
		h.hosts[hostID] = &hostState{
			info: HostInfo{HostID: hostID, HostName: hostName, LastSeen: time.Now()},
		}
	}
	token := randomToken()
	h.tokens[token] = hostID
	h.hosts[hostID].token = token
	h.save()
	log.Printf("[acp-hub] host paired: %s (%s)", hostID, hostName)
	return token, nil
}

// HostIDForToken resolves a host token to its hostId.
func (h *Hub) HostIDForToken(token string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	hid, ok := h.tokens[token]
	return hid, ok
}

// ── host connections ──────────────────────────────────────────────────

// ConnectStream registers the host's outbound WebSocket; the returned
// stop func must be called when the connection ends (it fails all pending
// relayed requests for that host).
func (h *Hub) ConnectStream(hostID string, write func(payload []byte) error) (*streamConn, func(), error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	hs := h.hosts[hostID]
	if hs == nil {
		return nil, nil, ErrHostUnknown
	}
	conn := &streamConn{id: h.nextConnID.Add(1), write: write, done: make(chan struct{})}
	hs.conn = conn
	hs.info.Online = true
	hs.info.LastSeen = time.Now()
	h.broadcastLocked(hostsChanged())
	return conn, func() { h.disconnectStream(hostID, conn) }, nil
}

func (h *Hub) disconnectStream(hostID string, conn *streamConn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	hs := h.hosts[hostID]
	if hs == nil || hs.conn != conn {
		return // superseded by a newer connection
	}
	hs.conn = nil
	hs.info.Online = false
	close(conn.done)
	for reqID, pr := range h.pending[hostID] {
		close(pr.done)
		delete(h.pending[hostID], reqID)
	}
	if len(h.pending[hostID]) == 0 {
		delete(h.pending, hostID)
	}
	h.broadcastLocked(hostsChanged())
}

// RegisterEvent accepts a host event: tags it with the host's id/name,
// assigns a sequence number (host-provided when present, else hub-side),
// buffers it for gap-pull, updates liveness (and ready for host_status
// events), then fans it out to browser subscribers. Returns false for
// unknown hosts.
func (h *Hub) RegisterEvent(hostID string, ev Event) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	hs := h.hosts[hostID]
	if hs == nil {
		return false
	}
	hs.info.LastSeen = time.Now()
	// Host-provided seq (events frames carry seqStart); fall back to
	// hub-side assignment for direct RegisterEvent callers (tests).
	if s, ok := ev["seq"].(float64); ok && s > 0 {
		hs.seq = uint64(s)
	} else {
		hs.seq++
		ev["seq"] = hs.seq
	}
	hs.evBuf = append(hs.evBuf, ev)
	if len(hs.evBuf) > eventBufCap {
		hs.evBuf = hs.evBuf[len(hs.evBuf)-eventBufCap:]
	}
	if t, _ := ev["type"].(string); t == "host_status" {
		if r, ok := ev["ready"].(bool); ok && r != hs.info.Ready {
			hs.info.Ready = r
			h.broadcastLocked(hostsChanged())
		}
	}
	ev["hostId"] = hostID
	ev["hostName"] = hs.info.HostName
	h.broadcastLocked(ev)
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
			if s, _ := ev["seq"].(float64); uint64(s) > after {
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

	payload, err := json.Marshal(RelayRequest{V: 1, Type: "request", ReqID: reqID, Method: method, Path: path, Body: body})
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
	// Larger than the old SSE path: WS fan-out still drops on a full buffer,
	// but 512 absorbs short FE write stalls without losing a turn of chunks.
	ch = make(chan Event, 512)
	h.mu.Lock()
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
	}
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
	for _, write := range writes {
		_ = write(payload)
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
