package hub

import (
	"log"
	"sort"
	"time"
)

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
	// Relay is the process-wide relay latency and outcome summary. It is a
	// coarse debug histogram, not a metrics contract.
	Relay         relayStatSnapshot `json:"relay"`
	UptimeSeconds int64             `json:"uptimeSeconds"`
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
		Relay:           h.relayStats.snapshot(),
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
