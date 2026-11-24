package hub

import (
	"encoding/json"
	"github.com/AgentsHarness/capri-hub/wire"
	"log"
	"sort"
	"time"
)

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
	// Any attach cancels a pending detach grace: a same-epoch resume keeps the
	// pending table, a new epoch fails it below.
	hs.pendingGraceToken++
	if hs.proto == nil || hs.proto.epoch != epoch {
		// Requests dispatched in the old sequence space can never be
		// answered there; the new epoch's sender starts from zero, so fail
		// them instead of leaving the browser waiting for RelayTimeout.
		if hs.proto != nil {
			h.failPendingLocked(hostID)
		}
		hs.proto = newSessionProto(epoch, resumeUp)
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
		// Tombstones describe the retired sequence space; the new epoch
		// starts with no relay memory on either side.
		delete(h.relayTombstones, hostID)
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
		notify: make(chan struct{}, 1),
		stop:   make(chan struct{}),
	}
	// The hello handshake is itself a fresh frame; a Dispatch that races the
	// session goroutine's start must not mistake the link for a silent one.
	s.lastFrameAt.Store(time.Now().UnixNano())
	hs.session = s
	hs.info.Online = true
	hs.info.LastSeen = time.Now()
	// A pending grace-period clear of the gap-pull buffer must not run while
	// this session is attached.
	hs.evBufEpoch++

	aud, _ := h.audienceLocked(hostID)
	liveness := SessionLiveness
	limits := SessionLimits
	caps := wire.Caps{Deflate: deflate, TransportUnits: true, RelayAck: true}
	ack = wire.HelloAck{
		Epoch:     epoch,
		HubBoot:   h.hubBoot,
		AckUp:     hs.proto.upAcked(),
		AckDown:   hs.proto.downAcked(),
		Audience:  &aud,
		Liveness:  &liveness,
		Limits:    &limits,
		Caps:      &caps,
		RelayAcks: h.relayAcksLocked(hostID),
	}
	h.broadcast(hostsChanged())
	return s, old, ack, nil
}

// detach clears the attachment. A superseded session (a newer one already
// holds the host) must not touch the registry or the pending table; the
// replacement owns both from the moment it attached.
//
// Pending relayed requests are not failed here. A same-epoch reconnect can
// still replay the down log and deliver their answers, so they are failed only
// when the grace timer expires with no new session (schedulePendingGrace), on
// a new-epoch attach, or by RelayTimeout.
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
	hs.pendingGraceToken++
	graceToken := hs.pendingGraceToken
	h.broadcast(hostsChanged())
	h.mu.Unlock()

	// Keep the gap-pull buffer for EventBufGrace: a browser can still fill a
	// hole left by a short disconnect.
	h.scheduleEvBufClear(s.hostID, epoch)
	h.schedulePendingGrace(s.hostID, graceToken)
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

// schedulePendingGrace fails hostID's pending requests after pendingGrace
// unless the host reattached (or a later detach superseded this timer). One
// timer per detach, not per request: the pending table is failed as a whole,
// exactly as a new epoch does.
func (h *Hub) schedulePendingGrace(hostID string, token uint64) {
	fail := func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		hs := h.hosts[hostID]
		if hs == nil || hs.session != nil || hs.pendingGraceToken != token {
			return
		}
		h.failPendingLocked(hostID)
	}
	grace := pendingGrace
	if grace <= 0 {
		fail()
		return
	}
	time.AfterFunc(grace, fail)
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

// touchHost refreshes the host's freshness stamp for a received frame. It is
// deliberately silent: hosts_changed is a registry transition (attach/detach,
// status flip), not a per-frame broadcast.
func (h *Hub) touchHost(hostID string) {
	h.mu.Lock()
	if hs := h.hosts[hostID]; hs != nil {
		hs.info.LastSeen = time.Now()
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

// failPendingLocked closes and drops every pending request for hostID. It is
// the new-epoch, unpair and detach-grace path: none of them can still deliver
// an answer, so the whole table is terminal. Caller must hold h.mu.
func (h *Hub) failPendingLocked(hostID string) {
	for reqID, pr := range h.pending[hostID] {
		// The host must drop any answer it still holds for these; a same-epoch
		// reconnect learns it from hello_ack.relayAcks. A new epoch clears the
		// table instead: its down log starts empty, so there is nothing to
		// abort.
		h.addAbortTombstoneLocked(hostID, reqID)
		close(pr.done)
		delete(h.pending[hostID], reqID)
	}
	delete(h.pending, hostID)
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
	Version      *string
}

// UpdateHostStatus applies the status snapshot carried by a host heartbeat.
// On any visible-field flip it updates the registry entry and broadcasts
// hosts_changed. Returns false for unknown hosts. Does not touch the
// transcript buffer. Port and version flips are also persisted (the FE may
// need them after a hub restart before the next heartbeat).
func (h *Hub) UpdateHostStatus(hostID string, p HostStatusPatch) bool {
	h.mu.Lock()
	hs := h.hosts[hostID]
	if hs == nil {
		h.mu.Unlock()
		return false
	}
	changed := false
	persistChanged := false
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
			persistChanged = true
		}
	}
	// An empty version means an old host that predates the field; keep the
	// last known value instead of erasing it on every heartbeat.
	if p.Version != nil && *p.Version != "" && *p.Version != hs.info.Version {
		hs.info.Version = *p.Version
		changed = true
		persistChanged = true
	}
	persist := persistChanged && h.dataFile != ""
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
