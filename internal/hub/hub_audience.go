package hub

import (
	"fmt"
	"github.com/AgentsHarness/capri-hub/wire"
	"sort"
	"strings"
)

// ── audience (absolute viewer state, one frame) ───────────────────────

// Audience is the absolute viewer state for one host: how many browsers
// receive its events and which sessions they display. One frame carries both,
// with one generation — the host pauses its upload on watchers==0 and filters
// nothing when all is set.
//
// The snapshot is built under h.mu from the live subscriber list, so it is
// always the newest state. It travels unreliable and latest-wins: the session
// overwrites an unsent snapshot and repeats the newest on every periodic
// heartbeat.

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
		// The global browser count is admin telemetry. User pages have no
		// `feSubscribers` in their hello and guests never receive
		// hub-level events.
		if s.role == "user" || s.role == "guest" {
			continue
		}
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
// broadcastToUser delivers a hub-level event to exactly one account's live
// pages. It is used for prefs_changed, whose payload is the user's own prefs
// document and must never reach another user.
func (h *Hub) broadcastToUser(userID string, ev Event) {
	cur := h.subs.Load()
	if cur == nil {
		return
	}
	root := hostOwnerOrDefault(userID) == "root"
	for _, s := range *cur {
		if root {
			if s.role == "admin" || s.role == "" {
				s.deliver(ev)
			}
			continue
		}
		if s.role == "user" && s.userID == userID {
			s.deliver(ev)
		}
	}
}

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
// given guest token. Closing the socket is what makes revocation, expiry or a
// whitelist change take effect on an already-open tab; the client's next
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

// DropUserSubscribers kicks every live browser authenticated as userID.
// Token reset and account deletion use it so an already-open page stops
// receiving events immediately instead of waiting for its next request.
func (h *Hub) DropUserSubscribers(userID string) {
	cur := h.subs.Load()
	if cur == nil || userID == "" {
		return
	}
	for _, s := range *cur {
		if s.role == "user" && s.userID == userID {
			s.kick()
		}
	}
}

// dropSubscribersForHost closes live pages whose filter or ownership snapshot
// includes hostID. Unpair must use it: a later owner can reuse the same hostId
// (the registry key is free after deletion), and a stale userHosts/session
// snapshot would otherwise deliver the new owner's events to the old page.
func (h *Hub) dropSubscribersForHost(hostID string) {
	cur := h.subs.Load()
	if cur == nil || hostID == "" {
		return
	}
	for _, s := range *cur {
		stale := s.hostFilter() == hostID || s.allowedHosts[hostID]
		if hosts := s.userHosts.Load(); hosts != nil && (*hosts)[hostID] {
			stale = true
		}
		if stale {
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
