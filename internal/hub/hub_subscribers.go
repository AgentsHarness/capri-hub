package hub

import (
	"sync"
	"sync/atomic"
	"time"
)

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

	// role is "admin", "user" or "guest". userID is the users.json id for a
	// user subscriber. Ordinary users are scoped to their owned hosts;
	// guests are additionally scoped to a session whitelist. The maps are
	// built once at subscribe time and never mutated, so the fan-out path
	// reads them without a lock.
	role         string
	userID       string
	guest        bool
	guestTokenID string
	// userHosts is the live host set for an ordinary user. It is stored
	// behind an atomic pointer so SetSubscriberUserHosts can refresh it
	// without mutating a map the fan-out path is reading.
	userHosts       atomic.Pointer[map[string]bool]
	allowedHosts    map[string]bool
	allowedSessions map[string]bool
	// guestParentOf resolves a subagent child session to the parent that
	// spawned it (see Hub.noteGuestChild). A guest may read a child whose
	// parent is whitelisted — the subagent timeline lives under the child id.
	// Nil for admin subscribers.
	guestParentOf func(hostID, sessionID string) string

	// kicked is closed when the credential behind this subscriber is
	// revoked/deleted, its guest session whitelist changes, or its host is
	// unpaired, so /ws/fe can close the socket immediately instead of
	// waiting for the next request to be rejected.
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
		// Hub-level events: admin pages need all of them. Users only need
		// hosts_changed (it carries no data; their next GET is filtered).
		// Guests render from their access-role snapshot and get none.
		if s.role == "guest" {
			return false
		}
		if s.role == "user" {
			return false
		}
		return true
	}
	if s.role == "guest" && !s.allowedHosts[evHost] {
		return false
	}
	// Admin and user subscribers created through TrySubscribeScopedInfo
	// carry an explicit host set. A generic admin subscriber (tests,
	// compatibility) has none and remains unrestricted.
	if hosts := s.userHosts.Load(); hosts != nil && !(*hosts)[evHost] {
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
	if evHost == "" && s.role == "user" {
		// A user page still needs hosts_changed / prefs_changed to refresh
		// its own registry and prefs. hosts_changed carries no payload;
		// prefs_changed is delivered explicitly by broadcastToUser.
		switch ev["type"] {
		case "hosts_changed":
			return true
		}
		return false
	}
	if !s.watches(evHost) {
		return false
	}
	if s.role != "guest" {
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
// setUserHosts replaces the user's allowed host set. The map is never
// mutated after publication, so fan-out readers stay lock-free.
func (s *feSubscriber) setUserHosts(hosts []string) {
	next := make(map[string]bool, len(hosts))
	for _, id := range hosts {
		if id != "" {
			next[id] = true
		}
	}
	s.userHosts.Store(&next)
}

func (s *feSubscriber) kick() {
	if s.kicked == nil {
		return
	}
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
	ch, unsub, _, ok := h.trySubscribe(max, hostID, nil, nil, nil, info)
	return ch, unsub, ok
}

// TrySubscribeUserInfo is TrySubscribeHost for an ordinary user. allowedHosts
// is a snapshot of the hosts owned by that user at registration; the fan-out
// path uses it to reject events from any other host without taking h.mu.
func (h *Hub) TrySubscribeUserInfo(max int, hostID string, user User, allowedHosts []string, info SubscriberInfo) (
	ch chan Event, unsubscribe func(), kicked <-chan struct{}, ok bool,
) {
	return h.TrySubscribeScopedInfo(max, hostID, user.ID, "user", allowedHosts, info)
}

// TrySubscribeScopedInfo registers a browser subscriber scoped to one
// owner's hosts. Both the admin (scope "root", role "admin") and ordinary
// users use this path; role only affects display/telemetry.
func (h *Hub) TrySubscribeScopedInfo(max int, hostID, scopeID, role string, allowedHosts []string, info SubscriberInfo) (
	ch chan Event, unsubscribe func(), kicked <-chan struct{}, ok bool,
) {
	if role == "" {
		role = "user"
	}
	info.Role = role
	user := User{ID: scopeID}
	ch, unsub, sock, ok := h.trySubscribe(max, hostID, nil, &user, allowedHosts, info)
	if !ok || sock == nil {
		return ch, unsub, nil, ok
	}
	return ch, unsub, sock.kicked, true
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
	ch, unsubscribe, sock, ok := h.trySubscribe(max, hostID, &guest, nil, nil, info)
	if !ok || sock == nil {
		return ch, unsubscribe, nil, ok
	}
	return ch, unsubscribe, sock.kicked, true
}

func (h *Hub) trySubscribe(max int, hostID string, guest *GuestToken, user *User, allowedHosts []string, info SubscriberInfo) (
	ch chan Event, unsubscribe func(), sub *feSubscriber, ok bool,
) {
	// 512 absorbs short FE write stalls; the subscriber's own pump (see
	// feSubscriber) makes the fan-out path never wait on it.
	s := newFeSubscriber(512)
	s.id = h.nextSubID.Add(1)
	s.stats = &h.feStats
	s.connectedAt = nowStamp()
	s.info = info
	s.role = info.Role
	if s.role == "" {
		s.role = "admin"
	}
	// Every subscriber gets a kick channel: role revocation, host
	// reassignment, and guest-session edits all need to close live sockets.
	s.kicked = make(chan struct{})
	if hostID != "" {
		s.host.Store(hostID)
	}
	if user != nil {
		if s.role == "" {
			s.role = "user"
		}
		s.userID = user.ID
		s.setUserHosts(allowedHosts)
	} else if guest != nil {
		s.role = "guest"
		s.guest = true
		s.guestTokenID = guest.ID
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

// SetSubscriberUserHosts refreshes the host set an ordinary user subscriber
// may receive. The FE calls this implicitly through a subscribe frame; the
// snapshot keeps the fan-out path lock-free while still letting a user pair
// its first host without reloading the page.
func (h *Hub) SetSubscriberUserHosts(ch chan Event, hosts []string) bool {
	cur := h.subs.Load()
	if cur == nil {
		return false
	}
	for _, s := range *cur {
		if s.ch == ch && s.role == "user" {
			s.setUserHosts(hosts)
			return true
		}
	}
	return false
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
