package hub

import (
	"context"
	"errors"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AgentsHarness/capri-hub/wire"
)

// Transport is one attached host link. The session calls Recv from a single
// reader goroutine; a session's writer goroutine owns Send and SendFragment,
// and Close may be called from any goroutine and MUST unblock both.
//
// Send writes one complete logical frame. SendFragment writes one encoded
// wire transport unit, which carries either a whole frame or one slice of a
// fragmented one. SetWriteTimeout and SetMaxFrame are applied once at
// handshake, from the advertised liveness and limits. LastActivity reports
// the last time the transport read anything from the peer; it never covers
// writes, so a blackhole is not hidden by our own heartbeats.
type Transport interface {
	Send([]byte) error
	SendFragment([]byte) error
	Recv() ([]byte, error)
	Close(wire.CloseReason) error
	SetKeepalive(time.Duration)
	SetWriteTimeout(time.Duration)
	SetMaxFrame(int)
	LastActivity() time.Time
}

// deflateSetter is the optional capability a transport exposes when its wire
// can carry raw-deflate frames. It is applied only after hello_ack echoed
// hello.caps.deflate; a compressed frame before that echo is a protocol
// violation the transport rejects.
type deflateSetter interface{ SetDeflate(bool) }

var (
	// HandshakeTimeout bounds how long a freshly opened transport may stay
	// silent before the session is closed with liveness. Without it an idle
	// TCP connection would hold a reader goroutine and read no hello forever.
	HandshakeTimeout = 10 * time.Second

	// SessionLiveness is the time scale advertised in hello_ack. The wire
	// defaults are the production values; tests shrink it to exercise the
	// idle / retransmit paths without waiting.
	SessionLiveness = wire.DefaultLiveness

	// SessionLimits is what hello_ack advertises and what the hub itself
	// applies. Shrunk by tests.
	SessionLimits = wire.DefaultLimits

	// probeAfter is how long the hub lets the host stay silent before it
	// sends an hb liveness probe, and probeTimeout is how long the probe may
	// stay unanswered before the session closes with liveness. They default
	// to the shared wire constants; tests shrink them to exercise the path.
	probeAfter   = wire.ProbeAfter
	probeTimeout = wire.ProbeTimeout

	// relayHealthWindow is how recently the session must have received a
	// frame for Dispatch to trust the link without a preflight round trip.
	// relayProbeTimeout bounds that probe: a host that cannot answer in this
	// window is reported as reconnecting instead of receiving a request that
	// would likely never run to completion.
	relayHealthWindow = 2 * time.Second
	relayProbeTimeout = 1500 * time.Millisecond
)

// errRelayProbe reports that the fast liveness preflight did not get a
// matching probeAck in time.
var errRelayProbe = errors.New("hub: relay preflight probe failed")

// downInflightCap bounds the down sender's unacked request log. It must
// comfortably hold one maximum relay body plus its own request frame, and is a
// hard cap: the hub closes the session with overflow instead of buffering
// without limit. Derived from limits.maxRelayBody (the cap the hub advertises)
// so the log budget and the relay cap cannot drift apart. Audience is not in
// this log, so it can never overflow it.
func downInflightCap() int {
	return 2 * SessionLimits.MaxRelayBody
}

var (
	errSessionClosed = errors.New("hub: host session is closed")
	errDownOverflow  = errors.New("hub: down log over budget")
)

// session is one attached host transport. Its loop owns every read and every
// timer; the hub reaches it through dispatch, which appends to the down log, and
// pushAudience, which only posts absolute state. Neither writes the socket:
// writes belong to the writer goroutine, so a wedged write cannot stall reads,
// timers or ingestion.
type session struct {
	h         *Hub
	hostID    string
	epoch     uint64
	proto     *sessionProto
	transport Transport
	writer    atomic.Pointer[writer]
	// deflate is the downlink compression capability echoed at handshake.
	deflate bool

	// audiencePayload is the newest snapshot posted on this session, nil
	// before the first one. pushAudience runs on the hub's goroutines; the
	// loop reads it under the same mutex to refresh it on a heartbeat.
	audienceMu      sync.Mutex
	audiencePayload []byte

	wake   chan struct{}
	notify chan struct{}
	stop   chan struct{}
	// stopReason is the reason requestStop was called with; 0 means the loop
	// is still deciding for itself.
	stopReason atomic.Uint32
	stopOnce   sync.Once
	finished   atomic.Bool

	// Loop-owned link state: the last watermarks exchanged on THIS transport.
	lastDownAck uint64
	lastAckSent uint64

	// Liveness probe state, loop-owned. A probe is outstanding from the moment
	// it is posted to the writer until any frame (or its probeAck) arrives.
	probeNonce    uint64
	probePending  bool
	probeDeadline time.Time

	// lastFrameAt is the wall time of the last frame the session decoded. It
	// feeds Dispatch's preflight freshness check; it never counts our own
	// writes, so a silent peer still looks silent.
	lastFrameAt atomic.Int64

	// Preflight probe state. One probe is outstanding at a time; concurrent
	// Dispatch callers join its wait group instead of each writing an hb.
	probeMu    sync.Mutex
	probeGroup *relayProbe
	probeSeq   uint64
}

// healthy reports whether a frame arrived within window.
func (s *session) healthy(window time.Duration) bool {
	last := s.lastFrameAt.Load()
	if last == 0 {
		return false
	}
	return time.Since(time.Unix(0, last)) < window
}

// probe sends hb{probe:N} through the writer's control slot and waits for the
// matching probeAck. Concurrent callers share one outstanding probe: the first
// sends it, the rest wait on the same result. A nil return means the link
// answered; any error means no request should be dispatched on it.
func (s *session) probe(ctx context.Context, timeout time.Duration) error {
	if s.finished.Load() {
		return errSessionClosed
	}

	s.probeMu.Lock()
	if g := s.probeGroup; g != nil {
		s.probeMu.Unlock()
		return g.wait(ctx, s.stop, timeout)
	}
	s.probeSeq++
	g := &relayProbe{nonce: s.probeSeq, done: make(chan struct{})}
	s.probeGroup = g
	s.probeMu.Unlock()

	// The caller that owns the group clears it and fails every joiner if the
	// probe did not complete. A success is published by completeProbe, which
	// clears the slot before waking the waiters.
	defer func() {
		s.probeMu.Lock()
		if s.probeGroup == g {
			s.probeGroup = nil
		}
		s.probeMu.Unlock()
		g.fail()
	}()

	f, err := wire.NewHeartbeatProbe(s.proto.upAcked(), g.nonce, s.h.heartbeatStatus(s.hostID), false)
	if err != nil {
		return errRelayProbe
	}
	f.RelayAcks = s.h.relayAcks(s.hostID)
	if reason := s.postControl(f); reason != 0 {
		return errSessionClosed
	}
	return g.wait(ctx, s.stop, timeout)
}

// completeProbe resolves the outstanding preflight probe whose nonce the host
// echoed. A stale ack (the probe already timed out) is ignored.
func (s *session) completeProbe(nonce uint64) {
	s.probeMu.Lock()
	g := s.probeGroup
	if g != nil && g.nonce == nonce {
		s.probeGroup = nil
	}
	s.probeMu.Unlock()
	if g != nil && g.nonce == nonce {
		g.succeed()
	}
}

func (s *session) requestStop(r wire.CloseReason) {
	s.stopReason.Store(uint32(r))
	s.stopOnce.Do(func() { close(s.stop) })
}

func (s *session) closeReason() wire.CloseReason {
	if r := wire.CloseReason(s.stopReason.Load()); r.Valid() {
		return r
	}
	return wire.CloseNormal
}

func (s *session) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// notifyAckTable asks the session loop to push a heartbeat now. Relay aborts
// live in the ack table, so failing a request must not wait for the next
// periodic heartbeat: the host may otherwise execute a prompt the browser has
// already been told failed.
func (s *session) notifyAckTable() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// ServeHost runs one host transport to its end and closes it with the reason it
// ended for. ExpectedHostID is the host the transport was authenticated as
// before the upgrade ("" when the hello's token is the only identity, as on
// QUIC); when set, hello.token must resolve to it.
func (h *Hub) ServeHost(expectedHostID string, t Transport) wire.CloseReason {
	reason := h.serveHost(expectedHostID, t)
	if err := t.Close(reason); err != nil {
		Verbosef("[capri-hub] host %s: close(%s): %v", expectedHostID, reason, err)
	}
	return reason
}

func (h *Hub) serveHost(expected string, t Transport) wire.CloseReason {
	reader, stopReader := readFrames(t)
	defer stopReader()

	first, ok := awaitFrame(reader)
	if !ok {
		return wire.CloseLiveness
	}
	if first.err != nil {
		if errors.Is(first.err, wire.ErrUnreadable) {
			log.Printf("[capri-hub] host %s: unreadable handshake: %v", expected, first.err)
			return wire.CloseUnreadable
		}
		return wire.CloseNormal
	}
	hello, reason := decodeHello(first.data)
	if reason != 0 {
		log.Printf("[capri-hub] host %s: bad hello (%s)", expected, reason)
		return reason
	}
	// Transport units are mandatory in v3: every downlink frame may arrive as
	// fragments, and a peer that cannot reassemble them cannot run a session.
	if hello.Caps == nil || !hello.Caps.TransportUnits {
		log.Printf("[capri-hub] host %s: hello without caps.transportUnits", expected)
		return wire.CloseProtocol
	}
	hostID, ok := h.HostIDForToken(hello.Token)
	if !ok || (expected != "" && expected != hostID) {
		log.Printf("[capri-hub] host %s: hello token rejected", expected)
		return wire.CloseAuth
	}

	deflate := hello.Caps.Deflate
	if ds, ok := t.(deflateSetter); ok {
		ds.SetDeflate(deflate)
	}
	keepalive := time.Duration(SessionLiveness.Keepalive) * time.Second
	idle := time.Duration(SessionLiveness.Idle) * time.Second
	t.SetKeepalive(keepalive)
	// A write may not outlive the idle verdict: the writer is allowed to be
	// slow, but never so slow that a peer already declared dead still holds a
	// socket write open.
	t.SetWriteTimeout(idle * 3 / 4)
	t.SetMaxFrame(SessionLimits.MaxFrame)
	// QUIC request streams are accepted only now that hello's token has been
	// verified. Starting them in newQUICTransport allowed an unauthenticated
	// peer to fill the 64-slot frame queue with 32MB request frames before
	// authentication. Other transports do not implement this hook.
	if starter, ok := t.(interface{ StartRequestStreams() }); ok {
		starter.StartRequestStreams()
	}

	s, old, ack, err := h.attach(hostID, hello.Epoch, hello.Resume.Up, hello.Resume.Down, deflate)
	if err != nil {
		log.Printf("[capri-hub] host %s: attach: %v", hostID, err)
		if errors.Is(err, ErrHostUnknown) {
			return wire.CloseAuth
		}
		return wire.CloseProtocol
	}
	s.transport = t
	s.deflate = deflate
	if old != nil {
		// The new transport owns the down log now; the old loop exits on stop
		// and its ServeHost closes the old transport.
		old.requestStop(wire.CloseSuperseded)
	}
	ackPayload, err := wire.Encode(wire.NewHelloAck(ack))
	if err != nil {
		s.finish(wire.CloseProtocol)
		return wire.CloseProtocol
	}
	log.Printf("[capri-hub] host %s attached (epoch %d, audience gen %d)", hostID, hello.Epoch, ack.Audience.Gen)
	reason = s.run(reader, ackPayload)
	s.finish(reason)
	log.Printf("[capri-hub] host %s detached (epoch %d, %s)", hostID, hello.Epoch, reason)
	return reason
}

// finish detaches the session from the registry exactly once. Pending relayed
// requests are left to Hub.detach's grace timer (unless a newer session of the
// same host already took over).
func (s *session) finish(reason wire.CloseReason) {
	if !s.finished.CompareAndSwap(false, true) {
		return
	}
	s.requestStop(reason)
	s.h.detach(s)
}

// run is the one session loop: read frames, apply them, schedule heartbeats
// and probes, and enforce idle. Socket writes run on the session's writer
// goroutine, so a blocked write delays output but never this loop. It returns
// the close reason.
func (s *session) run(reader <-chan readResult, helloAck []byte) wire.CloseReason {
	if err := s.transport.Send(helloAck); err != nil {
		log.Printf("[capri-hub] host %s: hello_ack write: %v", s.hostID, err)
		return wire.CloseNormal
	}
	keepalive := time.Duration(SessionLiveness.Keepalive) * time.Second
	idle := time.Duration(SessionLiveness.Idle) * time.Second
	rto := 2 * keepalive

	s.lastDownAck = s.proto.downAcked()
	s.lastAckSent = s.proto.upAcked()

	w := newWriter(s, s.transport, s.deflate)
	s.writer.Store(w)
	w.start()
	// A snapshot posted between attach and this point had no writer to take
	// it; hello_ack carried the initial one, so only a later change is here.
	s.refreshAudience()

	// A same-epoch resume must replay the entries this transport has not
	// carried yet; they were appended before this link existed.
	if reason := s.flushNew(); reason != 0 {
		return reason
	}

	lastRecv := time.Now()
	nextHB := lastRecv.Add(keepalive)
	rtoAt := lastRecv.Add(rto)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()

	for {
		frameClock := lastRecv
		if a := s.transport.LastActivity(); a.After(frameClock) {
			frameClock = a
		}
		next := nextHB
		if d := frameClock.Add(idle); d.Before(next) {
			next = d
		}
		if s.probePending {
			if s.probeDeadline.Before(next) {
				next = s.probeDeadline
			}
		} else if d := lastRecv.Add(probeAfter); d.Before(next) {
			next = d
		}
		if s.proto.hasUnacked() && rtoAt.Before(next) {
			next = rtoAt
		}
		resetTimer(timer, time.Until(next))

		select {
		case <-s.stop:
			return s.closeReason()

		case r, open := <-reader:
			if !open {
				return wire.CloseNormal
			}
			if r.err != nil {
				if errors.Is(r.err, wire.ErrUnreadable) {
					log.Printf("[capri-hub] host %s: unreadable uplink frame: %v", s.hostID, r.err)
					return wire.CloseUnreadable
				}
				return wire.CloseNormal
			}
			lastRecv = time.Now()
			prevDownAck := s.lastDownAck
			if reason := s.handleFrame(r.data); reason != 0 {
				return reason
			}
			// Ack progress resets the RTO. Without this a frame that was
			// already in flight before the ack would still be retransmitted
			// on the old schedule, wasting the peer's ack.
			if s.lastDownAck > prevDownAck {
				rtoAt = time.Now().Add(rto)
			}
			if reason := s.flushNew(); reason != 0 {
				return reason
			}

		case <-s.wake:
			if reason := s.flushNew(); reason != 0 {
				return reason
			}

		case <-s.notify:
			// Push a fresh ack table immediately (relay abort/done) instead
			// of waiting for the next periodic heartbeat.
			if reason := s.sendHeartbeat(); reason != 0 {
				return reason
			}

		case <-w.progress:
			// A completed write means bytes are moving again; restart the
			// retransmit clock instead of replaying a frame that just left.
			rtoAt = time.Now().Add(rto)

		case <-timer.C:
			now := time.Now()
			// Probe escalation runs ahead of idle: silence gets one cheap
			// round-trip before the session is declared dead.
			if s.probePending {
				if !now.Before(s.probeDeadline) {
					log.Printf("[capri-hub] host %s: no probe ack for %s, closing session", s.hostID, probeTimeout)
					return wire.CloseLiveness
				}
			} else if !now.Before(lastRecv.Add(probeAfter)) {
				if reason := s.sendProbe(now); reason != 0 {
					return reason
				}
			}
			if !now.Before(nextHB) {
				if reason := s.sendHeartbeat(); reason != 0 {
					return reason
				}
				// Audience has no ack and no retransmit entry: the periodic
				// tick repeats the newest snapshot so a lost frame self-heals.
				s.refreshAudience()
				nextHB = now.Add(keepalive)
			}
			if s.proto.hasUnacked() && !now.Before(rtoAt) {
				// The writer is already moving bytes; a replay would queue
				// behind the frame it is trying to replace.
				if w.Busy() {
					rtoAt = now.Add(rto)
				} else {
					if reason := s.retransmit(); reason != 0 {
						return reason
					}
					rtoAt = now.Add(rto)
				}
			}
			frameClock := lastRecv
			if a := s.transport.LastActivity(); a.After(frameClock) {
				frameClock = a
			}
			if now.Sub(frameClock) >= idle {
				log.Printf("[capri-hub] host %s: no frame for %s, closing session", s.hostID, idle)
				return wire.CloseLiveness
			}
		}
	}
}

func resetTimer(t *time.Timer, d time.Duration) {
	if d < 0 {
		d = 0
	}
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

func (s *session) stopped() bool {
	select {
	case <-s.stop:
		return true
	default:
		return false
	}
}

// flushNew hands the down log to the writer. It never writes: the writer
// goroutine pulls the entries this transport has not carried yet.
func (s *session) flushNew() wire.CloseReason {
	if s.stopped() {
		// A superseded link must not write frames the new link owns; entries
		// appended after the handover belong to the replacement.
		return s.closeReason()
	}
	if w := s.writer.Load(); w != nil {
		w.kick()
	}
	return 0
}

// retransmit asks the writer to replay the oldest unacked batch. The writer
// owns the socket, so this only signals it; the batch is bounded so a lost
// frame never costs a replay of the whole in-flight log.
func (s *session) retransmit() wire.CloseReason {
	if s.stopped() {
		return s.closeReason()
	}
	w := s.writer.Load()
	if w == nil {
		return s.closeReason()
	}
	w.retransmit()
	return 0
}

// sendHeartbeat builds the periodic hb and posts it to the writer's
// latest-wins control slot. While a probe is outstanding the hb carries the
// same nonce again, so a heartbeat queued behind the probe cannot erase it.
func (s *session) sendHeartbeat() wire.CloseReason {
	var (
		f   wire.Frame
		err error
	)
	if s.probePending {
		f, err = wire.NewHeartbeatProbe(s.proto.upAcked(), s.probeNonce, s.h.heartbeatStatus(s.hostID), false)
	} else {
		f, err = wire.NewHeartbeat(s.proto.upAcked(), s.h.heartbeatStatus(s.hostID))
	}
	if err != nil {
		return wire.CloseProtocol
	}
	f.RelayAcks = s.h.relayAcks(s.hostID)
	return s.postControl(f)
}

// sendProbe posts a fresh liveness probe and arms its deadline.
func (s *session) sendProbe(now time.Time) wire.CloseReason {
	if s.probeNonce == 0 {
		s.probeNonce = uint64(now.UnixNano()) | 1
	} else {
		s.probeNonce++
	}
	f, err := wire.NewHeartbeatProbe(s.proto.upAcked(), s.probeNonce, s.h.heartbeatStatus(s.hostID), false)
	if err != nil {
		return wire.CloseProtocol
	}
	f.RelayAcks = s.h.relayAcks(s.hostID)
	if reason := s.postControl(f); reason != 0 {
		return reason
	}
	s.probePending = true
	s.probeDeadline = now.Add(probeTimeout)
	return 0
}

// sendProbeAck echoes a host probe nonce immediately.
func (s *session) sendProbeAck(nonce uint64) wire.CloseReason {
	f, err := wire.NewHeartbeatProbe(s.proto.upAcked(), nonce, s.h.heartbeatStatus(s.hostID), true)
	if err != nil {
		return wire.CloseProtocol
	}
	f.RelayAcks = s.h.relayAcks(s.hostID)
	return s.postControl(f)
}

func (s *session) postControl(f wire.Frame) wire.CloseReason {
	payload, err := wire.Encode(f)
	if err != nil {
		return wire.CloseProtocol
	}
	w := s.writer.Load()
	if w == nil {
		return s.closeReason()
	}
	w.postControl(payload)
	return 0
}

// ── handshake plumbing ────────────────────────────────────────────────

type readResult struct {
	data []byte
	err  error
}

// readFrames runs the transport's blocking Recv on one goroutine and hands
// each frame to the session loop. stop must be called before the transport is
// closed so a reader parked on its send cannot outlive the session.
func readFrames(t Transport) (<-chan readResult, func()) {
	out := make(chan readResult, 8)
	quit := make(chan struct{})
	go func() {
		defer close(out)
		for {
			b, err := t.Recv()
			select {
			case out <- readResult{data: b, err: err}:
			case <-quit:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	var once sync.Once
	return out, func() { once.Do(func() { close(quit) }) }
}

// awaitFrame waits for the first frame of a fresh transport.
func awaitFrame(reader <-chan readResult) (readResult, bool) {
	timer := time.NewTimer(HandshakeTimeout)
	defer timer.Stop()
	select {
	case r, ok := <-reader:
		return r, ok
	case <-timer.C:
		return readResult{}, false
	}
}

// decodeHello validates the first frame. It returns a non-zero close reason
// when the peer is not speaking this protocol.
func decodeHello(data []byte) (wire.Hello, wire.CloseReason) {
	f, err := wire.Decode(data)
	if err != nil {
		if errors.Is(err, wire.ErrProtocol) {
			return wire.Hello{}, wire.CloseProtocol
		}
		return wire.Hello{}, wire.CloseUnreadable
	}
	if f.Type != wire.TypeHello {
		return wire.Hello{}, wire.CloseProtocol
	}
	hello, err := f.Hello()
	if err != nil {
		return wire.Hello{}, wire.CloseProtocol
	}
	return hello, 0
}
