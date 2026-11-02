package hub

import (
	"context"
	"encoding/json"
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
	// applies: the up receiver parks at most limits.resumeWindow frames, so
	// the bound the host is told is the bound in force. Shrunk by tests.
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

// requestAckDeadline is how long a relayed request's down frame may stay
// unacked before that request is failed. Delivery is proven by the host's
// cumulative ack, so this is an RPC deadline inside the session, not a
// liveness heuristic: a host that answered is acked, a host that is slow to
// ack is treated as having lost the request.
//
// It is derived from the advertised liveness rather than a fixed second count,
// because it must outlive the retransmit timer: RTO is 2*keepalive, so a
// request frame lost once is replayed at 2*keepalive and only proven one
// heartbeat later. Three keepalives are one RTO plus one heartbeat of margin;
// a shorter deadline would fail requests whose frame a single loss delayed.
//
// Dispatch overrides this with the shorter interactiveAckWindow: a browser
// request prefers a fast 503 over waiting out a retransmit, and the preflight
// probe has already checked the link before the frame is written. Other
// callers get this window.
func requestAckDeadline() time.Duration {
	return 3 * time.Duration(SessionLiveness.Keepalive) * time.Second
}

// downInflightCap bounds the down sender's unacked log. It must comfortably
// hold one maximum relay body plus its own request frame, and is a hard cap:
// the hub closes the session with overflow instead of buffering without limit.
// Derived from limits.maxRelayBody (the cap the hub advertises) so the log
// budget and the relay cap cannot drift apart.
func downInflightCap() int {
	return 2 * SessionLimits.MaxRelayBody
}

var (
	errSessionClosed = errors.New("hub: host session is closed")
	errDownOverflow  = errors.New("hub: down log over budget")
)

// reqAck is one dispatched request whose frame has not been acked yet.
//
// window is how long this request may stay unacked once its frame is on the
// wire: interactive browser requests use a short budget so a prompt that was
// never delivered fails fast, while other callers fall back to the general
// requestAckDeadline. deadline stays zero until the writer completes the
// frame (see noteWritten).
type reqAck struct {
	reqID    string
	window   time.Duration
	deadline time.Time
}

// sessionProto is the protocol state of one (hostId, epoch). It outlives a
// transport so a same-epoch reconnect resumes at the same watermarks, and a
// new epoch replaces it wholesale.
//
// The mutex exists because a superseded session may still be unwinding while
// its replacement already uses the same state on a same-epoch resume; the
// session loop never holds it while calling into Hub (lock order: h.mu →
// proto.mu).
type sessionProto struct {
	mu    sync.Mutex
	epoch uint64
	up    *wire.Receiver
	down  *wire.Sender
	// reqAcks is keyed by the request frame's down seq. Entries are dropped
	// when the seq is acked; a surviving entry past its deadline means the
	// host never confirmed delivery.
	reqAcks map[uint64]reqAck
	// reqAckDeadline is fixed when the sequence space is created, from the
	// liveness advertised for this process (see requestAckDeadline). A
	// same-epoch reconnect reuses it; the advertised liveness does not
	// change inside a run.
	reqAckDeadline time.Duration

	// audienceSeq is the seq of the newest audience frame still in the down
	// log, 0 when there is none. Audience is absolute state: while that frame
	// is unacknowledged every newer snapshot replaces its payload in place
	// instead of appending another entry. audienceGen is the generation the
	// entry currently carries; audienceSentGen is the newest generation of
	// that entry a writer has actually written to a transport. If a replacement
	// lands after the old payload was written, the peer may already have
	// applied it under this seq and will discard a retransmission as a
	// duplicate, so ackDown arms a resend under a fresh seq. audienceLatest is
	// the newest snapshot seen, used for that resend.
	audienceSeq     uint64
	audienceGen     uint64
	audienceSentGen uint64
	audienceLatest  wire.Audience
	audienceResend  *wire.Audience
}

// newSessionProto starts a sequence space. upAcked is the epoch's retired
// high-water baseline declared in hello.resume.up: the host's event bus may be
// past events the hub never saw (the FE rebuilds those from history), so the
// first live event is baseline+1 and everything at or below is a duplicate.
// window is the advertised limits.resumeWindow for the up receiver.
func newSessionProto(epoch, upAcked uint64, window int) *sessionProto {
	return &sessionProto{
		epoch:          epoch,
		up:             wire.NewReceiverWindow(upAcked, window),
		down:           wire.NewSender(0),
		reqAcks:        make(map[uint64]reqAck),
		reqAckDeadline: requestAckDeadline(),
	}
}

func (p *sessionProto) upAcked() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.up.Acked()
}

func (p *sessionProto) downAcked() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.down.Acked()
}

// accept hands one reliable uplink frame to the receiver and returns the
// payloads that became contiguous.
func (p *sessionProto) accept(seq uint64, payload []byte) ([][]byte, uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.up.Accept(seq, payload)
}

// ackDown applies the peer's watermark and forgets the requests it covers. It
// returns the watermark actually in force: Sender.Ack clamps an ack above the
// last assigned seq, because a peer cannot confirm a frame that was never
// sent. Reporting the clamped value keeps the session's own mirror honest —
// recording the raw number would make every later, genuine ack look stale and
// stall the down log for the life of the session.
func (p *sessionProto) ackDown(n uint64) uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.down.Ack(n)
	applied := p.down.Acked()
	for seq := range p.reqAcks {
		if seq <= applied {
			delete(p.reqAcks, seq)
		}
	}
	if p.audienceSeq != 0 && p.audienceSeq <= applied {
		// The ack covers the audience frame, but if its payload was replaced
		// after the last write the peer never saw the newest generation.
		// Reusing the acked seq would be dropped as a duplicate, so queue the
		// latest snapshot for a fresh seq.
		if p.audienceSentGen < p.audienceGen {
			aud := p.audienceLatest
			p.audienceResend = &aud
		}
		p.audienceSeq, p.audienceGen, p.audienceSentGen = 0, 0, 0
	}
	return applied
}

// takeAudienceResend returns a snapshot that must be sent because the payload
// folded into an already-written audience frame was newer than anything the
// peer could have applied. It clears the flag; a no-op read.
func (p *sessionProto) takeAudienceResend() (wire.Audience, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.audienceResend == nil {
		return wire.Audience{}, false
	}
	a := *p.audienceResend
	p.audienceResend = nil
	return a, true
}

// appendReliable assigns the next down seq, stamps the current up watermark,
// encodes the frame and logs it.
func (p *sessionProto) appendReliable(build func(seq, ack uint64) wire.Frame) (uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	seq := p.down.Next() + 1
	payload, err := wire.Encode(build(seq, p.up.Acked()))
	if err != nil {
		return 0, err
	}
	if got := p.down.Append(payload); got != seq {
		return 0, errors.New("hub: down seq assignment drifted")
	}
	if p.down.Bytes() > downInflightCap() {
		return seq, errDownOverflow
	}
	return seq, nil
}

// dispatchRequest appends a relay request and records its reqId atomically with
// the append, so an ack racing the dispatch can never leave a phantom entry
// behind. The ack deadline stays zero until the writer has written the frame:
// a request stuck behind a slow socket must not time out before the host could
// possibly have seen it.
func (p *sessionProto) dispatchRequest(reqID string, f wire.Frame, window time.Duration) (uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	seq := p.down.Next() + 1
	f.Seq = seq
	f.Ack = p.up.Acked()
	payload, err := wire.Encode(f)
	if err != nil {
		return 0, err
	}
	if got := p.down.Append(payload); got != seq {
		return 0, errors.New("hub: down seq assignment drifted")
	}
	p.reqAcks[seq] = reqAck{reqID: reqID, window: window}
	if p.down.Bytes() > downInflightCap() {
		return seq, errDownOverflow
	}
	return seq, nil
}

// noteWritten arms the request ack deadline for the frame at seq, or re-arms it
// after a retransmission. It is called by the writer only after the complete
// logical frame reached the transport, which is the moment the host may
// actually have seen it. For an audience frame it also records the generation
// that was actually written: a later payload replacement under the same seq
// must not pretend the newer snapshot reached the host.
//
// A replay while the current deadline is still in force does not extend it: the
// deadline is an upper bound of 3*keepalive on unacked delivery, and RTO is
// 2*keepalive, so extending on every replay would let a host that never acks
// postpone its own failure forever. A replay that completes after the deadline
// (the writer was blocked) starts a fresh window, because only then did a new
// copy actually reach the wire.
func (p *sessionProto) noteWritten(seq uint64, payload []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if seq != 0 && seq == p.audienceSeq {
		if f, err := wire.Decode(payload); err == nil && f.Type == wire.TypeAudience && f.Gen > p.audienceSentGen {
			p.audienceSentGen = f.Gen
		}
	}
	ra, ok := p.reqAcks[seq]
	if !ok {
		return
	}
	now := time.Now()
	if ra.deadline.IsZero() || !now.Before(ra.deadline) {
		window := ra.window
		if window <= 0 {
			window = p.reqAckDeadline
		}
		ra.deadline = now.Add(window)
		p.reqAcks[seq] = ra
	}
}

// entriesAfter returns the unacked log entries above seq.
func (p *sessionProto) entriesAfter(seq uint64) []wire.Entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []wire.Entry
	for _, e := range p.down.Entries() {
		if e.Seq > seq {
			out = append(out, e)
		}
	}
	return out
}

// entry returns the unacked log entry for seq, if it is still present.
func (p *sessionProto) entry(seq uint64) (wire.Entry, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.down.Entry(seq)
}

// entries returns the whole unacked log, in seq order.
func (p *sessionProto) entries() []wire.Entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.down.Entries()
}

func (p *sessionProto) downLen() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.down.Len()
}

func (p *sessionProto) hasUnacked() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.down.Len() > 0
}

// nextRequestDeadline is the earliest armed ack deadline still outstanding. A
// request whose frame has not been written yet has no deadline and cannot make
// the session loop spin.
func (p *sessionProto) nextRequestDeadline() (time.Time, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out time.Time
	for _, ra := range p.reqAcks {
		if ra.deadline.IsZero() {
			continue
		}
		if out.IsZero() || ra.deadline.Before(out) {
			out = ra.deadline
		}
	}
	return out, !out.IsZero()
}

// expireRequests drops requests whose frame was never acked by now and reports
// their reqIds, so the session can fail them without holding proto.mu.
func (p *sessionProto) expireRequests(now time.Time) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for seq, ra := range p.reqAcks {
		if ra.deadline.IsZero() || now.Before(ra.deadline) {
			continue
		}
		out = append(out, ra.reqID)
		delete(p.reqAcks, seq)
	}
	return out
}

// oldestUnacked returns at most max entries of the unacked log above the acked
// watermark, capped by bytes. An RTO replays this batch instead of the whole
// log: one lost frame must not cost a full replay of everything in flight.
func (p *sessionProto) oldestUnacked(max, maxBytes int) []wire.Entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	acked := p.down.Acked()
	var (
		out   []wire.Entry
		bytes int
	)
	for _, e := range p.down.Entries() {
		if e.Seq <= acked {
			continue
		}
		if len(out) >= max || (len(out) > 0 && bytes+len(e.Payload) > maxBytes) {
			break
		}
		out = append(out, e)
		bytes += len(e.Payload)
	}
	return out
}

// session is one attached host transport. Its loop owns every read and every
// timer; the hub reaches it through dispatch / pushAudience, which only append
// to the down log and wake the loop. Socket writes belong to the writer
// goroutine, so a wedged write cannot stall reads, timers or ingestion.
type session struct {
	h         *Hub
	hostID    string
	epoch     uint64
	proto     *sessionProto
	transport Transport
	writer    atomic.Pointer[writer]
	// deflate is the downlink compression capability echoed at handshake.
	deflate bool

	wake chan struct{}
	stop chan struct{}
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

// relayProbe is one outstanding preflight probe. done closes exactly once;
// ok is read after done is closed.
type relayProbe struct {
	nonce uint64
	ok    atomic.Bool
	done  chan struct{}
	once  sync.Once
}

func (g *relayProbe) succeed() {
	g.ok.Store(true)
	g.once.Do(func() { close(g.done) })
}

func (g *relayProbe) fail() { g.once.Do(func() { close(g.done) }) }

// wait blocks until the probe is answered, the caller gives up, the timeout
// fires, or the session ends.
func (g *relayProbe) wait(ctx context.Context, stop <-chan struct{}, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-g.done:
		if g.ok.Load() {
			return nil
		}
		return errRelayProbe
	case <-ctx.Done():
		return ctx.Err()
	case <-stop:
		return errSessionClosed
	case <-timer.C:
		return errRelayProbe
	}
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

// dispatch appends one relay request to the down log and wakes the loop.
// window is the per-request ack budget armed when the writer completes the
// frame (0 falls back to the session's general requestAckDeadline).
func (s *session) dispatch(reqID, method, path string, body []byte, window time.Duration) error {
	if s.finished.Load() {
		return errSessionClosed
	}
	f := wire.Frame{V: wire.ProtocolVersion, Type: wire.TypeRequest, ReqID: reqID, Method: method, Path: path}
	if len(body) > 0 {
		f.Body = body
	}
	if _, err := s.proto.dispatchRequest(reqID, f, window); err != nil {
		if errors.Is(err, errDownOverflow) {
			s.requestStop(wire.CloseOverflow)
		}
		return err
	}
	s.signal()
	return nil
}

// pushAudience logs one absolute audience snapshot, replacing the payload of
// the single unacknowledged audience frame when there is one. Keeping the seq
// stable retains a gapless log; replacing rather than appending keeps a burst
// of viewer changes from filling the down log with obsolete generations.
// replaced reports that an existing entry's payload changed, so the session
// can ask the writer to put the new snapshot on the wire even though its seq is
// at or below the writer's progress watermark.
func (p *sessionProto) pushAudience(a wire.Audience) (seq uint64, replaced bool, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if a.Gen < p.audienceLatest.Gen {
		// A snapshot minted before one already pushed arrived late; it can
		// never move the absolute state backwards.
		return 0, false, nil
	}
	p.audienceLatest = a
	// A newer snapshot supersedes a queued post-ack resend.
	p.audienceResend = nil
	if p.audienceSeq != 0 && p.audienceSeq <= p.down.Acked() {
		// Ack bookkeeping normally clears this; guard against a stale seq if
		// it was advanced elsewhere.
		p.audienceSeq, p.audienceGen, p.audienceSentGen = 0, 0, 0
	}
	if p.audienceSeq != 0 {
		if a.Gen <= p.audienceGen {
			return p.audienceSeq, false, nil
		}
		seq := p.audienceSeq
		payload, err := wire.Encode(wire.NewAudience(seq, p.up.Acked(), a))
		if err != nil {
			return 0, false, err
		}
		if err := p.down.Elide(seq, payload); err == nil {
			p.audienceGen = a.Gen
			if p.down.Bytes() > downInflightCap() {
				return seq, false, errDownOverflow
			}
			return seq, true, nil
		}
		// The entry vanished between the ack check and Elide; fall through to
		// appending rather than losing the snapshot.
		p.audienceSeq, p.audienceGen, p.audienceSentGen = 0, 0, 0
	}
	seq = p.down.Next() + 1
	payload, err := wire.Encode(wire.NewAudience(seq, p.up.Acked(), a))
	if err != nil {
		return 0, false, err
	}
	if got := p.down.Append(payload); got != seq {
		return 0, false, errors.New("hub: down seq assignment drifted")
	}
	p.audienceSeq = seq
	p.audienceGen = a.Gen
	p.audienceSentGen = 0
	if p.down.Bytes() > downInflightCap() {
		return seq, false, errDownOverflow
	}
	return seq, false, nil
}

// pushAudience appends or updates the one absolute audience snapshot.
func (s *session) pushAudience(a wire.Audience) error {
	if s.finished.Load() {
		return errSessionClosed
	}
	seq, replaced, err := s.proto.pushAudience(a)
	if err != nil {
		if errors.Is(err, errDownOverflow) {
			s.requestStop(wire.CloseOverflow)
		}
		return err
	}
	if replaced {
		if w := s.writer.Load(); w != nil {
			w.rewrite(seq)
		}
	}
	s.signal()
	return nil
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
	// Transport units are mandatory in v2: every downlink frame may arrive as
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

// finish detaches the session from the registry exactly once and fails the
// relayed requests that were waiting on it (unless a newer session of the same
// host already took over).
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
		if d, ok := s.proto.nextRequestDeadline(); ok && d.Before(next) {
			next = d
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
			for _, reqID := range s.proto.expireRequests(now) {
				log.Printf("[capri-hub] host %s: request %s not acked within %s", s.hostID, reqID, s.proto.reqAckDeadline)
				s.h.failRequest(s.hostID, reqID, 503, "host 未确认中继请求")
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

// handleFrame applies one decoded frame and returns a close reason when the
// session must end.
func (s *session) handleFrame(data []byte) wire.CloseReason {
	f, err := wire.Decode(data)
	if err != nil {
		log.Printf("[capri-hub] host %s: bad frame: %v", s.hostID, err)
		if errors.Is(err, wire.ErrProtocol) {
			return wire.CloseProtocol
		}
		return wire.CloseUnreadable
	}
	// A frame's ack is the peer's watermark over this direction's reliable
	// log; it is applied before the payload so a respond can never be
	// processed as "not delivered".
	if f.Ack > s.lastDownAck {
		s.lastDownAck = s.proto.ackDown(f.Ack)
		// A newer audience snapshot folded into the acked seq after that
		// frame was written never reached the peer. Send it under a fresh
		// seq now; the receiver would drop a duplicate seq as already
		// applied.
		if aud, ok := s.proto.takeAudienceResend(); ok {
			if err := s.pushAudience(aud); err != nil {
				if errors.Is(err, errDownOverflow) {
					return wire.CloseOverflow
				}
				log.Printf("[capri-hub] host %s: audience resend: %v", s.hostID, err)
			}
		}
	}
	// Any frame from the host proves the link is live and moves the registry
	// freshness stamp /api/hosts exposes. No hosts_changed: this is per-frame
	// bookkeeping, not a registry transition.
	s.probePending = false
	s.lastFrameAt.Store(time.Now().UnixNano())
	s.h.touchHost(s.hostID)
	switch f.Type {
	case wire.TypeEvents:
		return s.handleEvents(data, f)
	case wire.TypeRespond:
		return s.handleRespond(f)
	case wire.TypeHeartbeat:
		return s.handleHeartbeat(f)
	default:
		// request / audience / hello are hub→host frames. A host sending one
		// is speaking a different protocol.
		return wire.CloseProtocol
	}
}

// handleEvents feeds a reliable events frame through the receiver. The
// session seq space IS the event seq space: a batch advances the watermark by
// one per event, so the next frame continues from the last event's seq. Frames
// that arrive ahead of a gap are parked one event at a time; filling the gap
// releases them all in order, and the bodies are applied without decode /
// re-encode on the fan-out path.
func (s *session) handleEvents(raw []byte, f wire.Frame) wire.CloseReason {
	var (
		ready [][]byte
		ack   uint64
	)
	for i, body := range f.Events {
		seq := f.Seq + uint64(i)
		r, a, err := s.proto.accept(seq, body)
		switch {
		case errors.Is(err, wire.ErrOverflow):
			log.Printf("[capri-hub] host %s: resume window overflow at seq %d", s.hostID, seq)
			return wire.CloseOverflow
		case err != nil:
			return wire.CloseUnreadable
		}
		ready = append(ready, r...)
		ack = a
	}
	if len(ready) > 0 {
		raws := make([]json.RawMessage, len(ready))
		for i, b := range ready {
			raws[i] = b
		}
		if !s.h.ingestRawEvents(s, raws) {
			// A newer session took the host over while these events were
			// parked: they belong to a dead epoch and must not be applied.
			log.Printf("[capri-hub] host %s: superseded session dropped late events", s.hostID)
			return wire.CloseSuperseded
		}
	}
	if ack > s.lastAckSent {
		s.h.noteUpAck(s, ack)
		s.lastAckSent = ack
		// Confirm immediately so the host can drop its replay copies instead
		// of waiting for the next heartbeat tick.
		if reason := s.sendHeartbeat(); reason != 0 {
			return reason
		}
	}
	return 0
}

// handleRespond applies one answer frame in the relay plane's chunk order.
// A frame that advances the per-request ack or ends the request triggers an
// immediate hb, so the host learns what it may drop without waiting for the
// next heartbeat tick.
func (s *session) handleRespond(f wire.Frame) wire.CloseReason {
	known, notify := s.h.acceptRespond(s.hostID, f)
	if !known {
		log.Printf("[capri-hub] host %s: respond for unknown reqId %s", s.hostID, f.ReqID)
	}
	if notify {
		return s.sendHeartbeat()
	}
	return 0
}

func (s *session) handleHeartbeat(f wire.Frame) wire.CloseReason {
	// A host probe is answered immediately through the control slot; it rides
	// the same latest-wins channel as the periodic hb so a busy writer never
	// accumulates a backlog of probes.
	if f.Probe != 0 {
		if reason := s.sendProbeAck(f.Probe); reason != 0 {
			return reason
		}
	}
	if f.ProbeAck != 0 {
		s.probePending = false
		s.completeProbe(f.ProbeAck)
	}
	st, err := f.Heartbeat()
	if err != nil {
		return wire.CloseProtocol
	}
	s.h.UpdateHostStatus(s.hostID, HostStatusPatch{
		Ready:        &st.Ready,
		Busy:         &st.Busy,
		Booting:      &st.Booting,
		PendingCount: &st.PendingCount,
		Port:         &st.Port,
	})
	return 0
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
