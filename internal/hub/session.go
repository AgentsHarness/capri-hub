package hub

import (
	"encoding/json"
	"errors"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AgentsHarness/capri-wire"
)

// Transport is one attached host link. The session calls Recv from a single
// reader goroutine and Send / SetKeepalive from its own goroutine. Close may be
// called from any goroutine and MUST unblock Recv, which is how a superseded
// link is torn down.
type Transport interface {
	Send([]byte) error
	Recv() ([]byte, error)
	Close(wire.CloseReason) error
	SetKeepalive(time.Duration)
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

	// RequestAckTimeout is how long a relayed request's down frame may stay
	// unacked before that request is failed. Delivery is proven by the host's
	// cumulative ack, so this is an RPC deadline inside the session, not a
	// liveness heuristic: a host that answered is acked, a host that is slow
	// to ack is treated as having lost the request. A var so tests can shrink
	// it.
	RequestAckTimeout = 6 * time.Second
)

// maxDownInflight bounds the down sender's unacked log. It must comfortably
// hold one maximum relay body plus its own request frame, and is a hard cap:
// the hub closes the session with overflow instead of buffering without limit.
// A var so tests can shrink it.
var maxDownInflight = 2 * (28 << 20)

var (
	errSessionClosed = errors.New("hub: host session is closed")
	errDownOverflow  = errors.New("hub: down log over budget")
)

// reqAck is one dispatched request whose frame has not been acked yet.
type reqAck struct {
	reqID    string
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
}

// newSessionProto starts a sequence space. upAcked is the epoch's retired
// high-water baseline declared in hello.resume.up: the host's event bus may be
// past events the hub never saw (the FE rebuilds those from history), so the
// first live event is baseline+1 and everything at or below is a duplicate.
// window is the advertised limits.resumeWindow for the up receiver.
func newSessionProto(epoch, upAcked uint64, window int) *sessionProto {
	return &sessionProto{
		epoch:   epoch,
		up:      wire.NewReceiverWindow(upAcked, window),
		down:    wire.NewSender(0),
		reqAcks: make(map[uint64]reqAck),
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
	return applied
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
	if p.down.Bytes() > maxDownInflight {
		return seq, errDownOverflow
	}
	return seq, nil
}

// dispatchRequest appends a relay request and records the deadline that proves
// its delivery, atomically with the append so an ack racing the dispatch can
// never leave a phantom deadline behind.
func (p *sessionProto) dispatchRequest(reqID string, f wire.Frame) (uint64, error) {
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
	p.reqAcks[seq] = reqAck{reqID: reqID, deadline: time.Now().Add(RequestAckTimeout)}
	if p.down.Bytes() > maxDownInflight {
		return seq, errDownOverflow
	}
	return seq, nil
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

// nextRequestDeadline is the earliest ack deadline still outstanding.
func (p *sessionProto) nextRequestDeadline() (time.Time, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out time.Time
	for _, ra := range p.reqAcks {
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
		if now.Before(ra.deadline) {
			continue
		}
		out = append(out, ra.reqID)
		delete(p.reqAcks, seq)
	}
	return out
}

// session is one attached host transport. Its loop owns every write and every
// timer; the hub reaches it through dispatch / pushAudience, which only append
// to the down log and wake the loop.
type session struct {
	h         *Hub
	hostID    string
	epoch     uint64
	proto     *sessionProto
	transport Transport

	wake chan struct{}
	stop chan struct{}
	// stopReason is the reason requestStop was called with; 0 means the loop
	// is still deciding for itself.
	stopReason atomic.Uint32
	stopOnce   sync.Once
	finished   atomic.Bool

	// Loop-owned link state: how far the down log has been handed to THIS
	// transport, and the last watermarks exchanged on it.
	written     uint64
	lastDownAck uint64
	lastAckSent uint64
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
func (s *session) dispatch(reqID, method, path string, body []byte) error {
	if s.finished.Load() {
		return errSessionClosed
	}
	f := wire.Frame{V: wire.ProtocolVersion, Type: wire.TypeRequest, ReqID: reqID, Method: method, Path: path}
	if len(body) > 0 {
		f.Body = body
	}
	if _, err := s.proto.dispatchRequest(reqID, f); err != nil {
		if errors.Is(err, errDownOverflow) {
			s.requestStop(wire.CloseOverflow)
		}
		return err
	}
	s.signal()
	return nil
}

// pushAudience appends one absolute audience snapshot to the down log.
func (s *session) pushAudience(a wire.Audience) error {
	if s.finished.Load() {
		return errSessionClosed
	}
	_, err := s.proto.appendReliable(func(seq, ack uint64) wire.Frame {
		return wire.NewAudience(seq, ack, a)
	})
	if err != nil {
		if errors.Is(err, errDownOverflow) {
			s.requestStop(wire.CloseOverflow)
		}
		return err
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
	hostID, ok := h.HostIDForToken(hello.Token)
	if !ok || (expected != "" && expected != hostID) {
		log.Printf("[capri-hub] host %s: hello token rejected", expected)
		return wire.CloseAuth
	}

	deflate := hello.Caps != nil && hello.Caps.Deflate
	if ds, ok := t.(deflateSetter); ok {
		ds.SetDeflate(deflate)
	}
	keepalive := time.Duration(SessionLiveness.Keepalive) * time.Second
	t.SetKeepalive(keepalive)

	s, old, ack, err := h.attach(hostID, hello.Epoch, hello.Resume.Up, hello.Resume.Down, deflate)
	if err != nil {
		log.Printf("[capri-hub] host %s: attach: %v", hostID, err)
		if errors.Is(err, ErrHostUnknown) {
			return wire.CloseAuth
		}
		return wire.CloseProtocol
	}
	s.transport = t
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

// run is the one session loop: read frames, apply them, send heartbeats,
// retransmit unacked down frames and enforce idle. It returns the close reason.
func (s *session) run(reader <-chan readResult, helloAck []byte) wire.CloseReason {
	if err := s.transport.Send(helloAck); err != nil {
		log.Printf("[capri-hub] host %s: hello_ack write: %v", s.hostID, err)
		return wire.CloseNormal
	}
	keepalive := time.Duration(SessionLiveness.Keepalive) * time.Second
	idle := time.Duration(SessionLiveness.Idle) * time.Second
	rto := 2 * keepalive

	s.written = s.proto.downAcked()
	s.lastDownAck = s.written
	s.lastAckSent = s.proto.upAcked()

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
		next := nextHB
		if d := lastRecv.Add(idle); d.Before(next) {
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

		case <-timer.C:
			now := time.Now()
			if !now.Before(nextHB) {
				if reason := s.sendHeartbeat(); reason != 0 {
					return reason
				}
				nextHB = now.Add(keepalive)
			}
			if s.proto.hasUnacked() && !now.Before(rtoAt) {
				if reason := s.retransmit(); reason != 0 {
					return reason
				}
				rtoAt = now.Add(rto)
			}
			for _, reqID := range s.proto.expireRequests(now) {
				log.Printf("[capri-hub] host %s: request %s not acked within %s", s.hostID, reqID, RequestAckTimeout)
				s.h.failRequest(s.hostID, reqID, 503, "host 未确认中继请求")
			}
			if now.Sub(lastRecv) >= idle {
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
	}
	switch f.Type {
	case wire.TypeEvents:
		return s.handleEvents(data, f)
	case wire.TypeRespond:
		s.handleRespond(f)
		return 0
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

func (s *session) handleRespond(f wire.Frame) {
	if f.Chunk != "" || f.Encoding != "" || f.More {
		if !s.h.RespondChunk(s.hostID, f.ReqID, f.RespondStatus(), f.Encoding, f.Chunk, f.More) {
			log.Printf("[capri-hub] host %s: respond chunk for unknown reqId %s", s.hostID, f.ReqID)
		}
		return
	}
	if !s.h.Respond(s.hostID, f.ReqID, RelayResponse{Status: f.RespondStatus(), Body: f.Body}) {
		log.Printf("[capri-hub] host %s: respond for unknown reqId %s", s.hostID, f.ReqID)
	}
}

func (s *session) handleHeartbeat(f wire.Frame) wire.CloseReason {
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

// flushNew writes the down log entries this transport has not seen yet.
func (s *session) flushNew() wire.CloseReason {
	if s.stopped() {
		// A superseded link must not write frames the new link owns; entries
		// appended after the handover belong to the replacement.
		return s.closeReason()
	}
	for _, e := range s.proto.entriesAfter(s.written) {
		if err := s.transport.Send(e.Payload); err != nil {
			log.Printf("[capri-hub] host %s: downlink write: %v", s.hostID, err)
			return wire.CloseNormal
		}
		s.written = e.Seq
	}
	return 0
}

// retransmit replays the whole unacked down log after an RTO.
func (s *session) retransmit() wire.CloseReason {
	if s.stopped() {
		return s.closeReason()
	}
	for _, e := range s.proto.entries() {
		if err := s.transport.Send(e.Payload); err != nil {
			log.Printf("[capri-hub] host %s: retransmit write: %v", s.hostID, err)
			return wire.CloseNormal
		}
		if e.Seq > s.written {
			s.written = e.Seq
		}
	}
	return 0
}

func (s *session) sendHeartbeat() wire.CloseReason {
	f, err := wire.NewHeartbeat(s.proto.upAcked(), s.h.heartbeatStatus(s.hostID))
	if err != nil {
		return wire.CloseProtocol
	}
	payload, err := wire.Encode(f)
	if err != nil {
		return wire.CloseProtocol
	}
	if err := s.transport.Send(payload); err != nil {
		log.Printf("[capri-hub] host %s: heartbeat write: %v", s.hostID, err)
		return wire.CloseNormal
	}
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
