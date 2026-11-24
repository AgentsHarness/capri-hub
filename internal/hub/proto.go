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
}

// newSessionProto starts a sequence space. upAcked is the epoch's retired
// high-water baseline declared in hello.resume.up: the host's event bus may be
// past events the hub never saw (the FE rebuilds those from history), so the
// first live event is baseline+1 and everything at or below is a duplicate.
func newSessionProto(epoch, upAcked uint64) *sessionProto {
	return &sessionProto{
		epoch: epoch,
		up:    wire.NewReceiver(upAcked),
		down:  wire.NewSender(0),
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
// payload when it is the next expected seq.
func (p *sessionProto) accept(seq uint64, payload []byte) ([]byte, uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.up.Accept(seq, payload)
}

// ackDown applies the peer's watermark. It returns the watermark actually in
// force: Sender.Ack clamps an ack above the last assigned seq, because a peer
// cannot confirm a frame that was never sent. Reporting the clamped value
// keeps the session's own mirror honest — recording the raw number would make
// every later, genuine ack look stale and stall the down log for the life of
// the session.
func (p *sessionProto) ackDown(n uint64) uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.down.Ack(n)
	return p.down.Acked()
}

// appendReliable assigns the next down seq, stamps the current up watermark,
// encodes the frame and logs it. A frame that would put the log over budget is
// refused before it enters the log, so the caller's error means the host was
// never sent the frame.
func (p *sessionProto) appendReliable(build func(seq, ack uint64) wire.Frame) (uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	seq := p.down.Next() + 1
	payload, err := wire.Encode(build(seq, p.up.Acked()))
	if err != nil {
		return 0, err
	}
	if p.down.Bytes()+len(payload) > downInflightCap() {
		return 0, errDownOverflow
	}
	if got := p.down.Append(payload); got != seq {
		return 0, errors.New("hub: down seq assignment drifted")
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

// dispatch appends one relay request to the down log and wakes the loop.
//
// The entry stays in the log until the host's cumulative ack covers it. There
// is deliberately no per-request delivery deadline: a frame the host may have
// executed must not be failed by the hub's own clock (see pendingGrace in
// hub.go for how a detach is bounded).
func (s *session) dispatch(reqID, method, path string, body []byte, opts DispatchOptions) error {
	if s.finished.Load() {
		return errSessionClosed
	}
	f := wire.Frame{
		V: wire.ProtocolVersion, Type: wire.TypeRequest, ReqID: reqID, Method: method, Path: path,
		IdemKey: opts.IdemKey, IdemScope: opts.IdemScope,
	}
	if len(body) > 0 {
		f.Body = body
	}
	_, err := s.proto.appendReliable(func(seq, ack uint64) wire.Frame {
		f.Seq = seq
		f.Ack = ack
		return f
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

// pushAudience posts one absolute audience snapshot to the writer's
// latest-wins slot. It carries no seq and is never acked: a newer snapshot
// supersedes one still waiting, and a lost one is corrected by the next
// heartbeat refresh.
func (s *session) pushAudience(a wire.Audience) error {
	if s.finished.Load() {
		return errSessionClosed
	}
	payload, err := wire.Encode(wire.NewAudience(a))
	if err != nil {
		return err
	}
	s.audienceMu.Lock()
	s.audiencePayload = payload
	s.audienceMu.Unlock()
	if w := s.writer.Load(); w != nil {
		w.postAudience(payload)
	}
	return nil
}

// refreshAudience re-posts the newest snapshot so one lost on the unreliable
// path is corrected on the next heartbeat tick instead of waiting for a new
// viewer change.
func (s *session) refreshAudience() {
	s.audienceMu.Lock()
	payload := s.audiencePayload
	s.audienceMu.Unlock()
	if len(payload) == 0 {
		return
	}
	if w := s.writer.Load(); w != nil {
		w.postAudience(payload)
	}
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
// one per event, so the next frame continues from the last event's seq. The
// up log is gapless (the host fills a bus gap with trimmed placeholders), so a
// frame that does not continue the watermark is a protocol violation; the
// bodies are applied without decode / re-encode on the fan-out path.
func (s *session) handleEvents(raw []byte, f wire.Frame) wire.CloseReason {
	var (
		ready [][]byte
		ack   uint64
	)
	for i, body := range f.Events {
		seq := f.Seq + uint64(i)
		payload, a, err := s.proto.accept(seq, body)
		if err != nil {
			log.Printf("[capri-hub] host %s: event seq %d out of order: %v", s.hostID, seq, err)
			return wire.CloseProtocol
		}
		if payload != nil {
			ready = append(ready, payload)
		}
		ack = a
	}
	if len(ready) > 0 {
		raws := make([]json.RawMessage, len(ready))
		for i, b := range ready {
			raws[i] = b
		}
		if !s.h.ingestRawEvents(s, raws) {
			// A newer session took the host over while these events were
			// in flight: they belong to a dead epoch and must not be applied.
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
		Version:      &st.Version,
	})
	return 0
}
