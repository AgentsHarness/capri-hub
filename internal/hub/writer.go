package hub

import (
	"bytes"
	"compress/flate"
	"errors"
	"io"
	"log"
	"sync"
	"sync/atomic"

	"github.com/AgentsHarness/capri-hub/wire"
)

const (
	// retransmitBatch and retransmitBatchBytes bound one RTO replay. A lost
	// frame is repaired by resending the oldest unacked window, not by
	// replaying everything in flight.
	retransmitBatch      = 8
	retransmitBatchBytes = 1 << 20
	// minDownCompressSize is the flate floor: below it the stream header
	// costs more than the compression saves.
	minDownCompressSize = 256
)

var errWriterStopped = errors.New("hub: writer stopped")

// writer owns every socket write for one session. The session loop appends
// reliable frames to the down log and posts control frames to a latest-wins
// slot; this goroutine is the only one that calls Transport.Send /
// SendFragment, so a wedged peer blocks output instead of the loop.
//
// written is how far the log has been handed to this transport and is advanced
// only after a complete logical frame was written. A request's ack deadline is
// armed at that point (proto.noteWritten), never at dispatch.
type writer struct {
	s       *session
	tr      Transport
	deflate bool

	wake         chan struct{}
	retransmitCh chan struct{}
	// rewriteCh asks for one specific unacked entry to be written again after
	// its payload was replaced in place. Audience is absolute state: the seq
	// stays fixed, but a newer snapshot must reach the peer without waiting
	// for the RTO. One slot is enough — only one audience frame is pending.
	rewriteCh chan uint64
	progress  chan struct{}
	busy      atomic.Bool

	// controlQ is a small FIFO of control frames. Plain heartbeats coalesce
	// with the previous one (only the newest snapshot matters), while a
	// probe/probeAck is never dropped: its sender is waiting for a specific
	// reply, and losing it would fail a live link or a healthy peer's probe.
	controlMu sync.Mutex
	controlQ  [][]byte

	written uint64 // owned by the writer goroutine
	frameID uint32 // owned by the writer goroutine
}

func newWriter(s *session, tr Transport, deflate bool) *writer {
	return &writer{
		s:            s,
		tr:           tr,
		deflate:      deflate,
		wake:         make(chan struct{}, 1),
		retransmitCh: make(chan struct{}, 1),
		rewriteCh:    make(chan uint64, 1),
		progress:     make(chan struct{}, 1),
		written:      s.proto.downAcked(),
	}
}

func (w *writer) start() { go w.run() }

// Busy reports whether a write is in progress. The session skips an RTO replay
// while it is, because the writer is already moving the frame that replay
// would duplicate.
func (w *writer) Busy() bool { return w.busy.Load() }

// kick wakes the writer to pick up newly appended reliable frames.
func (w *writer) kick() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// retransmit asks the writer to replay the oldest unacked batch.
func (w *writer) retransmit() {
	select {
	case w.retransmitCh <- struct{}{}:
	default:
	}
}

// rewrite asks the writer to write the entry at seq again because its payload
// was replaced in place. The slot holds one seq; a later replacement of the
// same single audience entry supersedes an earlier request.
func (w *writer) rewrite(seq uint64) {
	select {
	case w.rewriteCh <- seq:
	default:
		select {
		case <-w.rewriteCh:
		default:
		}
		select {
		case w.rewriteCh <- seq:
		default:
		}
	}
}

// controlQueueDepth bounds queued control frames. In steady state the queue
// holds at most one heartbeat, and probes are rare; the bound only matters for
// a long run of host probes nobody drains.
const controlQueueDepth = 16

// postControl enqueues one control frame. Consecutive plain heartbeats
// coalesce (only the newest snapshot matters); probes and probeAcks are always
// kept because a specific peer is waiting for that nonce.
func (w *writer) postControl(payload []byte) {
	w.controlMu.Lock()
	if n := len(w.controlQ); n > 0 && isPlainHeartbeat(payload) && isPlainHeartbeat(w.controlQ[n-1]) {
		w.controlQ[n-1] = payload
	} else {
		w.controlQ = append(w.controlQ, payload)
		if len(w.controlQ) > controlQueueDepth {
			w.dropOldestPlainLocked()
		}
	}
	w.controlMu.Unlock()
	w.kick()
}

// dropOldestPlainLocked removes one plain heartbeat from the queue; if every
// queued frame carries a probe, the oldest is dropped as a last resort so the
// queue stays bounded.
func (w *writer) dropOldestPlainLocked() {
	for i, p := range w.controlQ {
		if isPlainHeartbeat(p) {
			w.controlQ = append(w.controlQ[:i], w.controlQ[i+1:]...)
			return
		}
	}
	w.controlQ = w.controlQ[1:]
}

// isPlainHeartbeat reports whether an encoded hb carries neither a probe nor
// a probeAck. The JSON keys are distinct, so a substring test is exact.
func isPlainHeartbeat(payload []byte) bool {
	return !bytes.Contains(payload, []byte(`"probe"`)) &&
		!bytes.Contains(payload, []byte(`"probeAck"`))
}

// controlLen reports how many control frames are waiting.
func (w *writer) controlLen() int {
	w.controlMu.Lock()
	defer w.controlMu.Unlock()
	return len(w.controlQ)
}

// noteProgress tells the session that bytes moved, so it restarts the RTO
// instead of replaying a frame that just left.
func (w *writer) noteProgress() {
	select {
	case w.progress <- struct{}{}:
	default:
	}
}

func (w *writer) run() {
	defer w.busy.Store(false)
	for {
		if w.s.stopped() {
			return
		}
		// Control first: an hb must not sit behind a large reliable frame.
		if c, ok := w.takeControl(); ok {
			if err := w.writeControl(c); err != nil {
				w.fail(err)
				return
			}
			continue
		}
		if entries := w.s.proto.entriesAfter(w.written); len(entries) > 0 {
			if err := w.writeEntries(entries); err != nil {
				w.fail(err)
				return
			}
			continue
		}
		select {
		case <-w.s.stop:
			return
		case <-w.wake:
		case <-w.retransmitCh:
			if err := w.replay(); err != nil {
				w.fail(err)
				return
			}
		case seq := <-w.rewriteCh:
			if e, ok := w.s.proto.entry(seq); ok {
				if err := w.writeEntries([]wire.Entry{e}); err != nil {
					w.fail(err)
					return
				}
			}
		}
	}
}

func (w *writer) takeControl() ([]byte, bool) {
	w.controlMu.Lock()
	defer w.controlMu.Unlock()
	if len(w.controlQ) == 0 {
		return nil, false
	}
	c := w.controlQ[0]
	w.controlQ = w.controlQ[1:]
	return c, true
}

func (w *writer) writeControl(payload []byte) error {
	w.busy.Store(true)
	defer w.busy.Store(false)
	// Control frames deliberately do not signal progress: heartbeats are
	// written on their own clock, and resetting the RTO on them would push
	// retransmission past every keepalive tick.
	return w.tr.Send(payload)
}

func (w *writer) writeEntries(entries []wire.Entry) error {
	for _, e := range entries {
		if w.s.stopped() {
			return errWriterStopped
		}
		// A control frame posted between two reliable frames goes first.
		if c, ok := w.takeControl(); ok {
			if err := w.writeControl(c); err != nil {
				return err
			}
		}
		if err := w.writeReliable(e); err != nil {
			return err
		}
	}
	return nil
}

func (w *writer) writeReliable(e wire.Entry) error {
	w.busy.Store(true)
	defer w.busy.Store(false)
	if err := w.writeFrame(e.Payload); err != nil {
		return err
	}
	// The complete logical frame is on the wire: only now may a request's ack
	// deadline start (or restart, after a retransmission), and only now is an
	// audience generation known to have reached the peer.
	w.s.proto.noteWritten(e.Seq, e.Payload)
	if e.Seq > w.written {
		w.written = e.Seq
	}
	w.noteProgress()
	return nil
}

// replay resends the oldest unacked batch. Entries at or below written keep
// their place in the log; entries above it were never written by this writer
// and advance the watermark as usual.
func (w *writer) replay() error {
	entries := w.s.proto.oldestUnacked(retransmitBatch, retransmitBatchBytes)
	if len(entries) == 0 {
		return nil
	}
	return w.writeEntries(entries)
}

// writeFrame sends one logical frame: a small uncompressed frame as a single
// Send, anything larger (or compressed) as transport units. Control frames
// posted meanwhile are written between units, so a 28MB answer cannot hold a
// heartbeat hostage.
func (w *writer) writeFrame(payload []byte) error {
	out := payload
	compressed := false
	if w.deflate && len(payload) >= minDownCompressSize {
		if z := deflateFrame(payload); z != nil && len(z) < len(payload) {
			out, compressed = z, true
		}
	}
	if !compressed && len(out) <= wire.UnitSize {
		return w.tr.Send(out)
	}
	if err := w.interleaveControl(); err != nil {
		return err
	}
	units, err := wire.SplitFrame(out, compressed, w.nextFrameID(), wire.UnitSize)
	if err != nil {
		return err
	}
	for i, unit := range units {
		if i > 0 {
			if err := w.interleaveControl(); err != nil {
				return err
			}
		}
		if err := w.tr.SendFragment(unit); err != nil {
			return err
		}
	}
	return nil
}

// interleaveControl writes at most one pending control frame. Control frames
// are small and never compressed, so they take the whole-frame path.
func (w *writer) interleaveControl() error {
	c, ok := w.takeControl()
	if !ok {
		return nil
	}
	return w.tr.Send(c)
}

func (w *writer) nextFrameID() uint32 {
	w.frameID++
	return w.frameID
}

func (w *writer) fail(err error) {
	if errors.Is(err, errWriterStopped) {
		return
	}
	log.Printf("[capri-hub] host %s: downlink write: %v", w.s.hostID, err)
	w.s.requestStop(wire.CloseNormal)
}

// deflateFrame returns payload compressed with flate, or nil when compression
// failed. The pools keep a chunk storm from allocating a fresh writer and
// buffer per frame; a buffer that grew past a megabyte is not returned, so one
// giant frame does not pin its footprint for the session's lifetime.
func deflateFrame(payload []byte) []byte {
	buf := downFlateBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	fw := downFlateWriterPool.Get().(*flate.Writer)
	fw.Reset(buf)
	_, werr := fw.Write(payload)
	cerr := fw.Close()
	downFlateWriterPool.Put(fw)
	if werr != nil || cerr != nil {
		downFlateBufPool.Put(buf)
		return nil
	}
	out := append([]byte(nil), buf.Bytes()...)
	if buf.Cap() <= 1<<20 {
		downFlateBufPool.Put(buf)
	}
	return out
}

var (
	downFlateWriterPool = sync.Pool{
		New: func() any {
			fw, _ := flate.NewWriter(io.Discard, flate.BestSpeed)
			return fw
		},
	}
	downFlateBufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}
)
