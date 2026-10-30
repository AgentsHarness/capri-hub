package wire

import (
	"errors"
	"fmt"
)

// ErrOverflow is returned by Receiver.Accept once more than ResumeWindow frames
// are parked. The watermark stays where it was: the caller closes with
// overflow, and the peer replays from its log after reconnecting.
var ErrOverflow = errors.New("wire: resume window overflow")

// Receiver applies the peer's reliable frames in seq order. Frames that arrive
// ahead of a gap are parked; the watermark only ever advances over contiguous
// frames, because a jump would silently drop everything under it.
//
// A Receiver is owned by the session loop — one goroutine, no mutex.
type Receiver struct {
	acked  uint64
	window int
	buf    map[uint64][]byte
}

// NewReceiver starts a receiver whose watermark is acked and whose parked-frame
// bound is the package default.
func NewReceiver(acked uint64) *Receiver {
	return NewReceiverWindow(acked, ResumeWindow)
}

// NewReceiverWindow starts a receiver with an explicit resume window. The
// window is the peer's advertised limits.resumeWindow: a hub may allow more or
// fewer parked frames than the default, and the overflow bound must be the one
// it announced rather than a constant the two sides guess at.
func NewReceiverWindow(acked uint64, window int) *Receiver {
	if window < 1 {
		window = ResumeWindow
	}
	return &Receiver{acked: acked, window: window}
}

// Window reports the parked-frame bound this receiver applies.
func (r *Receiver) Window() int { return r.window }

// Accept hands one reliable frame to the receiver and returns the payloads that
// became applicable, in seq order, plus the current watermark.
//
// A duplicate (seq <= acked) applies nothing but still yields the ack, so a
// sender that lost the acknowledgement stops retransmitting. A gap parks the
// payload; the next contiguous frame drains the buffer behind it.
func (r *Receiver) Accept(seq uint64, payload []byte) (ready [][]byte, ack uint64, err error) {
	if seq == 0 {
		return nil, r.acked, fmt.Errorf("wire: reliable frame with seq 0")
	}
	if seq <= r.acked {
		return nil, r.acked, nil
	}
	if seq > r.acked+1 {
		if _, parked := r.buf[seq]; parked {
			return nil, r.acked, nil
		}
		if len(r.buf) >= r.window {
			return nil, r.acked, ErrOverflow
		}
		if r.buf == nil {
			r.buf = make(map[uint64][]byte)
		}
		r.buf[seq] = payload
		return nil, r.acked, nil
	}

	ready = append(ready, payload)
	r.acked = seq
	for {
		next, ok := r.buf[r.acked+1]
		if !ok {
			break
		}
		delete(r.buf, r.acked+1)
		r.acked++
		ready = append(ready, next)
	}
	return ready, r.acked, nil
}

// Acked is the watermark: every seq up to and including it has been applied.
func (r *Receiver) Acked() uint64 { return r.acked }

// Buffered is the number of parked frames waiting for a gap to fill.
func (r *Receiver) Buffered() int { return len(r.buf) }
