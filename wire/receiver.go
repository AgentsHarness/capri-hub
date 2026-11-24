package wire

import (
	"fmt"
)

// ErrOutOfOrder is returned by Receiver.Accept when a reliable frame arrives
// ahead of the next expected seq. The streams that carry reliable frames are
// ordered, and the sender never skips a seq (an uplink gap becomes trimmed
// placeholders, a downlink seq is assigned consecutively), so a gap means the
// two sides disagree about the sequence space. It wraps ErrProtocol so the
// generic close-reason mapping still applies.
var ErrOutOfOrder = fmt.Errorf("%w: reliable frame out of order", ErrProtocol)

// Receiver applies the peer's reliable frames in seq order. Acceptance is
// strict: only acked+1 advances the watermark, because the sender guarantees
// the seq space is gapless and a jump would silently drop everything under it.
//
// A Receiver is owned by the session loop — one goroutine, no mutex.
type Receiver struct {
	acked uint64
}

// NewReceiver starts a receiver whose watermark is acked.
func NewReceiver(acked uint64) *Receiver {
	return &Receiver{acked: acked}
}

// Accept hands one reliable frame to the receiver and returns the payload when
// it is the next expected seq, plus the current watermark.
//
// A duplicate (seq <= acked) applies nothing but still yields the ack, so a
// sender that lost the acknowledgement stops retransmitting. A seq above
// acked+1 is a protocol violation: the watermark stays put and the caller
// closes with protocol.
func (r *Receiver) Accept(seq uint64, payload []byte) (applied []byte, ack uint64, err error) {
	if seq == 0 {
		return nil, r.acked, fmt.Errorf("wire: reliable frame with seq 0")
	}
	if seq <= r.acked {
		return nil, r.acked, nil
	}
	if seq != r.acked+1 {
		return nil, r.acked, fmt.Errorf("%w: seq %d, expected %d", ErrOutOfOrder, seq, r.acked+1)
	}
	r.acked = seq
	return payload, r.acked, nil
}

// Acked is the watermark: every seq up to and including it has been applied.
func (r *Receiver) Acked() uint64 { return r.acked }
