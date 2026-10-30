package wire

import "fmt"

// Entry is one unacknowledged reliable frame in a Sender's log.
type Entry struct {
	Seq     uint64
	Payload []byte
}

// Sender assigns this direction's seqs and keeps the unacked log, which is the
// only repair path: after a reconnect the peer's ackUp is fed through Ack and
// the remaining entries in the log are replayed.
//
// A Sender is owned by the session loop — one goroutine, no mutex. A seq is
// assigned exactly once and is never renumbered, so a retransmission is always
// byte-identical to the original.
type Sender struct {
	next  uint64 // next seq to assign
	acked uint64 // every seq <= acked is confirmed
	log   []Entry
	bytes int
}

// NewSender starts a sender whose log is empty and whose watermark is acked.
func NewSender(acked uint64) *Sender {
	return &Sender{next: acked, acked: acked}
}

// Append logs payload under the next seq and returns that seq.
func (s *Sender) Append(payload []byte) uint64 {
	seq := s.next + 1
	s.append(seq, payload)
	return seq
}

// AppendAt logs a payload that was sequenced elsewhere, such as an event frame
// assembled before it reached the session. The first call on an empty log sets
// the baseline from seq itself, so a resumed stream can start above 1 without
// being renumbered.
func (s *Sender) AppendAt(seq uint64, payload []byte) error {
	if seq == 0 {
		return fmt.Errorf("wire: seq 0 is not assignable")
	}
	if s.next == 0 {
		s.next = seq - 1
	}
	if seq != s.next+1 {
		return fmt.Errorf("wire: seq %d, want %d", seq, s.next+1)
	}
	s.append(seq, payload)
	return nil
}

func (s *Sender) append(seq uint64, payload []byte) {
	s.next = seq
	s.log = append(s.log, Entry{Seq: seq, Payload: payload})
	s.bytes += len(payload)
}

// Ack advances the watermark to n and drops everything it covers. Stale or
// out-of-order acks never move it backwards; an ack past next is clamped, since
// a peer cannot confirm a seq that was never sent.
func (s *Sender) Ack(n uint64) {
	if n > s.next {
		n = s.next
	}
	if n <= s.acked {
		return
	}
	s.acked = n
	i := 0
	for i < len(s.log) && s.log[i].Seq <= n {
		s.bytes -= len(s.log[i].Payload)
		i++
	}
	if i == 0 {
		return
	}
	kept := copy(s.log, s.log[i:])
	clear(s.log[kept:])
	s.log = s.log[:kept]
}

// Elide replaces the payload logged for seq, keeping the seq. Compaction uses it
// to turn a droppable event into a trimmed placeholder without opening a hole.
func (s *Sender) Elide(seq uint64, replacement []byte) error {
	for i := range s.log {
		if s.log[i].Seq == seq {
			s.bytes += len(replacement) - len(s.log[i].Payload)
			s.log[i].Payload = replacement
			return nil
		}
	}
	return fmt.Errorf("wire: seq %d is not in the unacked log", seq)
}

// Entries returns a copy of the unacked log, in seq order.
func (s *Sender) Entries() []Entry {
	out := make([]Entry, len(s.log))
	copy(out, s.log)
	return out
}

// Bytes is the payload size of the unacked log.
func (s *Sender) Bytes() int { return s.bytes }

// Len is the number of unacked frames.
func (s *Sender) Len() int { return len(s.log) }

// Acked is the watermark: every seq up to and including it is confirmed.
func (s *Sender) Acked() uint64 { return s.acked }

// Next is the highest seq assigned so far (0 before the first Append).
func (s *Sender) Next() uint64 { return s.next }
