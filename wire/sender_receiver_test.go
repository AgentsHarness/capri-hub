package wire

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
)

// TestSenderReceiverLossyChannel drives one Sender and one Receiver through a
// channel that drops, duplicates, delays and reorders frames, and an ack path
// that does the same. Every trace must end with both sides agreeing on exactly
// the payloads that were sent, in seq order.
func TestSenderReceiverLossyChannel(t *testing.T) {
	for seed := int64(1); seed <= 500; seed++ {
		runTrace(t, seed)
	}
}

type packet struct {
	seq  uint64
	body []byte
	due  int
}

type ackMsg struct {
	due int
	ack uint64
}

func runTrace(t *testing.T, seed int64) {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	s := NewSender(0)
	r := NewReceiver(0)

	var flight []packet
	var acks []ackMsg
	bySeq := make(map[uint64][]byte)
	applied := 0
	lastAck := uint64(0)
	assigned := 0

	deliver := func(seq uint64, body []byte) uint64 {
		ready, ack, err := r.Accept(seq, body)
		if err != nil {
			t.Fatalf("seed %d: accept seq %d: %v", seed, seq, err)
		}
		for _, got := range ready {
			applied++
			want, ok := bySeq[uint64(applied)]
			if !ok || !bytes.Equal(got, want) {
				t.Fatalf("seed %d: applied #%d = %q, want %q", seed, applied, got, want)
			}
		}
		if ack < lastAck {
			t.Fatalf("seed %d: receiver ack regressed %d -> %d", seed, lastAck, ack)
		}
		lastAck = ack
		return ack
	}

	// send packs one wire transmission: loss, reorder and a possible duplicate.
	send := func(seq uint64, body []byte, at int) {
		if rng.Intn(100) < 12 {
			return
		}
		due := at + rng.Intn(4)
		flight = append(flight, packet{seq: seq, body: body, due: due})
		if rng.Intn(100) < 8 {
			flight = append(flight, packet{seq: seq, body: body, due: due + rng.Intn(3)})
		}
	}

	for step := 0; step < 40+rng.Intn(160); step++ {
		if rng.Intn(100) < 45 {
			body := []byte(fmt.Sprintf("p-%03d-%x", assigned, rng.Int63()))
			seq := s.Append(body)
			if seq != s.Next() {
				t.Fatalf("seed %d: Append returned %d, Next is %d", seed, seq, s.Next())
			}
			if _, ok := bySeq[seq]; ok {
				t.Fatalf("seed %d: seq %d assigned twice", seed, seq)
			}
			bySeq[seq] = body
			assigned++
			checkLog(t, seed, s)
			send(seq, body, step)
		}

		if rng.Intn(100) < 15 {
			for _, e := range s.Entries() {
				if want, ok := bySeq[e.Seq]; !ok || !bytes.Equal(e.Payload, want) {
					t.Fatalf("seed %d: retransmit %d = %q, want %q", seed, e.Seq, e.Payload, bySeq[e.Seq])
				}
				send(e.Seq, e.Payload, step)
			}
		}

		var pending []packet
		for _, p := range flight {
			if p.due > step {
				pending = append(pending, p)
				continue
			}
			ack := deliver(p.seq, p.body)
			if ack > 0 && rng.Intn(100) >= 10 {
				acks = append(acks, ackMsg{due: step + rng.Intn(4), ack: ack})
			}
			if ack > 1 && rng.Intn(100) < 15 {
				// A stale ack that arrives after a newer one must not move the
				// watermark back.
				acks = append(acks, ackMsg{due: step + 1 + rng.Intn(6), ack: ack - 1})
			}
		}
		flight = pending

		var pendingAcks []ackMsg
		for _, a := range acks {
			if a.due > step {
				pendingAcks = append(pendingAcks, a)
				continue
			}
			before := s.Acked()
			s.Ack(a.ack)
			if s.Acked() < before {
				t.Fatalf("seed %d: sender watermark regressed %d -> %d", seed, before, s.Acked())
			}
			checkLog(t, seed, s)
		}
		acks = pendingAcks
	}

	// Final drain: the channel stops losing and reordering. Both sides must
	// converge without any seq being renumbered or skipped.
	for guard := 0; s.Len() > 0; guard++ {
		if guard > 10_000 {
			t.Fatalf("seed %d: log did not drain (%d entries left)", seed, s.Len())
		}
		for _, e := range s.Entries() {
			deliver(e.Seq, e.Payload)
		}
		s.Ack(lastAck)
	}
	if r.Acked() != s.Next() {
		t.Fatalf("seed %d: receiver acked %d, sender next %d", seed, r.Acked(), s.Next())
	}
	if applied != int(s.Next()) {
		t.Fatalf("seed %d: applied %d of %d payloads", seed, applied, s.Next())
	}
	if s.Bytes() != 0 {
		t.Fatalf("seed %d: %d bytes left in the drained log", seed, s.Bytes())
	}
	if r.Buffered() != 0 {
		t.Fatalf("seed %d: %d frames still parked", seed, r.Buffered())
	}
}

func checkLog(t *testing.T, seed int64, s *Sender) {
	t.Helper()
	entries := s.Entries()
	if len(entries) != s.Len() {
		t.Fatalf("seed %d: Len %d, Entries %d", seed, s.Len(), len(entries))
	}
	if s.Acked() > s.Next() {
		t.Fatalf("seed %d: acked %d above next %d", seed, s.Acked(), s.Next())
	}
	sum := 0
	for i, e := range entries {
		sum += len(e.Payload)
		if e.Seq <= s.Acked() {
			t.Fatalf("seed %d: log kept acked seq %d (acked %d)", seed, e.Seq, s.Acked())
		}
		if i > 0 && e.Seq != entries[i-1].Seq+1 {
			t.Fatalf("seed %d: log jumped from %d to %d", seed, entries[i-1].Seq, e.Seq)
		}
	}
	if sum != s.Bytes() {
		t.Fatalf("seed %d: Bytes %d, entries hold %d", seed, s.Bytes(), sum)
	}
	if n := len(entries); n > 0 && entries[n-1].Seq != s.Next() {
		t.Fatalf("seed %d: log ends at %d, next is %d", seed, entries[n-1].Seq, s.Next())
	}
}

func TestSenderAssignsAfterAcked(t *testing.T) {
	s := NewSender(41)
	if got := s.Append([]byte("a")); got != 42 {
		t.Fatalf("first seq %d, want 42", got)
	}
	s.Ack(40) // stale
	if s.Acked() != 41 {
		t.Fatalf("stale ack moved the watermark to %d", s.Acked())
	}
	s.Ack(1000) // past next is clamped
	if s.Acked() != 42 || s.Len() != 0 {
		t.Fatalf("acked %d len %d after ack past next", s.Acked(), s.Len())
	}
}

func TestSenderAckDropsOnlyCovered(t *testing.T) {
	s := NewSender(0)
	for i := 0; i < 5; i++ {
		s.Append([]byte{byte(i)})
	}
	s.Ack(3)
	if s.Len() != 2 || s.Acked() != 3 {
		t.Fatalf("len %d acked %d after ack 3", s.Len(), s.Acked())
	}
	if got := s.Entries(); len(got) != 2 || got[0].Seq != 4 || !bytes.Equal(got[0].Payload, []byte{3}) ||
		got[1].Seq != 5 || !bytes.Equal(got[1].Payload, []byte{4}) {
		t.Fatalf("unacked log %v", got)
	}
	if s.Bytes() != 2 {
		t.Fatalf("bytes %d", s.Bytes())
	}
	s.Ack(1) // stale
	if s.Acked() != 3 || s.Len() != 2 {
		t.Fatalf("stale ack changed state: acked %d len %d", s.Acked(), s.Len())
	}
}

func TestSenderAppendAt(t *testing.T) {
	s := NewSender(0)
	if err := s.AppendAt(3, []byte("a")); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if s.Next() != 3 {
		t.Fatalf("baseline next %d, want 3", s.Next())
	}
	if err := s.AppendAt(4, []byte("b")); err != nil {
		t.Fatalf("contiguous: %v", err)
	}
	if err := s.AppendAt(6, []byte("c")); err == nil {
		t.Fatal("gap accepted")
	}
	if err := s.AppendAt(4, []byte("d")); err == nil {
		t.Fatal("renumber accepted")
	}
	if err := s.AppendAt(0, nil); err == nil {
		t.Fatal("seq 0 accepted")
	}
	if s.Next() != 4 || s.Len() != 2 {
		t.Fatalf("next %d len %d after rejected appends", s.Next(), s.Len())
	}
}

func TestSenderElideKeepsSeq(t *testing.T) {
	s := NewSender(0)
	for i := 0; i < 3; i++ {
		s.Append([]byte("payload"))
	}
	ph := TrimmedEvent("s1", 2)
	if err := s.Elide(2, ph); err != nil {
		t.Fatalf("elide: %v", err)
	}
	entries := s.Entries()
	if len(entries) != 3 || entries[1].Seq != 2 || !bytes.Equal(entries[1].Payload, ph) {
		t.Fatalf("elided log %v", entries)
	}
	if s.Bytes() != 2*len("payload")+len(ph) {
		t.Fatalf("bytes %d after elide", s.Bytes())
	}
	if err := s.Elide(9, ph); err == nil {
		t.Fatal("elide of an unlogged seq accepted")
	}
}

func TestReceiverDuplicatesAndGaps(t *testing.T) {
	r := NewReceiver(0)
	if ready, ack, err := r.Accept(2, []byte("two")); err != nil || len(ready) != 0 || ack != 0 {
		t.Fatalf("park: ready %d ack %d err %v", len(ready), ack, err)
	}
	if r.Buffered() != 1 {
		t.Fatalf("buffered %d", r.Buffered())
	}
	// Duplicate parked frame: no second slot, no ack movement.
	if ready, ack, err := r.Accept(2, []byte("two")); err != nil || len(ready) != 0 || ack != 0 {
		t.Fatalf("duplicate park: ready %d ack %d err %v", len(ready), ack, err)
	}
	if r.Buffered() != 1 {
		t.Fatalf("buffered %d after duplicate", r.Buffered())
	}
	ready, ack, err := r.Accept(1, []byte("one"))
	if err != nil || ack != 2 || len(ready) != 2 || string(ready[0]) != "one" || string(ready[1]) != "two" {
		t.Fatalf("drain: ready %q ack %d err %v", ready, ack, err)
	}
	if ready, ack, err := r.Accept(1, nil); err != nil || len(ready) != 0 || ack != 2 {
		t.Fatalf("duplicate: ready %d ack %d err %v", len(ready), ack, err)
	}
	if _, _, err := r.Accept(0, nil); err == nil {
		t.Fatal("seq 0 accepted")
	}
	if r.Buffered() != 0 {
		t.Fatalf("buffered %d after drain", r.Buffered())
	}
}
