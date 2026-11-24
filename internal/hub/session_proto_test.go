package hub

import (
	"context"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/wire"
)

// TestSessionAckBeyondNextDoesNotPoisonTheMirror: an ack for a seq the hub
// never sent is clamped to the watermark it actually has, and a later genuine
// ack still advances it. Recording the raw value would make every real ack
// look stale and stall the down log for the rest of the session.
func TestSessionAckBeyondNextDoesNotPoisonTheMirror(t *testing.T) {
	p := newSessionProto(1, 0)

	if got := p.ackDown(999); got != 0 {
		t.Fatalf("ack of an unsent seq advanced the watermark to %d", got)
	}
	seq, err := p.appendReliable(func(seq, ack uint64) wire.Frame {
		return wire.Frame{V: wire.ProtocolVersion, Type: wire.TypeRequest, Seq: seq, Ack: ack, ReqID: "r1", Method: "GET", Path: "/x"}
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if !p.hasUnacked() {
		t.Fatal("appended frame is not in the unacked log")
	}
	if got := p.ackDown(seq); got != seq {
		t.Fatalf("genuine ack of %d was clamped to %d", seq, got)
	}
	if p.hasUnacked() || p.downAcked() != seq {
		t.Fatalf("down log not drained: unacked=%v acked=%d", p.hasUnacked(), p.downAcked())
	}
}

// TestSessionResumeDownAdopted: a same-epoch resume adopts hello.resume.down
// as the down watermark, so frames the host already applied are not replayed
// and hello_ack reports the adopted value.
func TestSessionResumeDownAdopted(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")

	first := dialFakeHost(t, h, "h1", 5)
	for i := 1; i <= 5; i++ {
		go func() {
			_, _ = h.Dispatch(context.Background(), "h1", "GET", "/api/status", nil)
		}()
		if f := first.recvType(wire.TypeRequest, 2*time.Second); f.Seq != uint64(i) {
			t.Fatalf("down frame %d has seq %d", i, f.Seq)
		}
	}
	first.ft.hangup()
	first.waitReason(2 * time.Second)

	// The host applied 1..5; the hub must not replay them.
	second := dialFakeHostFull(t, h, "h1", 5, 0, 5)
	if got := second.ack.AckDown; got != 5 {
		t.Fatalf("hello_ack.ackDown = %d, want the adopted 5", got)
	}
	second.noFrame(300 * time.Millisecond)

	// The next frame continues the same down space.
	go func() {
		_, _ = h.Dispatch(context.Background(), "h1", "GET", "/api/status", nil)
	}()
	if f := second.recvType(wire.TypeRequest, 2*time.Second); f.Seq != 6 {
		t.Fatalf("first frame after resume has seq %d, want 6", f.Seq)
	}
}

// TestSessionUpGapClosesProtocol: the up log is gapless, so an events frame
// that does not continue the watermark ends the session with protocol and
// leaves the watermark where it was.
func TestSessionUpGapClosesProtocol(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHostResume(t, h, "h1", 1, 1)

	// The adopted baseline is 1, so the next live event is 2; seq 3 is a hole.
	fh.events(3, 0, chunkEvent(3, "c"))
	if got := fh.waitReason(2 * time.Second); got != wire.CloseProtocol {
		t.Fatalf("close = %s, want protocol", got)
	}
	if got := h.LastSeq("h1"); got != 1 {
		t.Fatalf("watermark = %d, want the adopted baseline 1", got)
	}
}

// stageFanout installs a host's fan-out queue without its drain goroutine, so
// a test sees exactly what the queue holds.
func stageFanout(t *testing.T, h *Hub, hostID string, n int) *hostState {
	t.Helper()
	h.mu.Lock()
	hs := h.hosts[hostID]
	h.mu.Unlock()
	if hs == nil {
		t.Fatalf("host %s is not paired", hostID)
	}
	hs.fanoutOnce.Do(func() {})
	hs.mu.Lock()
	hs.fanout = make(chan fanoutItem, n)
	hs.mu.Unlock()
	return hs
}

// drainFanout empties the queue the way its drain goroutine does: an item is
// delivered only while it still belongs to the host's live epoch.
func drainFanout(hs *hostState) []Event {
	var got []Event
	for {
		select {
		case item := <-hs.fanout:
			if hs.fanoutItemCurrent(item) {
				got = append(got, item.ev)
			}
		default:
			return got
		}
	}
}

// TestEpochResetQueuedBehindRetiredEvents: the subscribed{seq:baseline} reset
// travels through the per-host fan-out queue, so it is delivered after the
// items already queued for this host and before everything queued after it.
func TestEpochResetQueuedBehindRetiredEvents(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	dialFakeHost(t, h, "h1", 7)
	hs := stageFanout(t, h, "h1", 8)
	epoch := hs.epoch.Load()

	hs.enqueueFanout(h, "h1", Event{"v": 1, "type": "chunk", "hostId": "h1", "seq": uint64(3)}, epoch)
	h.mu.Lock()
	h.announceEpochReset(hs, 9)
	h.mu.Unlock()
	hs.enqueueFanout(h, "h1", Event{"v": 1, "type": "chunk", "hostId": "h1", "seq": uint64(10)}, epoch)

	got := drainFanout(hs)
	if len(got) != 3 {
		t.Fatalf("queue delivered %d events, want 3", len(got))
	}
	if got[0]["type"] != "chunk" || evSeq(got[0]) != 3 {
		t.Fatalf("first queued event = %v, want the earlier chunk 3", got[0])
	}
	if got[1]["type"] != "subscribed" || got[1]["host"] != "h1" || evSeq(got[1]) != 9 {
		t.Fatalf("second queued event = %v, want subscribed{host:h1,seq:9}", got[1])
	}
	if got[2]["type"] != "chunk" || evSeq(got[2]) != 10 {
		t.Fatalf("third queued event = %v, want chunk 10", got[2])
	}
}

// TestEpochResetDropsRetiredEpochFanout: ingest gates an event on the epoch
// under hs.mu and enqueues it after the lock is released, so attach can install
// a new epoch (and queue the reset) in between. That stale item must be dropped
// at the new epoch: delivered behind a baseline-0 reset, its high seq would be
// accepted by the FE and shadow every new-epoch event below it.
func TestEpochResetDropsRetiredEpochFanout(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	dialFakeHost(t, h, "h1", 7)
	hs := stageFanout(t, h, "h1", 8)
	retired := hs.epoch.Load()

	// Ingest passed its epoch check, buffered this event, and is about to
	// enqueue it when the attach below lands.
	hs.enqueueFanout(h, "h1", Event{"v": 1, "type": "chunk", "hostId": "h1", "seq": uint64(500)}, retired)

	// attach installs the new epoch, clears the buffer and queues the reset.
	hs.epoch.Store(retired + 1)
	h.mu.Lock()
	h.announceEpochReset(hs, 0)
	h.mu.Unlock()
	hs.enqueueFanout(h, "h1", Event{"v": 1, "type": "chunk", "hostId": "h1", "seq": uint64(1)}, retired+1)

	got := drainFanout(hs)
	if len(got) != 2 {
		t.Fatalf("queue delivered %v, want the reset plus the new-epoch event only", got)
	}
	if got[0]["type"] != "subscribed" || got[0]["host"] != "h1" || evSeq(got[0]) != 0 {
		t.Fatalf("first delivered event = %v, want subscribed{host:h1,seq:0}", got[0])
	}
	if got[1]["type"] != "chunk" || evSeq(got[1]) != 1 {
		t.Fatalf("second delivered event = %v, want the new epoch's chunk 1", got[1])
	}
}
