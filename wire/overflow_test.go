package wire

import (
	"errors"
	"testing"
)

func TestReceiverOverflow(t *testing.T) {
	r := NewReceiver(0)
	for seq := uint64(2); seq <= ResumeWindow+1; seq++ {
		ready, ack, err := r.Accept(seq, []byte{byte(seq)})
		if err != nil || len(ready) != 0 || ack != 0 {
			t.Fatalf("park seq %d: ready %d ack %d err %v", seq, len(ready), ack, err)
		}
	}
	if r.Buffered() != ResumeWindow {
		t.Fatalf("buffered %d, want %d", r.Buffered(), ResumeWindow)
	}

	_, ack, err := r.Accept(ResumeWindow+2, []byte("over"))
	if !errors.Is(err, ErrOverflow) {
		t.Fatalf("overflow err %v", err)
	}
	if ack != 0 || r.Acked() != 0 {
		t.Fatalf("overflow moved the watermark to %d (ack %d)", r.Acked(), ack)
	}
	if r.Buffered() != ResumeWindow {
		t.Fatalf("overflow changed the buffer to %d", r.Buffered())
	}

	// Filling the gap drains the whole parked run in order, without a jump.
	ready, ack, err := r.Accept(1, []byte("one"))
	if err != nil {
		t.Fatalf("fill gap: %v", err)
	}
	if ack != ResumeWindow+1 || len(ready) != ResumeWindow+1 {
		t.Fatalf("drain: ack %d ready %d", ack, len(ready))
	}
	for i, body := range ready {
		want := uint64(i + 1)
		if want > 1 && body[0] != byte(want) {
			t.Fatalf("drained #%d carried seq %d", i, body[0])
		}
	}
	if r.Buffered() != 0 {
		t.Fatalf("buffered %d after drain", r.Buffered())
	}

	// The window is free again.
	if _, _, err := r.Accept(ack+ResumeWindow, nil); err != nil {
		t.Fatalf("park after drain: %v", err)
	}
}

func TestReceiverWindowFromPeer(t *testing.T) {
	const window = 4
	r := NewReceiverWindow(0, window)
	if r.Window() != window {
		t.Fatalf("window %d, want %d", r.Window(), window)
	}
	for seq := uint64(2); seq <= window+1; seq++ {
		if _, ack, err := r.Accept(seq, []byte{byte(seq)}); err != nil || ack != 0 {
			t.Fatalf("park seq %d: ack %d err %v", seq, ack, err)
		}
	}
	// The advertised bound applies, not the package default.
	if _, ack, err := r.Accept(window+2, []byte("over")); !errors.Is(err, ErrOverflow) {
		t.Fatalf("overflow err %v (ack %d)", err, ack)
	}
	// A zero window falls back to the default rather than refusing every gap.
	if def := NewReceiverWindow(0, 0); def.Window() != ResumeWindow {
		t.Fatalf("fallback window %d, want %d", def.Window(), ResumeWindow)
	}
}

func TestReceiverOverflowKeepsExistingWatermark(t *testing.T) {
	r := NewReceiver(3)
	for seq := uint64(5); seq <= 4+ResumeWindow; seq++ {
		if _, ack, err := r.Accept(seq, nil); err != nil || ack != 3 {
			t.Fatalf("park seq %d: ack %d err %v", seq, ack, err)
		}
	}
	_, ack, err := r.Accept(5+ResumeWindow, nil)
	if !errors.Is(err, ErrOverflow) {
		t.Fatalf("overflow err %v", err)
	}
	if ack != 3 || r.Acked() != 3 {
		t.Fatalf("ack %d acked %d", ack, r.Acked())
	}
}
