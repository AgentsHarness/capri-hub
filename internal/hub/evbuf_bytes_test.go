package hub

import (
	"strings"
	"testing"
)

// The gap-pull buffer is bounded by bytes as well as by event count: the
// oldest events go first, while the delivery watermark keeps advancing.
func TestEvBufByteCapTrimsOldest(t *testing.T) {
	prev := evBufByteCap
	evBufByteCap = 400
	t.Cleanup(func() { evBufByteCap = prev })

	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	text := strings.Repeat("x", 100)
	for s := uint64(1); s <= 50; s++ {
		hubRaw(h, "h1", Event{"type": "chunk", "text": text, "seq": s})
	}

	// Trimming the gap-pull copy must not touch hs.acked/hs.seq.
	if got := h.LastSeq("h1"); got != 50 {
		t.Fatalf("watermark = %d, want 50 (evBuf trimming must not affect delivery accounting)", got)
	}

	h.mu.Lock()
	hs := h.hosts["h1"]
	h.mu.Unlock()
	hs.mu.Lock()
	n := len(hs.evBuf)
	bytes := hs.evBufBytes
	sum := eventsBytes(hs.evBuf)
	var oldest, newest uint64
	if n > 0 {
		oldest, newest = evSeq(hs.evBuf[0]), evSeq(hs.evBuf[n-1])
	}
	hs.mu.Unlock()

	if bytes > evBufByteCap {
		t.Fatalf("evBufBytes = %d, want <= %d", bytes, evBufByteCap)
	}
	if bytes != sum {
		t.Fatalf("evBufBytes = %d, actual buffer bytes = %d", bytes, sum)
	}
	if n == 0 || n >= 50 {
		t.Fatalf("evBuf holds %d of 50 events, want a non-empty trimmed tail", n)
	}
	if newest != 50 {
		t.Fatalf("newest buffered seq = %d, want 50", newest)
	}
	if oldest <= 40 {
		t.Fatalf("oldest buffered seq = %d, want only the newest events", oldest)
	}
	// A gap-pull sees exactly the retained tail.
	if evs := h.EventsAfter("h1", 0); len(evs) != n {
		t.Fatalf("EventsAfter returned %d events, want %d", len(evs), n)
	}
	// And the byte figure is visible in the diagnostics snapshot.
	stats := h.Stats()
	if len(stats.Hosts) != 1 {
		t.Fatalf("stats hosts = %d, want 1", len(stats.Hosts))
	}
	if got := stats.Hosts[0].EvBufBytes; got != bytes || got > evBufByteCap {
		t.Fatalf("stats evBufBytes = %d, want %d and <= %d", got, bytes, evBufByteCap)
	}
	if got := stats.Hosts[0].EvBufLen; got != n {
		t.Fatalf("stats evBufLen = %d, want %d", got, n)
	}
}

// A single event bigger than the whole byte budget cannot be kept: it is
// dropped, the buffer ends up empty, and the watermark still advances (the
// host's history and a fresh gap-pull have to cover the transcript).
func TestEvBufByteCapSmallerThanOneEvent(t *testing.T) {
	prev := evBufByteCap
	evBufByteCap = 32
	t.Cleanup(func() { evBufByteCap = prev })

	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	hubRaw(h, "h1", Event{"type": "chunk", "text": strings.Repeat("x", 200), "seq": uint64(1)})

	h.mu.Lock()
	hs := h.hosts["h1"]
	h.mu.Unlock()
	hs.mu.Lock()
	n, bytes := len(hs.evBuf), hs.evBufBytes
	hs.mu.Unlock()
	if n != 0 || bytes != 0 {
		t.Fatalf("evBuf = %d events / %d bytes, want empty", n, bytes)
	}
	if got := h.LastSeq("h1"); got != 1 {
		t.Fatalf("watermark = %d, want 1", got)
	}
}
