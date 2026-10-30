package hub

import (
	"context"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/wire"
)

// fakeTransport is the host end of one session link. Recv is unblocked by
// hangup (a peer close) or by Close (the hub ending the session).
type fakeTransport struct {
	inbox  chan []byte
	outbox chan []byte
	// closed carries the reason the hub closed with, once.
	closed chan wire.CloseReason
	done   chan struct{}

	closeOnce  sync.Once
	hangupOnce sync.Once
	// blockMu/block let a test make Send block like a wedged peer.
	blockMu sync.Mutex
	block   chan struct{}
	// keepalive records the cadence the session asked for.
	keepalive time.Duration
	// deflate records the caps.deflate echo the session applied.
	deflate bool
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{
		inbox:  make(chan []byte, 256),
		outbox: make(chan []byte, 512),
		closed: make(chan wire.CloseReason, 1),
		done:   make(chan struct{}),
	}
}

func (f *fakeTransport) setBlock(c chan struct{}) {
	f.blockMu.Lock()
	f.block = c
	f.blockMu.Unlock()
}

func (f *fakeTransport) Send(payload []byte) error {
	f.blockMu.Lock()
	block := f.block
	f.blockMu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-f.done:
			return io.ErrClosedPipe
		}
	}
	select {
	case f.outbox <- append([]byte(nil), payload...):
		return nil
	case <-f.done:
		return io.ErrClosedPipe
	}
}

func (f *fakeTransport) Recv() ([]byte, error) {
	select {
	case b, ok := <-f.inbox:
		if !ok {
			return nil, io.EOF
		}
		return b, nil
	case <-f.done:
		return nil, io.EOF
	}
}

func (f *fakeTransport) SetDeflate(v bool) { f.deflate = v }

func (f *fakeTransport) Close(r wire.CloseReason) error {
	f.closeOnce.Do(func() {
		f.closed <- r
		close(f.done)
	})
	return nil
}

func (f *fakeTransport) SetKeepalive(d time.Duration) { f.keepalive = d }

// hangup makes Recv fail the way a peer disconnect does.
func (f *fakeTransport) hangup() {
	f.hangupOnce.Do(func() { close(f.inbox) })
}

// fakeHost is a v2 host driven through the real hub.ServeHost path.
type fakeHost struct {
	t    *testing.T
	h    *Hub
	ft   *fakeTransport
	ack  wire.Frame // hello_ack
	end  chan wire.CloseReason
	done chan struct{} // closed when ServeHost returns, reason already sent
	host string
}

// dialFakeHost pairs hostID in h (call testPair first), performs the hello
// handshake and returns the connected fake host.
func dialFakeHost(t *testing.T, h *Hub, hostID string, epoch uint64) *fakeHost {
	t.Helper()
	return dialFakeHostResume(t, h, hostID, epoch, 0)
}

// dialFakeHostResume is dialFakeHost with an epoch baseline: the host declares
// that its event bus is already at resumeUp, so the first live event is
// resumeUp+1.
func dialFakeHostResume(t *testing.T, h *Hub, hostID string, epoch, resumeUp uint64) *fakeHost {
	t.Helper()
	return dialFakeHostFull(t, h, hostID, epoch, resumeUp, 0)
}

// dialFakeHostFull is dialFakeHostResume with an explicit resume.down: the
// highest down seq the host claims to have applied.
func dialFakeHostFull(t *testing.T, h *Hub, hostID string, epoch, resumeUp, resumeDown uint64) *fakeHost {
	t.Helper()
	h.mu.Lock()
	hs := h.hosts[hostID]
	var token string
	if hs != nil {
		token = hs.token
	}
	h.mu.Unlock()
	if token == "" {
		t.Fatalf("host %s is not paired", hostID)
	}

	ft := newFakeTransport()
	fh := &fakeHost{
		t: t, h: h, ft: ft,
		end:  make(chan wire.CloseReason, 1),
		done: make(chan struct{}),
		host: hostID,
	}
	go func() {
		reason := h.ServeHost("", ft)
		fh.end <- reason
		close(fh.done)
	}()
	t.Cleanup(func() {
		ft.hangup()
		select {
		case <-fh.done:
		case <-time.After(5 * time.Second):
		}
	})

	fh.send(wire.NewHello(wire.Hello{
		Epoch:  epoch,
		Token:  token,
		Resume: &wire.Resume{Up: resumeUp, Down: resumeDown},
	}))
	fh.ack = fh.recvType(wire.TypeHelloAck, 5*time.Second)
	if got := fh.ack.Epoch; got != epoch {
		t.Fatalf("hello_ack epoch = %d, want %d", got, epoch)
	}
	return fh
}

func (fh *fakeHost) send(f wire.Frame) {
	fh.t.Helper()
	b, err := wire.Encode(f)
	if err != nil {
		fh.t.Fatalf("encode %s: %v", f.Type, err)
	}
	select {
	case fh.ft.inbox <- b:
	case <-time.After(5 * time.Second):
		fh.t.Fatalf("send %s: session is not reading", f.Type)
	}
}

// recv returns the next frame from the hub.
func (fh *fakeHost) recv(timeout time.Duration) wire.Frame {
	fh.t.Helper()
	select {
	case b := <-fh.ft.outbox:
		f, err := wire.Decode(b)
		if err != nil {
			fh.t.Fatalf("decode downlink frame: %v (%s)", err, b)
		}
		return f
	case <-time.After(timeout):
		fh.t.Fatalf("no downlink frame within %s", timeout)
		return wire.Frame{}
	}
}

// recvType skips heartbeats until the wanted frame type arrives.
func (fh *fakeHost) recvType(typ string, timeout time.Duration) wire.Frame {
	fh.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			fh.t.Fatalf("no %s frame within %s", typ, timeout)
		}
		f := fh.recv(left)
		if f.Type == typ {
			return f
		}
	}
}

// noFrame asserts that nothing but heartbeats arrives within d.
func (fh *fakeHost) noFrame(d time.Duration) {
	fh.t.Helper()
	deadline := time.Now().Add(d)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return
		}
		select {
		case b := <-fh.ft.outbox:
			f, err := wire.Decode(b)
			if err != nil {
				fh.t.Fatalf("decode downlink frame: %v", err)
			}
			if f.Type != wire.TypeHeartbeat {
				fh.t.Fatalf("unexpected %s frame", f.Type)
			}
		case <-time.After(left):
			return
		}
	}
}

// events sends one contiguous events frame starting at seq; bodies are the
// JSON objects given (their seq must match the run).
func (fh *fakeHost) events(seq uint64, ack uint64, bodies ...string) {
	fh.t.Helper()
	raws := make([]json.RawMessage, len(bodies))
	for i, b := range bodies {
		raws[i] = json.RawMessage(b)
	}
	fh.send(wire.Frame{
		V: wire.ProtocolVersion, Type: wire.TypeEvents,
		Seq: seq, Ack: ack, Events: raws,
	})
}

// chunk builds one event body for events().
func chunkEvent(seq uint64, text string) string {
	b, err := json.Marshal(map[string]any{"type": "chunk", "seq": seq, "text": text})
	if err != nil {
		panic(err)
	}
	return string(b)
}

// shortLiveness shrinks the advertised time scale for one test.
func shortLiveness(t *testing.T, keepalive, idle int) {
	t.Helper()
	prev := SessionLiveness
	SessionLiveness = wire.Liveness{Keepalive: keepalive, Idle: idle}
	t.Cleanup(func() { SessionLiveness = prev })
}

// waitReason reads the close reason ServeHost returned.
func (fh *fakeHost) waitReason(timeout time.Duration) wire.CloseReason {
	fh.t.Helper()
	select {
	case r := <-fh.end:
		return r
	case <-time.After(timeout):
		fh.t.Fatalf("session did not end within %s", timeout)
		return 0
	}
}

// TestSessionAckBeyondNextDoesNotPoisonTheMirror: an ack for a seq the hub
// never sent is clamped to the watermark it actually has, and a later genuine
// ack still advances it. Recording the raw value would make every real ack
// look stale and stall the down log for the rest of the session.
func TestSessionAckBeyondNextDoesNotPoisonTheMirror(t *testing.T) {
	p := newSessionProto(1, 0, 8)

	if got := p.ackDown(999); got != 0 {
		t.Fatalf("ack of an unsent seq advanced the watermark to %d", got)
	}
	seq, err := p.appendReliable(func(seq, ack uint64) wire.Frame {
		return wire.NewAudience(seq, ack, wire.Audience{Gen: 1, Watchers: 1})
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

// TestSessionUpWindowFromAdvertisedLimits: the up receiver's overflow bound is
// the limits.resumeWindow the hub advertises, not a package constant.
func TestSessionUpWindowFromAdvertisedLimits(t *testing.T) {
	prev := SessionLimits
	SessionLimits = wire.DefaultLimits
	SessionLimits.ResumeWindow = 3
	t.Cleanup(func() { SessionLimits = prev })

	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)
	if fh.ack.Limits == nil || fh.ack.Limits.ResumeWindow != 3 {
		t.Fatalf("advertised limits = %+v, want resumeWindow 3", fh.ack.Limits)
	}

	// Seq 1 is missing; 2..5 park four frames, one past the advertised bound.
	fh.events(2, 0, chunkEvent(2, "b"), chunkEvent(3, "c"), chunkEvent(4, "d"), chunkEvent(5, "e"))
	if got := fh.waitReason(2 * time.Second); got != wire.CloseOverflow {
		t.Fatalf("close = %s, want overflow at the advertised window", got)
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

// TestSessionHandshake pins the hello_ack contents the host depends on: the
// authoritative watermarks, the audience snapshot with a non-zero generation,
// the advertised liveness and limits, and the deflate echo.
func TestSessionHandshake(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")

	ft := newFakeTransport()
	done := make(chan wire.CloseReason, 1)
	go func() { done <- h.ServeHost("", ft) }()
	defer func() {
		ft.hangup()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}()

	h.mu.Lock()
	token := h.hosts["h1"].token
	h.mu.Unlock()
	hello, err := wire.Encode(wire.NewHello(wire.Hello{
		Epoch:  42,
		Token:  token,
		Resume: &wire.Resume{Up: 7, Down: 3},
		Caps:   &wire.Caps{Deflate: true},
	}))
	if err != nil {
		t.Fatal(err)
	}
	ft.inbox <- hello

	var ack wire.Frame
	select {
	case b := <-ft.outbox:
		if ack, err = wire.Decode(b); err != nil {
			t.Fatalf("hello_ack: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no hello_ack")
	}
	if ack.Type != wire.TypeHelloAck {
		t.Fatalf("first frame = %q, want hello_ack", ack.Type)
	}
	ha, err := ack.HelloAck()
	if err != nil {
		t.Fatal(err)
	}
	if ha.Epoch != 42 || ha.AckUp != 7 || ha.AckDown != 0 {
		t.Fatalf("hello_ack = epoch %d ackUp %d ackDown %d, want 42/7/0 (resume.up is the new baseline)",
			ha.Epoch, ha.AckUp, ha.AckDown)
	}
	if ha.Audience == nil || ha.Audience.Gen != 1 || ha.Audience.Watchers != 0 {
		t.Fatalf("audience = %+v, want gen 1 / 0 watchers", ha.Audience)
	}
	if ha.Liveness == nil || *ha.Liveness != SessionLiveness {
		t.Fatalf("liveness = %+v, want %+v", ha.Liveness, SessionLiveness)
	}
	if ha.Limits == nil || ha.Limits.ResumeWindow != wire.ResumeWindow {
		t.Fatalf("limits = %+v", ha.Limits)
	}
	if ha.Caps == nil || !ha.Caps.Deflate {
		t.Fatalf("caps = %+v, want deflate echo", ha.Caps)
	}
	if !ft.deflate {
		t.Fatal("deflate capability was not applied to the transport")
	}
	if ft.keepalive != time.Duration(SessionLiveness.Keepalive)*time.Second {
		t.Fatalf("keepalive = %s", ft.keepalive)
	}
}

// TestSessionAuthRejects pins the handshake auth verdicts: an unknown token
// closes with auth, an expected host that disagrees with the token does too,
// and a non-hello first frame is a protocol violation.
func TestSessionAuthRejects(t *testing.T) {
	cases := []struct {
		name    string
		first   wire.Frame
		expect  wire.CloseReason
		prepare func(t *testing.T, h *Hub) string
	}{
		{
			name:   "bad token",
			first:  wire.NewHello(wire.Hello{Epoch: 1, Token: "nope", Resume: &wire.Resume{}}),
			expect: wire.CloseAuth,
		},
		{
			name:   "host mismatch",
			expect: wire.CloseAuth,
		},
		{
			name:   "not hello",
			first:  wire.Frame{V: wire.ProtocolVersion, Type: wire.TypeHeartbeat, Status: json.RawMessage(`{}`)},
			expect: wire.CloseProtocol,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := NewWithDir("")
			testPair(t, h, "h1", "H1")
			h.mu.Lock()
			token := h.hosts["h1"].token
			h.mu.Unlock()

			ft := newFakeTransport()
			first := tc.first
			switch tc.name {
			case "host mismatch":
				first = wire.NewHello(wire.Hello{Epoch: 1, Token: token, Resume: &wire.Resume{}})
				go func() { h.ServeHost("other", ft) }()
			case "bad token":
				first = wire.NewHello(wire.Hello{Epoch: 1, Token: "nope", Resume: &wire.Resume{}})
				go func() { h.ServeHost("", ft) }()
			default:
				go func() { h.ServeHost("", ft) }()
			}
			b, err := wire.Encode(first)
			if err != nil {
				t.Fatal(err)
			}
			ft.inbox <- b
			select {
			case r := <-ft.closed:
				if r != tc.expect {
					t.Fatalf("close reason = %s, want %s", r, tc.expect)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("session did not close")
			}
		})
	}
}

// TestSessionEpochResetResetsWatermarks: a reconnect with a new epoch starts
// both sequence spaces at zero, clears the gap-pull buffer and tells /ws/fe
// subscribers to reset their per-host watermark with subscribed{seq:0}.
func TestSessionEpochResetResetsWatermarks(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")

	ch, unsub := h.Subscribe()
	defer unsub()
	drainEvents(ch, 50*time.Millisecond)

	old := dialFakeHost(t, h, "h1", 1)
	old.events(1, 0, chunkEvent(1, "a"), chunkEvent(2, "b"))
	waitFor(t, func() bool { return h.LastSeq("h1") == 2 }, 2*time.Second)
	if evs := h.EventsAfter("h1", 0); len(evs) != 2 {
		t.Fatalf("gap-pull buffer = %d events, want 2", len(evs))
	}

	fresh := dialFakeHost(t, h, "h1", 2)
	if got := fresh.ack.AckUp; got != 0 {
		t.Fatalf("new epoch ackUp = %d, want 0", got)
	}
	if got := h.LastSeq("h1"); got != 0 {
		t.Fatalf("LastSeq after epoch change = %d, want 0", got)
	}
	if evs := h.EventsAfter("h1", 0); len(evs) != 0 {
		t.Fatalf("gap-pull buffer survived an epoch change (%d events)", len(evs))
	}
	var reset bool
	deadline := time.After(2 * time.Second)
	for !reset {
		select {
		case ev := <-ch:
			if ev["type"] == "subscribed" && ev["host"] == "h1" && evSeq(ev) == 0 {
				reset = true
			}
		case <-deadline:
			t.Fatal("no subscribed{seq:0} broadcast on the epoch change")
		}
	}
	// The audience generation never resets across an epoch change.
	if fresh.ack.Audience.Gen < old.ack.Audience.Gen {
		t.Fatalf("audience gen went backwards: %d → %d", old.ack.Audience.Gen, fresh.ack.Audience.Gen)
	}

	// The superseded transport is closed with the superseded verdict.
	if got := old.waitReason(2 * time.Second); got != wire.CloseSuperseded {
		t.Fatalf("old session close = %s, want superseded", got)
	}
}

// TestSessionSameEpochResume: reconnecting with the same epoch keeps the up
// watermark and does not reset the gap-pull buffer.
func TestSessionSameEpochResume(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")

	first := dialFakeHost(t, h, "h1", 7)
	first.events(1, 0, chunkEvent(1, "a"), chunkEvent(2, "b"))
	waitFor(t, func() bool { return h.LastSeq("h1") == 2 }, 2*time.Second)

	second := dialFakeHost(t, h, "h1", 7)
	if got := second.ack.AckUp; got != 2 {
		t.Fatalf("resume ackUp = %d, want 2", got)
	}
	if got := h.LastSeq("h1"); got != 2 {
		t.Fatalf("LastSeq after same-epoch resume = %d, want 2", got)
	}
	if evs := h.EventsAfter("h1", 0); len(evs) != 2 {
		t.Fatalf("gap-pull buffer = %d events, want 2 (resume keeps it)", len(evs))
	}
	if got := first.waitReason(2 * time.Second); got != wire.CloseSuperseded {
		t.Fatalf("first session close = %s, want superseded", got)
	}
}

// TestSessionEpochBaselineFromHello: a new epoch starts at the baseline the
// host declares in hello.resume.up, not at 0. The host's event bus may already
// be past events the hub never saw (the FE rebuilds those from history), so the
// first live event is baseline+1 and anything at or below it is a duplicate.
func TestSessionEpochBaselineFromHello(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	ch, unsub := h.Subscribe()
	defer unsub()
	drainEvents(ch, 50*time.Millisecond)

	fh := dialFakeHostResume(t, h, "h1", 3, 500)
	if got := fh.ack.AckUp; got != 500 {
		t.Fatalf("hello_ack ackUp = %d, want 500 (the declared baseline)", got)
	}
	if got := h.LastSeq("h1"); got != 500 {
		t.Fatalf("LastSeq after baseline hello = %d, want 500", got)
	}

	// The first live event continues the host's bus at baseline+1.
	fh.events(501, 0, chunkEvent(501, "live"))
	waitFor(t, func() bool { return h.LastSeq("h1") == 501 }, 2*time.Second)

	hbDeadline := time.Now().Add(2 * time.Second)
	for {
		hb := fh.recvType(wire.TypeHeartbeat, time.Until(hbDeadline))
		if hb.Ack == 501 {
			break
		}
		if time.Now().After(hbDeadline) {
			t.Fatalf("heartbeat ack = %d, want 501", hb.Ack)
		}
	}

	// A retransmission at or below the baseline is a duplicate: applied
	// nothing, opens no hole, and must not reach a browser.
	fh.events(500, 0, chunkEvent(500, "old"))
	fh.noFrame(200 * time.Millisecond)
	if got := h.LastSeq("h1"); got != 501 {
		t.Fatalf("LastSeq after duplicate = %d, want 501", got)
	}

	// The live event itself was fanned out, the duplicate was not.
	var sawLive bool
	for {
		select {
		case ev := <-ch:
			if ev["type"] != "chunk" {
				continue // subscribed{seq:baseline} and other hub-level noise
			}
			if evSeq(ev) == 500 {
				t.Fatalf("duplicate event 500 was fanned out: %v", ev)
			}
			if evSeq(ev) == 501 {
				sawLive = true
			}
			continue
		case <-time.After(100 * time.Millisecond):
		}
		break
	}
	if !sawLive {
		t.Fatal("event 501 was not fanned out")
	}
}

// TestSessionEventsAckAndFanout: applied events advance the watermark, are
// fanned out to browsers in order, and the host is acked immediately.
func TestSessionEventsAckAndFanout(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	ch, unsub := h.Subscribe()
	defer unsub()
	drainEvents(ch, 50*time.Millisecond)

	fh := dialFakeHost(t, h, "h1", 1)
	fh.events(1, 0, chunkEvent(1, "a"), chunkEvent(2, "b"))
	fh.events(3, 0, chunkEvent(3, "c"))

	var seqs []uint64
	deadline := time.After(2 * time.Second)
	for len(seqs) < 3 {
		select {
		case ev := <-ch:
			if ev["hostId"] == "h1" {
				seqs = append(seqs, evSeq(ev))
			}
		case <-deadline:
			t.Fatalf("only got %v", seqs)
		}
	}
	if seqs[0] != 1 || seqs[1] != 2 || seqs[2] != 3 {
		t.Fatalf("fan-out order = %v, want 1 2 3", seqs)
	}

	// The ack of the last frame is confirmed, possibly after an earlier one.
	hbDeadline := time.Now().Add(2 * time.Second)
	for {
		hb := fh.recvType(wire.TypeHeartbeat, time.Until(hbDeadline))
		if hb.Ack == 3 {
			break
		}
		if time.Now().After(hbDeadline) {
			t.Fatalf("last heartbeat ack = %d, want 3", hb.Ack)
		}
	}
	if got := h.LastSeq("h1"); got != 3 {
		t.Fatalf("LastSeq = %d, want 3", got)
	}
}

// TestSessionRejectsHole: an events frame that skips a seq is unreadable; the
// watermark must not jump over the hole.
func TestSessionRejectsHole(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	// A batch that opens a hole inside itself is unreadable. It is sent as
	// raw bytes because the encoder rejects it on the same check.
	raw := `{"v":2,"type":"events","seq":1,"events":[` + chunkEvent(1, "a") + `,` + chunkEvent(3, "c") + `]}`
	select {
	case fh.ft.inbox <- []byte(raw):
	case <-time.After(2 * time.Second):
		t.Fatal("send rejected")
	}
	if got := fh.waitReason(2 * time.Second); got != wire.CloseUnreadable {
		t.Fatalf("close reason = %s, want unreadable", got)
	}
	if got := h.LastSeq("h1"); got != 0 {
		t.Fatalf("watermark jumped to %d", got)
	}
}

// TestSessionOverflowClose: parking more than the resume window ends the
// session with overflow and leaves the watermark where it was.
func TestSessionOverflowClose(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	// seq 1 is missing; everything from 2 past the window parks.
	for i := uint64(0); i <= wire.ResumeWindow; i++ {
		seq := uint64(2) + i
		fh.send(wire.Frame{
			V: wire.ProtocolVersion, Type: wire.TypeEvents, Seq: seq,
			Events: []json.RawMessage{json.RawMessage(chunkEvent(seq, "x"))},
		})
	}
	if got := fh.waitReason(5 * time.Second); got != wire.CloseOverflow {
		t.Fatalf("close reason = %s, want overflow", got)
	}
	if got := h.LastSeq("h1"); got != 0 {
		t.Fatalf("watermark = %d, want 0", got)
	}
}

// TestSessionIdleClose: a session that receives no frame for liveness.idle is
// closed with liveness and the host goes offline.
func TestSessionIdleClose(t *testing.T) {
	shortLiveness(t, 1, 2)
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)
	waitFor(t, func() bool { return h.ListHosts()[0].Online }, time.Second)

	if got := fh.waitReason(5 * time.Second); got != wire.CloseLiveness {
		t.Fatalf("close reason = %s, want liveness", got)
	}
	waitFor(t, func() bool { return !h.ListHosts()[0].Online }, time.Second)
}

// TestSessionRequestAckDeadline: a request frame the host never acks fails
// that request alone, without a "host sent anything" heuristic. The deadline
// is derived from the advertised liveness (three heartbeats), not a fixed
// second count.
func TestSessionRequestAckDeadline(t *testing.T) {
	// idle above the deadline, so the request fails on its own clock rather
	// than on the session's liveness close.
	shortLiveness(t, 1, 10)
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	h.mu.Lock()
	deadline := h.hosts["h1"].proto.reqAckDeadline
	h.mu.Unlock()
	if want := 3 * time.Duration(SessionLiveness.Keepalive) * time.Second; deadline != want {
		t.Fatalf("request ack deadline = %s, want 3*keepalive = %s", deadline, want)
	}

	// The fake host never acks, so the dispatch must fail on its deadline.
	start := time.Now()
	resp, err := h.Dispatch(t.Context(), "h1", "GET", "/api/status", nil)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	elapsed := time.Since(start)
	if resp.Status != 503 {
		t.Fatalf("dispatch status = %d, want 503 (request frame never acked)", resp.Status)
	}
	if elapsed < deadline {
		t.Fatalf("dispatch failed after %s, before the %s deadline", elapsed, deadline)
	}
	if elapsed > deadline+5*time.Second {
		t.Fatalf("dispatch waited %s for a %s deadline", elapsed, deadline)
	}
	// The request frame was on the wire exactly as the protocol defines it.
	f := fh.recvType(wire.TypeRequest, 2*time.Second)
	if f.ReqID == "" || f.Method != "GET" || f.Path != "/api/status" {
		t.Fatalf("request frame = %+v", f)
	}
}

// TestSessionRequestSurvivesOneLostFrame: delivery is proven by the host's
// cumulative ack, and a lost request frame is replayed at RTO (2*keepalive).
// The request deadline must outlive that retransmit, or a single loss fails a
// request the session already repaired; it is 3*keepalive for exactly that
// reason.
func TestSessionRequestSurvivesOneLostFrame(t *testing.T) {
	shortLiveness(t, 1, 5)
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	rto := 2 * time.Duration(SessionLiveness.Keepalive) * time.Second
	h.mu.Lock()
	deadline := h.hosts["h1"].proto.reqAckDeadline
	h.mu.Unlock()
	if deadline <= rto {
		t.Fatalf("request ack deadline %s does not outlive the %s retransmit timer", deadline, rto)
	}

	done := make(chan RelayResponse, 1)
	go func() {
		resp, _ := h.Dispatch(t.Context(), "h1", "GET", "/api/status", nil)
		done <- resp
	}()

	// Lose the first request frame: receive it and ack nothing.
	first := fh.recvType(wire.TypeRequest, 2*time.Second)
	second := fh.recvType(wire.TypeRequest, rto+2*time.Second)
	if second.Seq != first.Seq || second.ReqID != first.ReqID {
		t.Fatalf("retransmit = seq %d req %q, want the original seq %d req %q",
			second.Seq, second.ReqID, first.Seq, first.ReqID)
	}
	// The replay proves delivery before the deadline: answer it.
	fh.send(wire.Frame{V: wire.ProtocolVersion, Type: wire.TypeHeartbeat, Ack: second.Seq, Status: json.RawMessage(`{}`)})
	fh.send(wire.Frame{
		V: wire.ProtocolVersion, Type: wire.TypeRespond, Ack: second.Seq,
		ReqID: second.ReqID, Status: json.RawMessage(`200`), Body: json.RawMessage(`{"ok":true}`),
	})
	select {
	case resp := <-done:
		if resp.Status != 200 {
			t.Fatalf("status = %d, want 200 after one lost request frame", resp.Status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dispatch did not resolve after the request was retransmitted")
	}
}

// TestSessionRequestAckStopsRetransmit: once the host acks the request frame,
// it stops being retransmitted, and an answer resolves the dispatch.
func TestSessionRequestAckStopsRetransmit(t *testing.T) {
	shortLiveness(t, 1, 4)
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	type result struct {
		resp RelayResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := h.Dispatch(t.Context(), "h1", "GET", "/api/status", nil)
		done <- result{resp, err}
	}()

	req := fh.recvType(wire.TypeRequest, 2*time.Second)
	// Ack the request frame, then answer it.
	fh.send(wire.Frame{V: wire.ProtocolVersion, Type: wire.TypeHeartbeat, Ack: req.Seq, Status: json.RawMessage(`{}`)})
	fh.send(wire.Frame{
		V: wire.ProtocolVersion, Type: wire.TypeRespond, Ack: req.Seq,
		ReqID: req.ReqID, Status: json.RawMessage(`200`), Body: json.RawMessage(`{"ok":true}`),
	})
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("dispatch: %v", r.err)
		}
		if r.resp.Status != 200 {
			t.Fatalf("status = %d", r.resp.Status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dispatch did not resolve")
	}
	// No retransmission after the ack: only heartbeats may arrive.
	fh.noFrame(1500 * time.Millisecond)
}

// TestSessionRetransmitsUnackedRequest: an unacked down frame is replayed at
// RTO (2*keepalive), byte-identical, with no max-retry counter.
func TestSessionRetransmitsUnackedRequest(t *testing.T) {
	shortLiveness(t, 1, 5)
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	go func() { _, _ = h.Dispatch(t.Context(), "h1", "GET", "/api/status", nil) }()

	first := fh.recvType(wire.TypeRequest, 2*time.Second)
	second := fh.recvType(wire.TypeRequest, 3*time.Second)
	if second.Seq != first.Seq || second.ReqID != first.ReqID {
		t.Fatalf("retransmit = seq %d req %q, want the original seq %d req %q",
			second.Seq, second.ReqID, first.Seq, first.ReqID)
	}
}

// TestSessionDownOverflowCloses: a down log over its byte budget is a hard
// stop — the hub closes with overflow rather than buffering without limit.
// The budget follows the advertised limits.maxRelayBody (2x), so shrinking the
// advertised cap shrinks the log budget with it.
func TestSessionDownOverflowCloses(t *testing.T) {
	prev := SessionLimits
	SessionLimits = wire.DefaultLimits
	SessionLimits.MaxRelayBody = 1 << 10
	t.Cleanup(func() { SessionLimits = prev })

	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	body := json.RawMessage(`{"pad":"` + strings.Repeat("x", 4<<10) + `"}`)
	if _, err := h.Dispatch(t.Context(), "h1", "POST", "/api/prompt", body); err == nil {
		t.Fatal("oversized dispatch was accepted")
	}
	if got := fh.waitReason(2 * time.Second); got != wire.CloseOverflow {
		t.Fatalf("close reason = %s, want overflow", got)
	}
}

// TestSessionAudienceNotify: a browser subscribing produces one audience
// frame with a new generation; an unchanged snapshot is not resent.
func TestSessionAudienceNotify(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)
	gen0 := fh.ack.Audience.Gen

	_, unsub := h.Subscribe()
	f := fh.recvType(wire.TypeAudience, 2*time.Second)
	a := f.AudienceState()
	if a.Watchers != 1 || a.Gen <= gen0 {
		t.Fatalf("audience = %+v, want watchers 1 and gen > %d", a, gen0)
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("audience is invalid: %v", err)
	}

	// A notify with an unchanged snapshot must not produce a frame.
	h.notifyAudience()
	fh.noFrame(200 * time.Millisecond)

	unsub()
	f = fh.recvType(wire.TypeAudience, 2*time.Second)
	if a := f.AudienceState(); a.Watchers != 0 || a.Gen <= gen0+1 {
		t.Fatalf("audience after unsub = %+v", a)
	}
}

// TestSessionHeartbeatStatus: an hb snapshot is applied to the registry and
// the host's ack releases the down log.
func TestSessionHeartbeatStatus(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	busy, ready := true, true
	st := wire.HeartbeatStatus{Ready: ready, Busy: busy, PendingCount: 2, Port: 8765}
	frame, err := wire.NewHeartbeat(0, st)
	if err != nil {
		t.Fatal(err)
	}
	fh.send(frame)
	waitFor(t, func() bool {
		hosts := h.ListHosts()
		return hosts[0].Busy && hosts[0].PendingCount == 2 && hosts[0].Port == 8765
	}, 2*time.Second)
}

// TestSessionUnreadableFrame: a transport that reports an undecodable frame
// ends the session with unreadable so the host replays from its log.
func TestSessionUnreadableFrame(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	ft := newFakeTransport()
	done := make(chan wire.CloseReason, 1)
	go func() { done <- h.ServeHost("", ft) }()

	h.mu.Lock()
	token := h.hosts["h1"].token
	h.mu.Unlock()
	b, _ := wire.Encode(wire.NewHello(wire.Hello{Epoch: 1, Token: token, Resume: &wire.Resume{}}))
	ft.inbox <- b
	select {
	case <-ft.outbox:
	case <-time.After(2 * time.Second):
		t.Fatal("no hello_ack")
	}

	ft.hangup() // the transport maps its own decode failures to an error
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("session did not end")
	}
}

// ── hub-side test hooks ──────────────────────────────────────────────

// testSession returns hostID's current session, attaching a quiet one that is
// never run when the test does not need a transport. Ingest goes through the
// same path the wire uses; the watermark mirror is updated here because the
// session loop is what normally does it.
func testSession(h *Hub, hostID string) *session {
	h.mu.Lock()
	defer h.mu.Unlock()
	hs := h.hosts[hostID]
	if hs == nil {
		return nil
	}
	if hs.session != nil {
		return hs.session
	}
	if hs.proto == nil {
		hs.proto = newSessionProto(1, 0, SessionLimits.ResumeWindow)
		hs.epoch.Store(1)
		hs.upAcked.Store(0)
	}
	hs.session = &session{
		h:      h,
		hostID: hostID,
		epoch:  hs.proto.epoch,
		proto:  hs.proto,
		wake:   make(chan struct{}, 1),
		stop:   make(chan struct{}),
	}
	hs.info.Online = true
	return hs.session
}

// viewingView is the wire-relevant part of an audience snapshot, for tests
// that only care which sessions the host may filter against.
type viewingView struct {
	All      bool
	Sessions []string
}

// testViewing resolves hostID's viewing set the way audienceLocked does.
func testViewing(h *Hub, hostID string) (viewingView, uint64, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	set := h.viewingSetLocked(hostID)
	if set == nil {
		return viewingView{}, 0, false
	}
	if set.all {
		return viewingView{All: true}, 0, true
	}
	out := viewingView{Sessions: make([]string, 0, len(set.sessions))}
	for sid := range set.sessions {
		out.Sessions = append(out.Sessions, sid)
	}
	sort.Strings(out.Sessions)
	return out, 0, true
}

// testIngest applies raw event bodies as hostID's session.
func testIngest(h *Hub, hostID string, raws []json.RawMessage) bool {
	s := testSession(h, hostID)
	if s == nil {
		return false
	}
	if !h.ingestRawEvents(s, raws) {
		return false
	}
	var max uint64
	for _, raw := range raws {
		var meta rawEventMeta
		if json.Unmarshal(raw, &meta) == nil && meta.Seq > max {
			max = meta.Seq
		}
	}
	if max > 0 {
		h.mu.Lock()
		if hs := h.hosts[hostID]; hs != nil && hs.session == s && max > hs.upAcked.Load() {
			hs.upAcked.Store(max)
		}
		h.mu.Unlock()
	}
	return true
}
