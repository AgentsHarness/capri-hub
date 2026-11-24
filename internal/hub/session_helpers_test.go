package hub

import (
	"encoding/json"
	"io"
	"sort"
	"sync"
	"sync/atomic"
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
	// lastRead is when Recv last returned a frame.
	lastRead atomic.Int64
	// writeTimeout / maxFrame record the handshake tuning.
	writeTimeout time.Duration
	maxFrame     int
	// fragmentHook runs after each accepted unit, so a test can interleave
	// inbound traffic with a frame's fragment run.
	hookMu       sync.Mutex
	fragmentHook func()
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

func (f *fakeTransport) waitBlock() error {
	f.blockMu.Lock()
	block := f.block
	f.blockMu.Unlock()
	if block == nil {
		return nil
	}
	select {
	case <-block:
		return nil
	case <-f.done:
		return io.ErrClosedPipe
	}
}

func (f *fakeTransport) Send(payload []byte) error {
	if err := f.waitBlock(); err != nil {
		return err
	}
	select {
	case f.outbox <- append([]byte(nil), payload...):
		return nil
	case <-f.done:
		return io.ErrClosedPipe
	}
}

// SendFragment records one transport unit in the same stream as Send; the
// outbox is the transport's wire, not a frame queue.
func (f *fakeTransport) SendFragment(unit []byte) error {
	if err := f.Send(unit); err != nil {
		return err
	}
	f.hookMu.Lock()
	hook := f.fragmentHook
	f.hookMu.Unlock()
	if hook != nil {
		hook()
	}
	return nil
}

func (f *fakeTransport) onFragment(hook func()) {
	f.hookMu.Lock()
	f.fragmentHook = hook
	f.hookMu.Unlock()
}

func (f *fakeTransport) Recv() ([]byte, error) {
	select {
	case b, ok := <-f.inbox:
		if !ok {
			return nil, io.EOF
		}
		f.lastRead.Store(time.Now().UnixNano())
		return b, nil
	case <-f.done:
		return nil, io.EOF
	}
}

func (f *fakeTransport) LastActivity() time.Time {
	n := f.lastRead.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
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

func (f *fakeTransport) SetWriteTimeout(d time.Duration) { f.writeTimeout = d }

func (f *fakeTransport) SetMaxFrame(n int) { f.maxFrame = n }

// hangup makes Recv fail the way a peer disconnect does.
func (f *fakeTransport) hangup() {
	f.hangupOnce.Do(func() { close(f.inbox) })
}

// fakeHost is a v3 host driven through the real hub.ServeHost path.
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
		Caps:   &wire.Caps{TransportUnits: true},
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
		hs.proto = newSessionProto(1, 0)
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

// ── P1-1: writer goroutine, framing, probes, LastSeen ────────────────

// shortProbe shrinks the probe timers for one test.
func shortProbe(t *testing.T, after, timeout time.Duration) {
	t.Helper()
	prevAfter, prevTimeout := probeAfter, probeTimeout
	probeAfter, probeTimeout = after, timeout
	t.Cleanup(func() {
		probeAfter, probeTimeout = prevAfter, prevTimeout
	})
}

// recvRaw returns the next raw transport message (a complete frame or one
// transport unit) from the hub.
func (fh *fakeHost) recvRaw(timeout time.Duration) []byte {
	fh.t.Helper()
	select {
	case b := <-fh.ft.outbox:
		return b
	case <-time.After(timeout):
		fh.t.Fatalf("no downlink message within %s", timeout)
		return nil
	}
}

// waitWriterBusy waits until the session's writer is inside a write.
func waitWriterBusy(t *testing.T, h *Hub, hostID string) {
	t.Helper()
	waitFor(t, func() bool {
		h.mu.Lock()
		s := h.hosts[hostID].session
		h.mu.Unlock()
		w := (*writer)(nil)
		if s != nil {
			w = s.writer.Load()
		}
		return w != nil && w.Busy()
	}, 2*time.Second)
}
