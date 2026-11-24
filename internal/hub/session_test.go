package hub

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/wire"
)

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
		Caps:   &wire.Caps{Deflate: true, TransportUnits: true},
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
	if ha.Limits == nil || *ha.Limits != SessionLimits {
		t.Fatalf("limits = %+v", ha.Limits)
	}
	if ha.Caps == nil || !ha.Caps.Deflate {
		t.Fatalf("caps = %+v, want deflate echo", ha.Caps)
	}
	if !ha.Caps.TransportUnits || !ha.Caps.RelayAck {
		t.Fatalf("caps = %+v, want transportUnits and relayAck echoed", ha.Caps)
	}
	if !ft.deflate {
		t.Fatal("deflate capability was not applied to the transport")
	}
	if ft.keepalive != time.Duration(SessionLiveness.Keepalive)*time.Second {
		t.Fatalf("keepalive = %s", ft.keepalive)
	}
	idle := time.Duration(SessionLiveness.Idle) * time.Second
	if ft.writeTimeout != idle*3/4 {
		t.Fatalf("write timeout = %s, want idle*3/4 = %s", ft.writeTimeout, idle*3/4)
	}
	if ft.maxFrame != SessionLimits.MaxFrame {
		t.Fatalf("maxFrame = %d, want the advertised %d", ft.maxFrame, SessionLimits.MaxFrame)
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
			first:  wire.NewHello(wire.Hello{Epoch: 1, Token: "nope", Resume: &wire.Resume{}, Caps: &wire.Caps{TransportUnits: true}}),
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
				first = wire.NewHello(wire.Hello{Epoch: 1, Token: token, Resume: &wire.Resume{}, Caps: &wire.Caps{TransportUnits: true}})
				go func() { h.ServeHost("other", ft) }()
			case "bad token":
				first = wire.NewHello(wire.Hello{Epoch: 1, Token: "nope", Resume: &wire.Resume{}, Caps: &wire.Caps{TransportUnits: true}})
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
	raw := `{"v":3,"type":"events","seq":1,"events":[` + chunkEvent(1, "a") + `,` + chunkEvent(3, "c") + `]}`
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

// TestSessionDuplicateEventsIgnored: a retransmitted events frame applies
// nothing, and the next new seq still continues the watermark.
func TestSessionDuplicateEventsIgnored(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	fh.events(1, 0, chunkEvent(1, "a"), chunkEvent(2, "b"))
	waitFor(t, func() bool { return h.LastSeq("h1") == 2 }, 2*time.Second)

	fh.events(1, 0, chunkEvent(1, "a"), chunkEvent(2, "b"))
	fh.events(3, 0, chunkEvent(3, "c"))
	waitFor(t, func() bool { return h.LastSeq("h1") == 3 }, 2*time.Second)
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

// TestSessionRequestSurvivesOneLostFrame: delivery is proven by the host's
// cumulative ack, and a lost request frame is replayed at RTO (2*keepalive).
// There is no ack deadline that could fail the request before that replay.
func TestSessionRequestSurvivesOneLostFrame(t *testing.T) {
	// Production liveness: keepalive 5s -> RTO 10s. The fake host does not
	// answer probes, so push the probe horizon past this test's retransmit.
	shortLiveness(t, 5, 20)
	shortProbe(t, 30*time.Second, 3*time.Second)
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	rto := 2 * time.Duration(SessionLiveness.Keepalive) * time.Second

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
	// The replay proves delivery: answer it.
	fh.send(wire.Frame{V: wire.ProtocolVersion, Type: wire.TypeHeartbeat, Ack: second.Seq, Status: json.RawMessage(`{}`)})
	fh.send(wire.Frame{
		V: wire.ProtocolVersion, Type: wire.TypeRespond, Ack: second.Seq, ChunkSeq: 1,
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
		V: wire.ProtocolVersion, Type: wire.TypeRespond, Ack: req.Seq, ChunkSeq: 1,
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
	shortLiveness(t, 1, 10)
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)

	go func() { _, _ = h.Dispatch(t.Context(), "h1", "GET", "/api/status", nil) }()

	first := fh.recvType(wire.TypeRequest, 2*time.Second)
	// The replay is scheduled at 2*keepalive; leave headroom for a loaded CI
	// scheduler without changing what the test proves.
	second := fh.recvType(wire.TypeRequest, 5*time.Second)
	if second.Seq != first.Seq || second.ReqID != first.ReqID {
		t.Fatalf("retransmit = seq %d req %q, want the original seq %d req %q",
			second.Seq, second.ReqID, first.Seq, first.ReqID)
	}
}
