package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/internal/hub"
	"github.com/coder/websocket"
)

// pairedHost starts a hub, pairs one host and returns the token. The
// probe tests share this because pairing is the slow, boilerplate part.
func pairedHost(t *testing.T, h *hub.Hub, srv *httptest.Server) string {
	t.Helper()
	code, _ := h.PairingCode()
	body, _ := json.Marshal(map[string]string{"code": code, "hostId": "h1", "hostName": "H1"})
	resp, err := http.Post(srv.URL+"/api/pair", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	defer resp.Body.Close()
	var res struct {
		OK    bool   `json:"ok"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("pair decode: %v", err)
	}
	if !res.OK || res.Token == "" {
		t.Fatalf("pair: %+v", res)
	}
	return res.Token
}

// probeTiming shrinks the liveness probe so a test can observe it, and
// restores the production values afterwards. Idle defaults to
// probeIdleDisabled so the existing tests keep their old semantics ("probe
// every tick, no idle gate"); tests about the gate itself set it explicitly.
//
// All three knobs are atomic because a handler that outlives this test —
// httptest.Server.Close does not wait for a hijacked WebSocket — is still
// allowed to read them.
func probeTiming(t *testing.T, interval, timeout time.Duration) {
	t.Helper()
	prevInterval := hostProbeInterval.Swap(int64(interval))
	prevTimeout := hostProbeTimeout.Swap(int64(timeout))
	prevIdle := hostProbeIdleAfter.Swap(int64(probeIdleDisabled))
	t.Cleanup(func() {
		hostProbeInterval.Store(prevInterval)
		hostProbeTimeout.Store(prevTimeout)
		hostProbeIdleAfter.Store(prevIdle)
	})
}

// probeIdleDisabled opens the idle gate on the very first tick. It is not a
// production value: the tests that only care about "does the probe fire"
// must not race the idle rule while the clock advances.
const probeIdleDisabled = time.Nanosecond

// withProbeIdle sets the idle gate for a test that is about the gate, after
// probeTiming has installed the rest.
func withProbeIdle(t *testing.T, idle time.Duration) {
	t.Helper()
	hostProbeIdleAfter.Store(int64(idle))
}

// waitHostOnline polls until the transport has registered the host. The
// registry entry exists as soon as the host is paired, so an "is it online"
// assertion made right after Dial can catch the handler before ConnectStream
// and read a false negative.
func waitHostOnline(t *testing.T, h *hub.Hub, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if hosts := h.ListHosts(); len(hosts) == 1 && hosts[0].Online {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("host never came online: %+v", h.ListHosts())
}

// waitHostGone polls the hub registry until the host is marked offline,
// failing the test if that never happens.
func waitHostGone(t *testing.T, h *hub.Hub, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		hosts := h.ListHosts()
		if len(hosts) == 1 && !hosts[0].Online {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	hosts := h.ListHosts()
	online := len(hosts) == 1 && hosts[0].Online
	t.Fatalf("host still online=%v after %s; the probe never fired", online, within)
}

// A host that answers pongs stays online well past several probe rounds.
// This is the control case: it proves the probe does not manufacture
// disconnects on a healthy, otherwise-silent link.
func TestHostProbeKeepsLiveHostOnline(t *testing.T) {
	probeTiming(t, 40*time.Millisecond, 40*time.Millisecond)

	h := hub.NewWithDir("")
	srv := httptest.NewServer(buildHandler(h, "secret", newFETicketStore(), newPairLimiter(), nil))
	defer srv.Close()
	tok := pairedHost(t, h, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/host",
		&websocket.DialOptions{HTTPHeader: http.Header{
			"Authorization":   []string{"Bearer " + tok},
			"X-Hub-Deflate":   []string{"1"},
			"X-Hub-State-Ack": []string{"1"},
		}})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	// Keep reading so the library can answer the hub's pings with pongs;
	// receiving a ping is what triggers the automatic pong reply.
	go func() {
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
		}
	}()

	// Ten probe rounds at 40ms: a live host must survive all of them.
	time.Sleep(400 * time.Millisecond)
	hosts := h.ListHosts()
	if len(hosts) != 1 || !hosts[0].Online {
		t.Fatalf("live host was dropped by the probe: %+v", hosts)
	}
}

// A JSON pong proves the uplink (the per-request silence check) and
// nothing else. It must not keep the registry online: LastSeen moves
// on host_status and other application frames. This host sends pongs
// and nothing else, and swallows control pings so those cannot mask it.
func TestJSONPongDoesNotRefreshLastSeen(t *testing.T) {
	// Keep the probe out of the way: detection must come from the sweep.
	probeTiming(t, time.Hour, time.Hour)
	// A fast JSON-ping cadence: this test is about the pong answering it.
	prevPing := hostPingInterval
	hostPingInterval = 20 * time.Millisecond
	t.Cleanup(func() { hostPingInterval = prevPing })
	prevSilence, prevSweep := hub.HostSilenceTimeout, hub.LivenessCheckInterval
	hub.HostSilenceTimeout = 120 * time.Millisecond
	hub.LivenessCheckInterval = 20 * time.Millisecond
	h := hub.NewWithDir("")
	runCtx, runCancel := context.WithCancel(context.Background())
	waitSweep := h.StartLivenessWatchdog(runCtx)
	t.Cleanup(func() {
		runCancel()
		waitSweep()
		hub.HostSilenceTimeout = prevSilence
		hub.LivenessCheckInterval = prevSweep
	})

	srv := httptest.NewServer(buildHandler(h, "secret", newFETicketStore(), newPairLimiter(), nil))
	defer srv.Close()
	tok := pairedHost(t, h, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/host",
		&websocket.DialOptions{
			HTTPHeader: http.Header{
				"Authorization":   []string{"Bearer " + tok},
				"X-Hub-Deflate":   []string{"1"},
				"X-Hub-State-Ack": []string{"1"},
			},
			// No control-pong: only the JSON pong may keep the host alive.
			OnPingReceived: func(context.Context, []byte) bool { return false },
		})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	replyToPings := make(chan struct{})
	go func() {
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var f struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(data, &f) != nil || f.Type != "ping" {
				continue
			}
			pong, _ := json.Marshal(map[string]any{"v": 1, "type": "pong"})
			if err := conn.Write(ctx, websocket.MessageText, pong); err != nil {
				return
			}
			select {
			case <-replyToPings:
			default:
				close(replyToPings)
			}
		}
	}()
	// Wait until at least one JSON pong is on the wire — the registry may
	// otherwise be judged before any evidence exists.
	select {
	case <-replyToPings:
	case <-time.After(5 * time.Second):
		t.Fatal("hub never sent a JSON ping")
	}

	waitHostGone(t, h, time.Second)
	// Pongs keep arriving. They must not bring the registry back.
	deadline := time.Now().Add(4 * hub.HostSilenceTimeout)
	for time.Now().Before(deadline) {
		hosts := h.ListHosts()
		if len(hosts) != 1 || hosts[0].Online {
			t.Fatalf("JSON pong restored the registry: %+v", hosts)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A control pong keeps the socket (the probe succeeds) and does not
// move LastSeen. With no host_status, the sweep marks the host offline
// even though every probe is answered.
func TestControlPongDoesNotRefreshLastSeen(t *testing.T) {
	// The probe runs many times per silence window and is answered. The
	// pong budget is wide enough that a scheduling hiccup cannot make the
	// probe drop the socket. The sweep is what this test is watching.
	probeTiming(t, 20*time.Millisecond, 400*time.Millisecond)
	prevSilence, prevSweep := hub.HostSilenceTimeout, hub.LivenessCheckInterval
	hub.HostSilenceTimeout = 250 * time.Millisecond
	hub.LivenessCheckInterval = 25 * time.Millisecond
	h := hub.NewWithDir("")
	runCtx, runCancel := context.WithCancel(context.Background())
	// The sweep is normally started by main; the handler tests build the
	// mux by hand, so run it here — the point is to prove a control pong
	// does not defeat it.
	waitSweep := h.StartLivenessWatchdog(runCtx)
	// Restore after the watcher is gone: it reads both knobs every tick.
	t.Cleanup(func() {
		runCancel()
		waitSweep()
		hub.HostSilenceTimeout = prevSilence
		hub.LivenessCheckInterval = prevSweep
	})

	srv := httptest.NewServer(buildHandler(h, "secret", newFETicketStore(), newPairLimiter(), nil))
	defer srv.Close()

	tok := pairedHost(t, h, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/host",
		&websocket.DialOptions{HTTPHeader: http.Header{
			"Authorization":   []string{"Bearer " + tok},
			"X-Hub-Deflate":   []string{"1"},
			"X-Hub-State-Ack": []string{"1"},
		}})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	// Reading is what makes the library answer pings with pongs. No JSON
	// frame is sent in either direction beyond the hub's own hello/pings.
	go func() {
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
		}
	}()

	waitHostOnline(t, h, 3*time.Second)
	waitHostGone(t, h, time.Second)
}

// The mirror case for the SWEEP path (TestHostProbeDropsSilentHost covers
// the probe path). With pongs suppressed, LastSeen only advances on JSON
// frames, so the registry watchdog must mark the host offline even though
// its socket is still open. This is the guarantee that lets the host slow
// its host_status heartbeat down: silence without pongs still means dead.
func TestHostSweepDropsHostWithoutPongs(t *testing.T) {
	// Keep the probe out of the way: detection must come from the sweep.
	probeTiming(t, time.Hour, time.Hour)
	prevSilence, prevSweep := hub.HostSilenceTimeout, hub.LivenessCheckInterval
	hub.HostSilenceTimeout = 50 * time.Millisecond
	hub.LivenessCheckInterval = 10 * time.Millisecond
	h := hub.NewWithDir("")
	runCtx, runCancel := context.WithCancel(context.Background())
	// The watcher reads the knobs every tick, so the restore has to happen
	// after it is gone: cancel, wait, then put the globals back.
	waitSweep := h.StartLivenessWatchdog(runCtx)
	t.Cleanup(func() {
		runCancel()
		waitSweep()
		hub.HostSilenceTimeout = prevSilence
		hub.LivenessCheckInterval = prevSweep
	})

	srv := httptest.NewServer(buildHandler(h, "secret", newFETicketStore(), newPairLimiter(), nil))
	defer srv.Close()

	tok := pairedHost(t, h, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/host", &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization":   []string{"Bearer " + tok},
			"X-Hub-Deflate":   []string{"1"},
			"X-Hub-State-Ack": []string{"1"},
		},
		// Swallow pings: no control pong, so the probe sees a dead peer.
		OnPingReceived: func(context.Context, []byte) bool { return false },
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	go func() {
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
		}
	}()

	// The host must be ONLINE first, or "offline" proves nothing.
	waitHostOnline(t, h, 3*time.Second)
	waitHostGone(t, h, 5*time.Second)
}

// A host that stops answering pings is dropped by the probe, and the hub
// registry flips offline as a result. onPingReceived returning false
// suppresses the library's automatic pong, which is exactly the shape of
// a blackholed uplink: the socket is open, but nothing comes back.
func TestHostProbeDropsSilentHost(t *testing.T) {
	probeTiming(t, 40*time.Millisecond, 40*time.Millisecond)

	h := hub.NewWithDir("")
	srv := httptest.NewServer(buildHandler(h, "secret", newFETicketStore(), newPairLimiter(), nil))
	defer srv.Close()
	tok := pairedHost(t, h, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/host", &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization":   []string{"Bearer " + tok},
			"X-Hub-Deflate":   []string{"1"},
			"X-Hub-State-Ack": []string{"1"},
		},
		// Swallow pings: the hub must conclude the peer is gone.
		OnPingReceived: func(context.Context, []byte) bool { return false },
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	go func() {
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
		}
	}()

	// Two failed probes at 40ms + 40ms each, plus the sweep that turns
	// "handler returned" into Online=false, lands well inside this.
	waitHostGone(t, h, 2*time.Second)
}

// After the probe drops a silent host, a NEW connection for the same
// hostId must restore Online, and the FE-facing hosts_changed must fire on
// both transitions. This is the whole reason the probe is safe to shorten:
// the recovery path is the ordinary reconnect, not a special case.
func TestHostProbeDropThenReconnectRestoresOnline(t *testing.T) {
	probeTiming(t, 40*time.Millisecond, 40*time.Millisecond)

	h := hub.NewWithDir("")
	srv := httptest.NewServer(buildHandler(h, "secret", newFETicketStore(), newPairLimiter(), nil))
	defer srv.Close()
	tok := pairedHost(t, h, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dial := func(onPing bool) *websocket.Conn {
		t.Helper()
		opts := &websocket.DialOptions{
			HTTPHeader: http.Header{
				"Authorization":   []string{"Bearer " + tok},
				"X-Hub-Deflate":   []string{"1"},
				"X-Hub-State-Ack": []string{"1"},
			},
		}
		if !onPing {
			opts.OnPingReceived = func(context.Context, []byte) bool { return false }
		}
		c, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/host", opts)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		go func() {
			for {
				if _, _, err := c.Read(ctx); err != nil {
					return
				}
			}
		}()
		return c
	}

	dead := dial(false) // swallows pings: the probe must drop it
	defer dead.Close(websocket.StatusNormalClosure, "")
	waitHostGone(t, h, 2*time.Second)

	live := dial(true) // answers pings: recovery is an ordinary reconnect
	defer live.Close(websocket.StatusNormalClosure, "")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hosts := h.ListHosts(); len(hosts) == 1 && hosts[0].Online {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("host did not come back online after reconnect: %+v", h.ListHosts())
}

// probeHost dials the shared test transport with an explicit ping policy.
// nil keeps the library's automatic pong; a returning-false func swallows
// pings, which is the shape of a blackholed uplink.
func probeHost(t *testing.T, srv *httptest.Server, tok string, onPing func(context.Context, []byte) bool) (*hostConn, func()) {
	t.Helper()
	hdr := http.Header{}
	if onPing != nil {
		// dialHost owns the handshake options, so a custom ping policy needs
		// its own dial. Reading is still required for the default policy to
		// answer pings; this goroutine provides it.
		hdr.Set("Authorization", "Bearer "+tok)
		hdr.Set("X-Hub-Deflate", "1")
		hdr.Set("X-Hub-State-Ack", "1")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/host",
			&websocket.DialOptions{HTTPHeader: hdr, OnPingReceived: onPing})
		if err != nil {
			cancel()
			t.Fatalf("dial: %v", err)
		}
		go func() {
			for {
				if _, _, err := conn.Read(ctx); err != nil {
					return
				}
			}
		}()
		return &hostConn{conn: conn, ctx: ctx}, func() { _ = conn.Close(websocket.StatusNormalClosure, ""); cancel() }
	}
	return dialHost(t, srv, tok, nil)
}

// A link carrying uplink traffic is never probed. The host sends a
// host_status frame every 40ms with the idle gate at 300ms, so the gate can
// only open if those frames fail to refresh the activity clock. It does not
// answer pings, so an opened gate is fatal — staying online is the whole
// assertion.
func TestHostProbeSkippedWhileUplinkActive(t *testing.T) {
	probeTiming(t, 20*time.Millisecond, 100*time.Millisecond)
	withProbeIdle(t, 300*time.Millisecond)

	h := hub.NewWithDir("")
	srv := httptest.NewServer(buildHandler(h, "secret", newFETicketStore(), newPairLimiter(), nil))
	defer srv.Close()
	tok := pairedHost(t, h, srv)

	hc, stop := probeHost(t, srv, tok, func(context.Context, []byte) bool { return false })
	defer stop()
	waitHostOnline(t, h, 3*time.Second)

	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		tick := time.NewTicker(40 * time.Millisecond)
		defer tick.Stop()
		for i := 0; i < 25; i++ { // 1s of frames
			<-tick.C
			payload, _ := json.Marshal(map[string]any{"v": 1, "type": "host_status", "ready": true})
			hc.mu.Lock()
			err := hc.conn.Write(hc.ctx, websocket.MessageText, payload)
			hc.mu.Unlock()
			if err != nil {
				return // the link was dropped; the loop below reports it
			}
		}
	}()

	// 1s is 50 probe ticks and several idle gates' worth of frames. A probe
	// that read those frames as silence would have killed the link.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if hosts := h.ListHosts(); len(hosts) != 1 || !hosts[0].Online {
			t.Fatalf("active link was probed and dropped: %+v", hosts)
		}
		time.Sleep(10 * time.Millisecond)
	}
	<-sendDone
	if hosts := h.ListHosts(); len(hosts) != 1 || !hosts[0].Online {
		t.Fatalf("host dropped after the active window: %+v", hosts)
	}
}

// An idle link does get probed, and a successful probe refreshes the clock:
// this host answers pongs and nothing else, so pongs are the only liveness
// evidence the hub has. It must survive many idle gates and probe rounds —
// a probe that failed, or a gate that opened and then never closed, would
// bury it.
func TestHostProbeFiresOnIdleLink(t *testing.T) {
	probeTiming(t, 20*time.Millisecond, 100*time.Millisecond)
	withProbeIdle(t, 60*time.Millisecond)

	h := hub.NewWithDir("")
	srv := httptest.NewServer(buildHandler(h, "secret", newFETicketStore(), newPairLimiter(), nil))
	defer srv.Close()
	tok := pairedHost(t, h, srv)

	// The library answers pings with pongs, while the JSON path stays
	// completely silent. Exactly the case the probe exists for. A custom
	// (accepting) ping policy is used so this host sends the mandatory
	// capability headers.
	_, stop := probeHost(t, srv, tok, func(context.Context, []byte) bool { return true })
	defer stop()
	waitHostOnline(t, h, 3*time.Second)

	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if hosts := h.ListHosts(); len(hosts) != 1 || !hosts[0].Online {
			t.Fatalf("pong-only idle host was dropped: %+v", hosts)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The socket stayed up, so Online is still true (nothing ran the
	// sweep). LastSeen is the connect-time stamp: control pongs do not
	// move it.
	hosts := h.ListHosts()
	if len(hosts) != 1 || time.Since(hosts[0].LastSeen) < 500*time.Millisecond {
		t.Fatalf("control pongs refreshed LastSeen: %+v", hosts)
	}
}

// The gate must not buy quiet at the price of a slower verdict. A host that
// is dead from the start is probed only once the gate opens, so the clock
// from "last sign of life" to "handler returned" is
// hostProbeIdleAfter + hostProbeFailures*(interval+timeout). Here that is
// 80ms + 2*(20+40) = 200ms, which has to land inside the window below.
func TestHostProbeDropsIdleDeadLink(t *testing.T) {
	const idleAfter = 80 * time.Millisecond
	const interval, timeout = 20 * time.Millisecond, 40 * time.Millisecond
	probeTiming(t, interval, timeout)
	withProbeIdle(t, idleAfter)

	h := hub.NewWithDir("")
	srv := httptest.NewServer(buildHandler(h, "secret", newFETicketStore(), newPairLimiter(), nil))
	defer srv.Close()
	tok := pairedHost(t, h, srv)

	// Swallow pings and send nothing: a blackholed uplink.
	_, stop := probeHost(t, srv, tok, func(context.Context, []byte) bool { return false })
	defer stop()
	waitHostOnline(t, h, 3*time.Second)

	start := time.Now()
	// idle gate + the two failed probes, plus one tick of granularity on
	// either side for the loop and the sweep.
	bound := idleAfter + hostProbeFailures*(interval+timeout) + 100*time.Millisecond
	waitHostGone(t, h, bound)
	if waited := time.Since(start); waited < idleAfter {
		t.Fatalf("host dropped after %s, before the %s idle gate could have elapsed", waited, idleAfter)
	}
}

// Our own downlink writes do not keep the probe gate shut. This host
// swallows pings and sends nothing; the hub pushes a subscribers frame
// every 40ms. The probe must still open and drop the link. A write that
// refreshed lastActive would make this test fail by keeping the host up.
func TestHostProbeNotSuppressedByOwnWrites(t *testing.T) {
	probeTiming(t, 20*time.Millisecond, 100*time.Millisecond)
	withProbeIdle(t, 250*time.Millisecond)

	h := hub.NewWithDir("")
	srv := httptest.NewServer(buildHandler(h, "secret", newFETicketStore(), newPairLimiter(), nil))
	defer srv.Close()
	tok := pairedHost(t, h, srv)

	_, stop := probeHost(t, srv, tok, func(context.Context, []byte) bool { return false })
	defer stop()
	waitHostOnline(t, h, 3*time.Second)

	// Each subscribe/unsubscribe pair flips the per-host count 0 -> 1 -> 0,
	// and every flip is a downlink `subscribers` frame. Alternating keeps it
	// above notifyHostsSubscribers' "same count, skip" rule.
	stopTraffic := make(chan struct{})
	trafficDone := make(chan struct{})
	go func() {
		defer close(trafficDone)
		tick := time.NewTicker(40 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stopTraffic:
				return
			case <-tick.C:
				_, unsub, ok := h.TrySubscribeHost(64, "h1")
				if !ok {
					return
				}
				unsub()
			}
		}
	}()
	defer func() { close(stopTraffic); <-trafficDone }()

	// idle 250ms + two failed rounds of (20ms + 100ms), plus slack.
	waitHostGone(t, h, 2*time.Second)
}
