package hub

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// testPair pairs hostID and returns its token.
func testPair(t *testing.T, h *Hub, hostID, hostName string) string {
	t.Helper()
	code, _ := h.PairingCode()
	token, err := h.Pair(code, hostID, hostName)
	if err != nil {
		t.Fatalf("Pair(%s): %v", hostID, err)
	}
	return token
}

func TestPairingFlow(t *testing.T) {
	h := NewWithDir(t.TempDir())
	code, exp := h.PairingCode()
	if len(code) != 6 {
		t.Errorf("code length = %d, want 6", len(code))
	}
	if !exp.After(time.Now()) {
		t.Error("code should not be expired")
	}

	if _, err := h.Pair("WRONG", "h1", "H1"); !errors.Is(err, ErrCodeInvalid) {
		t.Errorf("wrong code err = %v, want ErrCodeInvalid", err)
	}
	// Code matching is case-insensitive.
	tok, err := h.Pair(strings.ToLower(code), "h1", "H1")
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	if hid, ok := h.HostIDForToken(tok); !ok || hid != "h1" {
		t.Errorf("HostIDForToken = %q,%v want h1,true", hid, ok)
	}
	if _, ok := h.HostIDForToken("bogus"); ok {
		t.Error("bogus token should not resolve")
	}

	// Re-pairing revokes the old token.
	tok2, err := h.Pair(code, "h1", "H1-renamed")
	if err != nil {
		t.Fatalf("re-pair: %v", err)
	}
	if _, ok := h.HostIDForToken(tok); ok {
		t.Error("old token should be revoked after re-pair")
	}
	if _, ok := h.HostIDForToken(tok2); !ok {
		t.Error("new token should resolve")
	}
}

func TestExpiredCode(t *testing.T) {
	h := NewWithDir(t.TempDir())
	h.mu.Lock()
	h.codeExpires = time.Now().Add(-time.Minute)
	h.mu.Unlock()
	if _, err := h.Pair(h.pairingCode, "h1", "H1"); !errors.Is(err, ErrCodeInvalid) {
		t.Errorf("expired code err = %v, want ErrCodeInvalid", err)
	}
}

func TestPairingPersistence(t *testing.T) {
	dir := t.TempDir()
	h1 := NewWithDir(dir)
	tok := testPair(t, h1, "h1", "H1")

	h2 := NewWithDir(dir) // "restart"
	if hid, ok := h2.HostIDForToken(tok); !ok || hid != "h1" {
		t.Errorf("token lost across restart: %q,%v", hid, ok)
	}
	hosts := h2.ListHosts()
	if len(hosts) != 1 || hosts[0].HostID != "h1" || hosts[0].HostName != "H1" {
		t.Errorf("hosts after restart = %+v", hosts)
	}
}

func TestStreamLifecycle(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	write := func(payload []byte) error { return nil }
	conn, stop, err := h.ConnectStream("h1", write)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	hosts := h.ListHosts()
	if len(hosts) != 1 || !hosts[0].Online {
		t.Fatalf("host should be online: %+v", hosts)
	}
	if h.DefaultHostID() != "h1" {
		t.Errorf("default host = %q, want h1", h.DefaultHostID())
	}

	stop()
	if h.ListHosts()[0].Online {
		t.Error("host should be offline after stop")
	}
	// Only known host stays the default (requests would 503 while offline).
	if h.DefaultHostID() != "h1" {
		t.Errorf("default host = %q, want h1", h.DefaultHostID())
	}

	// A stale stop (old conn) must not kill the new connection.
	conn2, stop2, err := h.ConnectStream("h1", write)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	_ = conn
	stop() // stale
	if !h.ListHosts()[0].Online {
		t.Error("stale stop must not mark host offline")
	}
	_ = conn2
	stop2()
	if h.ListHosts()[0].Online {
		t.Error("host should be offline after real stop")
	}

	if _, _, err := h.ConnectStream("nope", write); !errors.Is(err, ErrHostUnknown) {
		t.Errorf("connect unknown host err = %v", err)
	}
}

func TestDispatchAndRespond(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	type frame struct {
		ReqID  string          `json:"reqId"`
		Method string          `json:"method"`
		Path   string          `json:"path"`
		Body   json.RawMessage `json:"body"`
	}
	got := make(chan frame, 1)
	_, stop, err := h.ConnectStream("h1", func(payload []byte) error {
		var f frame
		if err := json.Unmarshal(payload, &f); err != nil {
			t.Errorf("bad relay frame: %v", err)
			return err
		}
		got <- f
		return nil
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer stop()

	body := json.RawMessage(`{"blocks":[{"type":"text","text":"hi"}]}`)
	type result struct {
		resp RelayResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := h.Dispatch("h1", "POST", "/api/prompt", body)
		done <- result{resp, err}
	}()

	f := <-got
	if f.ReqID == "" || f.Method != "POST" || f.Path != "/api/prompt" {
		t.Fatalf("relay frame = %+v", f)
	}
	if string(f.Body) != string(body) {
		t.Errorf("body = %s, want %s", f.Body, body)
	}

	answer := RelayResponse{Status: 200, Body: json.RawMessage(`{"ok":true}`)}
	if !h.Respond("h1", f.ReqID, answer) {
		t.Fatal("Respond should resolve a pending request")
	}
	if h.Respond("h1", f.ReqID, answer) {
		t.Error("second Respond for the same reqId should fail")
	}

	r := <-done
	if r.err != nil || r.resp.Status != 200 || string(r.resp.Body) != `{"ok":true}` {
		t.Errorf("dispatch result = %+v, %v", r.resp, r.err)
	}
}

func TestDispatchOffline(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	_, err := h.Dispatch("h1", "POST", "/api/prompt", nil)
	var re *RelayError
	if !errors.As(err, &re) || re.Status != 503 {
		t.Errorf("offline dispatch err = %v, want RelayError 503", err)
	}
	if _, err := h.Dispatch("nope", "POST", "/api/prompt", nil); !errors.As(err, &re) || re.Status != 404 {
		t.Errorf("unknown host dispatch err = %v, want 404", err)
	}
}

func TestDispatchFailsOnDisconnect(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	_, stop, err := h.ConnectStream("h1", func(payload []byte) error { return nil })
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	type result struct {
		resp RelayResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := h.Dispatch("h1", "GET", "/api/status", nil)
		done <- result{resp, err}
	}()
	time.Sleep(50 * time.Millisecond) // let the request register
	stop()                            // host drops mid-request

	select {
	case r := <-done:
		var re *RelayError
		if !errors.As(r.err, &re) || re.Status != 503 {
			t.Errorf("err = %v, want RelayError 503", r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dispatch did not fail fast on disconnect")
	}
}

func TestEventTaggingAndFanout(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")

	ch, unsub := h.Subscribe()
	defer unsub()

	if !h.RegisterEvent("h1", Event{"type": "chunk", "text": "hi"}) {
		t.Fatal("RegisterEvent failed for paired host")
	}
	select {
	case ev := <-ch:
		if ev["hostId"] != "h1" || ev["hostName"] != "H1" {
			t.Errorf("event tags = %v/%v", ev["hostId"], ev["hostName"])
		}
		if ev["type"] != "chunk" {
			t.Errorf("event type = %v", ev["type"])
		}
	case <-time.After(time.Second):
		t.Fatal("no event received")
	}

	// Unknown host events are rejected.
	if h.RegisterEvent("nope", Event{"type": "chunk"}) {
		t.Error("RegisterEvent for unknown host should fail")
	}
}

func TestHostStatusReady(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	if !h.RegisterEvent("h1", Event{"type": "host_status", "ready": true}) {
		t.Fatal("RegisterEvent failed")
	}
	if hosts := h.ListHosts(); len(hosts) != 1 || !hosts[0].Ready {
		t.Errorf("ready not tracked: %+v", hosts)
	}
}

func TestHostsOrderingAndDefault(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	testPair(t, h, "h2", "H2")

	// h2 connects (online) → sorts first, becomes default.
	_, stop, err := h.ConnectStream("h2", func(payload []byte) error { return nil })
	if err != nil {
		t.Fatalf("connect h2: %v", err)
	}
	hosts := h.ListHosts()
	if len(hosts) != 2 || hosts[0].HostID != "h2" {
		t.Errorf("ordering = %+v, want h2 first", hosts)
	}
	if h.DefaultHostID() != "h2" {
		t.Errorf("default = %q, want h2", h.DefaultHostID())
	}

	// After h2 disconnects, default falls back to the most recently seen
	// host — h1, refreshed by a recent event.
	h.RegisterEvent("h1", Event{"type": "chunk", "text": "x"})
	stop()
	if h.DefaultHostID() != "h1" {
		t.Errorf("default after offline = %q, want h1", h.DefaultHostID())
	}
}

func TestHostsChangedBroadcast(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	ch, unsub := h.Subscribe()
	defer unsub()

	_, stop, err := h.ConnectStream("h1", func(payload []byte) error { return nil })
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	select {
	case ev := <-ch:
		if ev["type"] != "hosts_changed" {
			t.Errorf("event = %v, want hosts_changed", ev["type"])
		}
	case <-time.After(time.Second):
		t.Fatal("no hosts_changed on connect")
	}
	stop()
	select {
	case ev := <-ch:
		if ev["type"] != "hosts_changed" {
			t.Errorf("event = %v, want hosts_changed", ev["type"])
		}
	case <-time.After(time.Second):
		t.Fatal("no hosts_changed on disconnect")
	}
}
