package hub

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// 心跳静默的 host 必须被判离线并放开挂在它身上的中继请求。
// 这是「消息已上屏但从未送达」的兜底：上行黑障时传输层可能迟迟不报错，
// 于是请求会一直躺在 pending 表里，浏览器只能等 RelayTimeout。
func TestSweepStaleHostsMarksOfflineAndFailsPending(t *testing.T) {
	prev := HostSilenceTimeout
	HostSilenceTimeout = 20 * time.Millisecond
	defer func() { HostSilenceTimeout = prev }()

	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	_, stop, err := h.ConnectStream("h1", func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer stop()
	if !h.ListHosts()[0].Online {
		t.Fatal("host should start online")
	}

	// A relayed request that the host never answers.
	done := make(chan error, 1)
	go func() {
		_, err := h.Dispatch(context.Background(), "h1", "POST", "/api/prompt", nil)
		done <- err
	}()
	// Let Dispatch park in the pending table.
	time.Sleep(20 * time.Millisecond)

	h.sweepStaleHosts()

	if h.ListHosts()[0].Online {
		t.Error("silent host must be marked offline")
	}
	select {
	case err := <-done:
		var re *RelayError
		if !errors.As(err, &re) || re.Status != 503 {
			t.Errorf("pending request err = %v, want RelayError 503", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending request was not failed by the sweep")
	}
}

func TestNoteUplinkDoesNotMoveLastSeen(t *testing.T) {
	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	_, stop, err := h.ConnectStream("h1", func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer stop()

	h.mu.Lock()
	seen := h.hosts["h1"].info.LastSeen
	h.mu.Unlock()
	time.Sleep(2 * time.Millisecond)
	h.NoteUplink("h1")

	h.mu.Lock()
	defer h.mu.Unlock()
	hs := h.hosts["h1"]
	if !hs.info.LastSeen.Equal(seen) {
		t.Fatal("NoteUplink moved LastSeen")
	}
	if !hs.lastUplink.After(seen) {
		t.Fatal("NoteUplink did not move lastUplink")
	}
}

// A host that keeps beating must stay online: the sweep is a silence
// detector, not a periodic kick.
func TestSweepKeepsHeartbeatingHostOnline(t *testing.T) {
	prev := HostSilenceTimeout
	HostSilenceTimeout = 100 * time.Millisecond
	defer func() { HostSilenceTimeout = prev }()

	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	_, stop, err := h.ConnectStream("h1", func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer stop()

	ready := true
	h.UpdateHostStatus("h1", HostStatusPatch{Ready: &ready})
	h.sweepStaleHosts()

	if !h.ListHosts()[0].Online {
		t.Error("a host that just beat must stay online")
	}
}

// A host wrongly marked offline must come back on its next uplink frame:
// its link is fine, so it will never reconnect, and a flag only a reconnect
// can clear would keep it offline forever.
func TestHeartbeatRestoresHostOnline(t *testing.T) {
	prev := HostSilenceTimeout
	HostSilenceTimeout = 20 * time.Millisecond
	defer func() { HostSilenceTimeout = prev }()

	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	_, stop, err := h.ConnectStream("h1", func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer stop()

	ch, unsub, ok := h.TrySubscribeHost(0, "")
	if !ok {
		t.Fatal("TrySubscribeHost refused")
	}
	defer unsub()

	time.Sleep(2 * HostSilenceTimeout)
	h.sweepStaleHosts()
	if h.ListHosts()[0].Online {
		t.Fatal("silent host must be marked offline by the sweep")
	}
	// Drain the sweep's hosts_changed so the next one is unambiguous.
	for {
		select {
		case <-ch:
		case <-time.After(100 * time.Millisecond):
			goto drained
		}
	}
drained:

	// A host_status beat proves the host is talking. Ready is unchanged
	// (false), so only the Online flip can produce hosts_changed.
	ready := false
	if !h.UpdateHostStatus("h1", HostStatusPatch{Ready: &ready}) {
		t.Fatal("UpdateHostStatus rejected a known host")
	}
	if !h.ListHosts()[0].Online {
		t.Fatal("a beating host must be restored to online")
	}
	select {
	case ev := <-ch:
		if ev["type"] != "hosts_changed" {
			t.Fatalf("event = %v, want hosts_changed", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("restoring Online did not broadcast hosts_changed")
	}
}

// A swept host's transport is still attached but must receive no downlink
// writes; the next heartbeat clears the suspension and the same conn works
// again (nobody reconnects).
func TestSweepSuspendsConnWritesAndHeartbeatRestores(t *testing.T) {
	prev := HostSilenceTimeout
	HostSilenceTimeout = 20 * time.Millisecond
	defer func() { HostSilenceTimeout = prev }()

	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	var writes atomic.Int64
	conn, stop, err := h.ConnectStream("h1", func([]byte) error {
		writes.Add(1)
		return nil
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer stop()

	time.Sleep(2 * HostSilenceTimeout)
	h.sweepStaleHosts()
	if h.ListHosts()[0].Online {
		t.Fatal("silent host must be marked offline by the sweep")
	}
	if h.HostWritable("h1", conn) {
		t.Fatal("swept conn must not be writable")
	}

	writes.Store(0)
	if _, err := h.Dispatch(context.Background(), "h1", "POST", "/api/prompt", nil); err == nil {
		t.Fatal("Dispatch to a swept host must fail")
	}
	if n := writes.Load(); n != 0 {
		t.Fatalf("swept conn received %d writes, want 0", n)
	}

	ready := false
	if !h.UpdateHostStatus("h1", HostStatusPatch{Ready: &ready}) {
		t.Fatal("UpdateHostStatus rejected a known host")
	}
	if !h.ListHosts()[0].Online || !h.HostWritable("h1", conn) {
		t.Fatal("a heartbeat must clear the suspension and restore Online")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := h.Dispatch(ctx, "h1", "POST", "/api/prompt", nil); err == nil {
		t.Fatal("Dispatch should time out waiting for the host")
	}
	if n := writes.Load(); n != 1 {
		t.Fatalf("restored conn received %d writes, want 1", n)
	}
}

// A host already offline is left alone (no repeat broadcast churn).
func TestSweepIgnoresAlreadyOfflineHost(t *testing.T) {
	prev := HostSilenceTimeout
	HostSilenceTimeout = time.Millisecond
	defer func() { HostSilenceTimeout = prev }()

	h := NewWithDir(t.TempDir())
	testPair(t, h, "h1", "H1")
	// Never connected: offline from the start.
	h.sweepStaleHosts()
	if h.ListHosts()[0].Online {
		t.Error("never-connected host must not be online")
	}
}
