package hub

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

	// Re-pairing revokes the old token. The first successful pair consumed
	// the code, so take the freshly rotated one.
	code2, _ := h.PairingCode()
	tok2, err := h.Pair(code2, "h1", "H1-renamed")
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

func TestPairCodeIsSingleUse(t *testing.T) {
	h := NewWithDir("")
	code, _ := h.PairingCode()
	if _, err := h.Pair(code, "h1", "H1"); err != nil {
		t.Fatalf("first pair: %v", err)
	}
	if _, err := h.Pair(code, "h2", "H2"); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("reused pairing code err = %v, want ErrCodeInvalid", err)
	}
	fresh, _ := h.PairingCode()
	if fresh == code {
		t.Fatal("pairing code did not rotate after success")
	}
	if _, err := h.Pair(fresh, "h2", "H2"); err != nil {
		t.Fatalf("fresh code must pair: %v", err)
	}
}

func TestExpiredCode(t *testing.T) {
	h := NewWithDir(t.TempDir())
	h.mu.Lock()
	old := h.pairingCode
	h.codeExpires = time.Now().Add(-time.Minute)
	h.mu.Unlock()
	// Pair with the expired code value must still fail (does not auto-accept).
	if _, err := h.Pair(old, "h1", "H1"); !errors.Is(err, ErrCodeInvalid) {
		t.Errorf("expired code err = %v, want ErrCodeInvalid", err)
	}
}

// PairingCode() must auto-rotate when the current code is past expiry so
// admins never see a dead code advertised as current.
func TestPairingCodeAutoRotateOnRead(t *testing.T) {
	h := NewWithDir(t.TempDir())
	h.mu.Lock()
	old := h.pairingCode
	h.codeExpires = time.Now().Add(-time.Minute)
	h.mu.Unlock()

	code, exp := h.PairingCode()
	if code == old {
		t.Error("PairingCode must rotate after expiry")
	}
	if !exp.After(time.Now()) {
		t.Error("new code must not be already expired")
	}
	// New code works for Pair.
	if _, err := h.Pair(code, "h1", "H1"); err != nil {
		t.Fatalf("pair with rotated code: %v", err)
	}
}

// After disconnect, gap-pull buffer is kept for EventBufGrace then cleared.
// Reconnect cancels the pending clear.
func TestEventBufGrace(t *testing.T) {
	prev := EventBufGrace
	EventBufGrace = 80 * time.Millisecond
	// Cleanup, not defer: the sessions below read this global while they
	// unwind, and their own cleanups run before this one.
	t.Cleanup(func() { EventBufGrace = prev })

	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 1)
	fh.events(1, 0, chunkEvent(1, "a"))
	waitFor(t, func() bool { return h.LastSeq("h1") == 1 }, 2*time.Second)

	fh.ft.hangup()
	waitFor(t, func() bool { return !h.ListHosts()[0].Online }, 2*time.Second)
	// Immediately after detach the buffer is still available.
	if n := len(h.EventsAfter("h1", 0)); n != 1 {
		t.Fatalf("evBuf right after detach = %d, want 1", n)
	}
	// After grace, cleared.
	time.Sleep(120 * time.Millisecond)
	if n := len(h.EventsAfter("h1", 0)); n != 0 {
		t.Fatalf("evBuf after grace = %d, want 0", n)
	}

	// A reconnect within the grace window cancels the clear.
	EventBufGrace = 250 * time.Millisecond
	again := dialFakeHost(t, h, "h1", 1)
	again.events(2, 0, chunkEvent(2, "b"))
	waitFor(t, func() bool { return h.LastSeq("h1") == 2 }, 2*time.Second)
	again.ft.hangup()
	waitFor(t, func() bool { return !h.ListHosts()[0].Online }, 2*time.Second)
	third := dialFakeHost(t, h, "h1", 1)
	defer third.ft.hangup()
	time.Sleep(300 * time.Millisecond)
	// The pre-grace buffer was already cleared, so only event 2 remains —
	// and it must have survived the reconnect (the clear was cancelled).
	evs := h.EventsAfter("h1", 0)
	if len(evs) != 1 || evSeq(evs[0]) != 2 {
		t.Fatalf("evBuf after reconnect within grace = %v, want [2] (clear cancelled)", evs)
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

// Re-pair after a process restart must revoke the old token. load() has
// to restore hostState.token (and Pair must revoke by hostId) for this.
func TestRePairAfterRestartRevokesOldToken(t *testing.T) {
	dir := t.TempDir()
	h1 := NewWithDir(dir)
	tok1 := testPair(t, h1, "h1", "H1")

	h2 := NewWithDir(dir) // restart
	code, _ := h2.PairingCode()
	tok2, err := h2.Pair(code, "h1", "H1-new")
	if err != nil {
		t.Fatalf("re-pair: %v", err)
	}
	if _, ok := h2.HostIDForToken(tok1); ok {
		t.Error("old token must be revoked after re-pair post-restart")
	}
	if hid, ok := h2.HostIDForToken(tok2); !ok || hid != "h1" {
		t.Errorf("new token = %q,%v want h1,true", hid, ok)
	}
}

func TestPersistFileMode(t *testing.T) {
	dir := t.TempDir()
	h := NewWithDir(dir)
	_ = testPair(t, h, "h1", "H1")
	fi, err := os.Stat(filepath.Join(dir, "hub.json"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("hub.json mode %o must not be group/other readable", mode)
	}
}

// Concurrent Pair must not race on the shared tokens map during persist
// marshal (go test -race) and must leave a valid hub.json.
func TestConcurrentPairPersist(t *testing.T) {
	dir := t.TempDir()
	h := NewWithDir(dir)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Codes are single-use and rotate after success. A concurrent
			// peer may take the code we just read; retry with the current
			// one instead of reusing a burned code.
			for attempt := 0; attempt < 8; attempt++ {
				code, _ := h.PairingCode()
				if _, err := h.Pair(code, fmt.Sprintf("h%d", i), "H"); err == nil {
					return
				}
			}
		}(i)
	}
	wg.Wait()

	b, err := os.ReadFile(filepath.Join(dir, "hub.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pf persistFile
	if err := json.Unmarshal(b, &pf); err != nil {
		t.Fatalf("invalid hub.json after concurrent pairs: %v", err)
	}
	if len(pf.Hosts) == 0 || len(pf.Tokens) == 0 {
		t.Errorf("empty snapshot: hosts=%d tokens=%d", len(pf.Hosts), len(pf.Tokens))
	}
}
