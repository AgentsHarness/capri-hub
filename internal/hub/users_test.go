package hub

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUserTokenStorePersistence(t *testing.T) {
	dir := t.TempDir()
	h := NewWithDir(dir)
	u, token, err := h.CreateUser("Alice")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, "u_") {
		t.Fatalf("token = %q, want u_ prefix", token)
	}
	if _, ok := h.UserByToken(token); !ok {
		t.Fatal("created token does not resolve")
	}

	// A restart keeps the account and its hash, and the old token works.
	h2 := NewWithDir(dir)
	got, ok := h2.UserByToken(token)
	if !ok || got.ID != u.ID || got.Label != "Alice" {
		t.Fatalf("after restart UserByToken = %+v,%v", got, ok)
	}
	users := h2.Users()
	if len(users) != 1 || users[0].TokenHash == "" || users[0].TokenHash == token {
		t.Fatalf("Users() = %+v", users)
	}

	// Reset rotates the hash and invalidates the old token.
	_, token2, err := h2.ResetUserToken(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := h2.UserByToken(token); ok {
		t.Fatal("old token still resolves after reset")
	}
	if _, ok := h2.UserByToken(token2); !ok {
		t.Fatal("new token does not resolve")
	}
}

func TestUserPairingCodeAndHostOwnership(t *testing.T) {
	h := NewWithDir("")
	u, _, err := h.CreateUser("Alice")
	if err != nil {
		t.Fatal(err)
	}
	code, _ := h.UserPairingCode(u.ID)
	if len(code) != 6 {
		t.Fatalf("code = %q", code)
	}
	owner, ok := h.OwnerForPairCode(code)
	if !ok || owner != u.ID {
		t.Fatalf("OwnerForPairCode = %q,%v", owner, ok)
	}
	token, actualID, err := h.PairAs(u.ID, code, "local", "Alice Mac")
	if err != nil {
		t.Fatal(err)
	}
	if owner, _ := h.HostOwner(actualID); owner != u.ID {
		t.Fatalf("host owner = %q, want %s", owner, u.ID)
	}
	if got := h.ListHostsFor(u.ID); len(got) != 1 || got[0].HostName != "Alice Mac" {
		t.Fatalf("ListHostsFor = %+v", got)
	}
	if got := h.DefaultHostIDFor(u.ID); got != actualID {
		t.Fatalf("DefaultHostIDFor = %q, want %q", got, actualID)
	}
	// A root host with the same requested id gets a different registry id;
	// the user host is never hijacked.
	rootCode, _ := h.PairingCode()
	rootToken, rootHostID, err := h.PairAs("root", rootCode, "local", "Root Mac")
	if err != nil {
		t.Fatal(err)
	}
	if rootHostID == actualID {
		t.Fatalf("root pair reused user host id %q", actualID)
	}
	if _, ok := h.HostIDForToken(token); !ok {
		t.Fatal("user host token lost")
	}
	if _, ok := h.HostIDForToken(rootToken); !ok {
		t.Fatal("root host token lost")
	}
}

func TestUserPrefsIsolation(t *testing.T) {
	h := NewWithDir(t.TempDir())
	u, _, err := h.CreateUser("Alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.SetPrefsFor(u.ID, BrowserPrefs{Entries: PrefsEntries{
		"se:alice-only": {V: "1", At: 10, Site: "alice"},
	}}); err != nil {
		t.Fatal(err)
	}
	alice, _ := h.PrefsFor(u.ID)
	if len(alice.PinnedSessions) != 1 || alice.PinnedSessions[0] != "alice-only" {
		t.Fatalf("alice prefs = %+v", alice)
	}
	root, _ := h.PrefsFor("root")
	if len(root.PinnedSessions) != 0 {
		t.Fatalf("root saw user prefs: %+v", root)
	}
	other, _, err := h.CreateUser("Bob")
	if err != nil {
		t.Fatal(err)
	}
	bob, _ := h.PrefsFor(other.ID)
	if len(bob.PinnedSessions) != 0 {
		t.Fatalf("bob saw alice prefs: %+v", bob)
	}
	// Persist across restart.
	h2 := NewWithDir(filepath.Dir(h.usersFile))
	alice2, _ := h2.PrefsFor(u.ID)
	if len(alice2.PinnedSessions) != 1 {
		t.Fatalf("user prefs lost across restart: %+v", alice2)
	}
}

func TestDropUserSubscribersKicksUser(t *testing.T) {
	h := NewWithDir("")
	u, token, err := h.CreateUser("Alice")
	if err != nil {
		t.Fatal(err)
	}
	_, unsub, kicked, ok := h.TrySubscribeUserInfo(0, "", u, nil, SubscriberInfo{Role: "user"})
	if !ok {
		t.Fatal("user subscribe refused")
	}
	defer unsub()
	// Token reset is the production trigger; it must close the live page's
	// kicked channel instead of panicking on a nil channel.
	if _, _, err := h.ResetUserToken(u.ID); err != nil {
		t.Fatal(err)
	}
	h.DropUserSubscribers(u.ID)
	select {
	case <-kicked:
	case <-time.After(time.Second):
		t.Fatal("user subscriber was not kicked")
	}
	if _, ok := h.UserByToken(token); ok {
		t.Fatal("old token still resolves")
	}
}

func TestUserFileNeverPlaintext(t *testing.T) {
	dir := t.TempDir()
	h := NewWithDir(dir)
	_, token, err := h.CreateUser("Alice")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), token) {
		t.Fatalf("users.json contains plaintext token: %s", b)
	}
}
