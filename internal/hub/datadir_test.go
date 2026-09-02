package hub

import (
	"os"
	"path/filepath"
	"testing"
)

// HUB_DATA_DIR is what lets a container keep pairing state on a mounted
// volume. If it silently fell back to the home directory the state would
// land inside the container's writable layer and every `docker compose
// up --force-recreate` would drop every paired host — a failure that
// looks like "the hub forgot my hosts" rather than a config mistake.
func TestDefaultDataDirHubDataDirOverride(t *testing.T) {
	want := filepath.Join(t.TempDir(), "data")
	t.Setenv("HUB_DATA_DIR", want)

	if got := defaultDataDir(); got != want {
		t.Fatalf("defaultDataDir() = %q, want %q", got, want)
	}
}

func TestDefaultDataDirFallsBackToHome(t *testing.T) {
	t.Setenv("HUB_DATA_DIR", "")

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory on this platform: %v", err)
	}
	want := filepath.Join(home, ".capri-hub")
	if got := defaultDataDir(); got != want {
		t.Fatalf("defaultDataDir() = %q, want %q", got, want)
	}
}

func TestDefaultDataDirIgnoresWhitespaceOnlyOverride(t *testing.T) {
	// An env_file line like `HUB_DATA_DIR= ` must not resolve state to a
	// relative path — better to fall back to the documented default.
	t.Setenv("HUB_DATA_DIR", "   ")

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory on this platform: %v", err)
	}
	if got, want := defaultDataDir(), filepath.Join(home, ".capri-hub"); got != want {
		t.Fatalf("defaultDataDir() = %q, want %q", got, want)
	}
}

// End-to-end: New() (not just defaultDataDir) must actually persist into
// the override directory, and a fresh Hub must read it back.
func TestNewPersistsIntoHubDataDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HUB_DATA_DIR", dir)

	h := New()
	code, _ := h.PairingCode()
	if _, err := h.Pair(code, "host-a", "Host A"); err != nil {
		t.Fatalf("Pair: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "hub.json")); err != nil {
		t.Fatalf("hub.json not written to HUB_DATA_DIR: %v", err)
	}

	// A restart with the same volume keeps the pairing.
	again := New()
	hosts := again.ListHosts()
	if len(hosts) != 1 || hosts[0].HostID != "host-a" {
		t.Fatalf("pairing did not survive restart: %+v", hosts)
	}
}
