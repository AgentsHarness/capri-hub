package hub

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestPersistSerializesConcurrentWrites: concurrent Pair/rename/port writes
// must leave hub.json matching the final in-memory registry, not an older
// snapshot renamed last. Before persistMu, each writer took its snapshot
// under h.mu and wrote outside it, so a slow older write could land after a
// newer one and drop a pairing.
func TestPersistSerializesConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	h := NewWithDir(dir)
	code, _ := h.PairingCode()

	const hosts = 48
	var wg sync.WaitGroup
	for i := 0; i < hosts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("h%02d", i)
			if _, err := h.Pair(code, id, "name-"+id); err != nil {
				t.Errorf("Pair(%s): %v", id, err)
			}
		}(i)
	}
	wg.Wait()

	// Two more concurrent writers on separate fields, then one final pass
	// whose values must be the ones on disk.
	const finalName = "final-name"
	port := 4321
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := h.RenameHost("h00", finalName); err != nil {
			t.Errorf("RenameHost: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		if !h.UpdateHostStatus("h01", HostStatusPatch{Port: &port}) {
			t.Errorf("UpdateHostStatus: host unknown")
		}
	}()
	wg.Wait()

	b, err := os.ReadFile(filepath.Join(dir, "hub.json"))
	if err != nil {
		t.Fatalf("read hub.json: %v", err)
	}
	var pf persistFile
	if err := json.Unmarshal(b, &pf); err != nil {
		t.Fatalf("hub.json is not valid JSON: %v", err)
	}
	if len(pf.Hosts) != hosts {
		t.Fatalf("hub.json has %d hosts, want %d (a concurrent write lost one)", len(pf.Hosts), hosts)
	}
	if got := pf.Hosts["h00"].HostName; got != finalName {
		t.Errorf("h00 name = %q, want %q (stale snapshot won)", got, finalName)
	}
	if got := pf.Hosts["h01"].Port; got != port {
		t.Errorf("h01 port = %d, want %d (stale snapshot won)", got, port)
	}
	// Every token must also survive: a lost snapshot typically drops hosts
	// and their tokens together.
	if len(pf.Tokens) != hosts {
		t.Errorf("hub.json has %d tokens, want %d", len(pf.Tokens), hosts)
	}
}
