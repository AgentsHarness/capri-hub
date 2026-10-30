package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/internal/hub"
)

// getStats fetches /api/stats with an optional bearer token.
func getStats(t *testing.T, srv *httptest.Server, token string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/stats", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/stats: %v", err)
	}
	defer res.Body.Close()
	var body map[string]any
	if res.StatusCode == 200 {
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
			t.Fatalf("decode stats: %v", err)
		}
	}
	return res, body
}

// TestStatsEndpoint: the admin diagnostics endpoint must expose the
// counters that back every "this drop is recoverable" claim, and must not
// be reachable without an admin credential.
func TestStatsEndpoint(t *testing.T) {
	h := hub.NewWithDir("")
	const admin = "secret"
	srv := httptest.NewServer(buildHandler(h, admin, newFETicketStore(), newPairLimiter(), nil))
	defer srv.Close()
	pairedHost(t, h, srv) // register h1; the admin token is the FE token

	// Admin sees the shape even before any traffic.
	res, body := getStats(t, srv, admin)
	if res.StatusCode != 200 {
		t.Fatalf("admin stats status = %d", res.StatusCode)
	}
	for _, key := range []string{"ok", "hosts", "pairedHosts", "subscribers", "feDropped", "feResyncs", "uptimeSeconds"} {
		if _, ok := body[key]; !ok {
			t.Errorf("stats lost %q: %v", key, body)
		}
	}

	// Unauthenticated and guest callers are refused.
	if res, _ := getStats(t, srv, ""); res.StatusCode != 401 {
		t.Errorf("unauth stats status = %d, want 401", res.StatusCode)
	}
	guest, err := h.CreateGuestToken("只读", 0, nil)
	if err != nil {
		t.Fatalf("create guest: %v", err)
	}
	if res, _ := getStats(t, srv, guest.Token); res.StatusCode != 403 {
		t.Errorf("guest stats status = %d, want 403", res.StatusCode)
	}

	// Fill the per-host fan-out queue: many non-reading subscribers make
	// broadcast much slower than ingestion, so the bounded queue overflows
	// and drops. The point is that the drop count is now observable.
	const subscribers = 64
	for i := 0; i < subscribers; i++ {
		_, unsub, ok := h.TrySubscribe(0)
		if !ok {
			t.Fatalf("subscribe %d refused", i)
		}
		t.Cleanup(unsub)
	}
	const events = 20000
	for i := 1; i <= events; i++ {
		raw, _ := json.Marshal(hub.Event{"type": "chunk", "seq": uint64(i)})
		if !h.RegisterRawEvents("h1", []json.RawMessage{raw}) {
			t.Fatalf("ingest %d rejected", i)
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	var hostRow map[string]any
	for time.Now().Before(deadline) {
		_, body = getStats(t, srv, admin)
		rows, _ := body["hosts"].([]any)
		for _, raw := range rows {
			row, _ := raw.(map[string]any)
			if row["hostId"] == "h1" {
				hostRow = row
			}
		}
		if hostRow != nil {
			if dropped, _ := hostRow["fanoutDropped"].(float64); dropped > 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if hostRow == nil {
		t.Fatalf("stats has no row for h1: %v", body["hosts"])
	}
	if dropped, _ := hostRow["fanoutDropped"].(float64); dropped <= 0 {
		t.Fatalf("fanoutDropped = %v after %d events into a full queue, want > 0", hostRow["fanoutDropped"], events)
	}
	for _, key := range []string{"hostId", "lastSeq", "online", "fanoutDropped", "subscribers", "evBufLen", "unackedState"} {
		if _, ok := hostRow[key]; !ok {
			t.Errorf("host row lost %q: %v", key, hostRow)
		}
	}
	if seq, _ := hostRow["lastSeq"].(float64); seq != events {
		t.Errorf("lastSeq = %v, want %d", hostRow["lastSeq"], events)
	}
	if n, _ := hostRow["subscribers"].(float64); int(n) != subscribers {
		t.Errorf("host subscribers = %v, want %d", hostRow["subscribers"], subscribers)
	}
	if n, _ := hostRow["evBufLen"].(float64); n <= 0 {
		t.Errorf("evBufLen = %v, want > 0", hostRow["evBufLen"])
	}
	// The process-level FE counters are the other half of the evidence.
	if n, _ := body["feDropped"].(float64); n <= 0 {
		t.Errorf("feDropped = %v, want > 0 (slow subscribers must register drops)", body["feDropped"])
	}
	if n, _ := body["pairedHosts"].(float64); n != 1 {
		t.Errorf("pairedHosts = %v, want 1", body["pairedHosts"])
	}
	if n, _ := body["subscribers"].(float64); int(n) != subscribers {
		t.Errorf("process subscribers = %v, want %d", body["subscribers"], subscribers)
	}
}
