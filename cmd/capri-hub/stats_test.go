package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/internal/hub"
	"github.com/coder/websocket"
)

// pairedHost pairs h1 and attaches it through the real /ws/host endpoint.
func pairedHost(t *testing.T, ctx context.Context, h *hub.Hub, srv *httptest.Server) *websocket.Conn {
	t.Helper()
	return dialPairedHost(t, ctx, srv, h, "h1", "H1")
}

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

// TestStatsEndpoint: the admin diagnostics endpoint must expose the per-host
// data-plane state, and must not be reachable without an admin credential.
func TestStatsEndpoint(t *testing.T) {
	h := hub.NewWithDir("")
	const admin = "secret"
	srv := httptest.NewServer(buildHandler(h, admin, newFETicketStore(), newPairLimiter(), nil))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := pairedHost(t, ctx, h, srv) // register + attach h1

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

	const subscribers = 4
	for i := 0; i < subscribers; i++ {
		_, unsub, ok := h.TrySubscribe(0)
		if !ok {
			t.Fatalf("subscribe %d refused", i)
		}
		t.Cleanup(unsub)
	}
	const events = 5
	for i := 1; i <= events; i++ {
		pushHostEvent(t, ctx, conn, i, map[string]any{"type": "chunk", "text": "x"})
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && h.LastSeq("h1") != events {
		time.Sleep(5 * time.Millisecond)
	}

	_, body = getStats(t, srv, admin)
	var hostRow map[string]any
	rows, _ := body["hosts"].([]any)
	for _, raw := range rows {
		row, _ := raw.(map[string]any)
		if row["hostId"] == "h1" {
			hostRow = row
		}
	}
	if hostRow == nil {
		t.Fatalf("stats has no row for h1: %v", body["hosts"])
	}
	for _, key := range []string{"hostId", "lastSeq", "online", "epoch", "fanoutDropped", "subscribers", "evBufLen"} {
		if _, ok := hostRow[key]; !ok {
			t.Errorf("host row lost %q: %v", key, hostRow)
		}
	}
	if seq, _ := hostRow["lastSeq"].(float64); uint64(seq) != events {
		t.Errorf("lastSeq = %v, want %d", hostRow["lastSeq"], events)
	}
	if n, _ := hostRow["subscribers"].(float64); int(n) != subscribers {
		t.Errorf("host subscribers = %v, want %d", hostRow["subscribers"], subscribers)
	}
	if n, _ := hostRow["evBufLen"].(float64); n <= 0 {
		t.Errorf("evBufLen = %v, want > 0", hostRow["evBufLen"])
	}
	if n, _ := body["pairedHosts"].(float64); n != 1 {
		t.Errorf("pairedHosts = %v, want 1", body["pairedHosts"])
	}
	if n, _ := body["subscribers"].(float64); int(n) != subscribers {
		t.Errorf("process subscribers = %v, want %d", body["subscribers"], subscribers)
	}
}
