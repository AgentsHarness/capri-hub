package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/AgentsHarness/capri-hub/internal/hub"
)

func newUsersTestServer(t *testing.T, dir string) (*hub.Hub, *httptest.Server) {
	t.Helper()
	h := hub.NewWithDir(dir)
	srv := httptest.NewServer(buildHandler(h, "admin-secret", newFETicketStore(), newPairLimiter(), nil))
	t.Cleanup(srv.Close)
	return h, srv
}

func callJSON(t *testing.T, srv *httptest.Server, token, method, path string, body any) (int, map[string]any, string) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, srv.URL+path, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	raw, _ := json.Marshal(out)
	return res.StatusCode, out, string(raw)
}

func createUser(t *testing.T, srv *httptest.Server, label string) (id, token string) {
	t.Helper()
	status, out, raw := callJSON(t, srv, "admin-secret", http.MethodPost, "/api/users/create", map[string]any{"label": label})
	if status != 200 {
		t.Fatalf("create user status=%d body=%s", status, raw)
	}
	u, _ := out["user"].(map[string]any)
	id, _ = u["id"].(string)
	token, _ = out["token"].(string)
	if id == "" || token == "" {
		t.Fatalf("create user response = %s", raw)
	}
	return id, token
}

func pairingCodeFor(t *testing.T, srv *httptest.Server, token string) string {
	t.Helper()
	status, out, raw := callJSON(t, srv, token, http.MethodGet, "/api/pairing", nil)
	if status != 200 {
		t.Fatalf("pairing status=%d body=%s", status, raw)
	}
	code, _ := out["code"].(string)
	if code == "" {
		t.Fatalf("pairing response = %s", raw)
	}
	return code
}

func pairHost(t *testing.T, srv *httptest.Server, code, hostID, hostName string) (token, actualID string) {
	t.Helper()
	status, out, raw := callJSON(t, srv, "", http.MethodPost, "/api/pair", map[string]any{
		"code": code, "hostId": hostID, "hostName": hostName,
	})
	if status != 200 {
		t.Fatalf("pair %s status=%d body=%s", hostName, status, raw)
	}
	token, _ = out["token"].(string)
	actualID, _ = out["hostId"].(string)
	if token == "" || actualID == "" {
		t.Fatalf("pair response = %s", raw)
	}
	return token, actualID
}

func TestUserLifecycleAndTokenSelfService(t *testing.T) {
	dir := t.TempDir()
	_, srv := newUsersTestServer(t, dir)

	id, token := createUser(t, srv, "Alice")
	if !strings.HasPrefix(token, "u_") {
		t.Fatalf("generated token = %q, want u_ prefix", token)
	}

	// Admin list must not leak token material.
	status, out, raw := callJSON(t, srv, "admin-secret", http.MethodGet, "/api/users", nil)
	if status != 200 {
		t.Fatalf("list status=%d body=%s", status, raw)
	}
	if strings.Contains(raw, token) || strings.Contains(raw, "tokenHash") {
		t.Fatalf("user list leaked token material: %s", raw)
	}
	users, _ := out["users"].([]any)
	if len(users) != 1 {
		t.Fatalf("users = %s, want one", raw)
	}

	// The user token authenticates as a normal user.
	status, out, raw = callJSON(t, srv, token, http.MethodGet, "/api/access-role", nil)
	if status != 200 || out["role"] != "user" {
		t.Fatalf("access-role = %d %s, want user", status, raw)
	}
	if status, _, _ = callJSON(t, srv, token, http.MethodGet, "/api/users", nil); status != 403 {
		t.Fatalf("user listing users status = %d, want 403", status)
	}

	// A user can replace their own token.
	const newToken = "alice-chosen-token-123456"
	status, out, raw = callJSON(t, srv, token, http.MethodPost, "/api/me/token", map[string]any{"token": newToken})
	if status != 200 || out["token"] != newToken {
		t.Fatalf("self change = %d %s", status, raw)
	}
	if status, _, _ = callJSON(t, srv, token, http.MethodGet, "/api/access-role", nil); status != 401 {
		t.Fatalf("old token status = %d, want 401", status)
	}
	if status, _, raw := callJSON(t, srv, newToken, http.MethodGet, "/api/access-role", nil); status != 200 {
		t.Fatalf("new token status = %d body=%s", status, raw)
	}

	// Admin reset invalidates the user-chosen token and returns a fresh one.
	status, out, raw = callJSON(t, srv, "admin-secret", http.MethodPost, "/api/users/reset", map[string]any{"id": id})
	if status != 200 {
		t.Fatalf("reset status=%d body=%s", status, raw)
	}
	resetToken, _ := out["token"].(string)
	if resetToken == "" || resetToken == newToken {
		t.Fatalf("reset token = %q", resetToken)
	}
	if status, _, _ = callJSON(t, srv, newToken, http.MethodGet, "/api/access-role", nil); status != 401 {
		t.Fatalf("pre-reset token status = %d, want 401", status)
	}

	// Plaintext tokens never reach the data dir; users.json stores hashes.
	rawFile, err := os.ReadFile(dir + "/users.json")
	if err != nil {
		t.Fatalf("read users.json: %v", err)
	}
	data := string(rawFile)
	if strings.Contains(data, resetToken) || strings.Contains(data, newToken) {
		t.Fatalf("users.json contains plaintext token: %s", data)
	}

	if status, _, raw := callJSON(t, srv, "admin-secret", http.MethodPost, "/api/users/delete", map[string]any{"id": id}); status != 200 {
		t.Fatalf("delete status=%d body=%s", status, raw)
	}
	if status, _, _ = callJSON(t, srv, resetToken, http.MethodGet, "/api/access-role", nil); status != 401 {
		t.Fatalf("deleted user token status = %d, want 401", status)
	}
}

func TestUserHostIsolationPairingAndForwarding(t *testing.T) {
	_, srv := newUsersTestServer(t, t.TempDir())
	aliceID, alice := createUser(t, srv, "Alice")
	bobID, bob := createUser(t, srv, "Bob")

	aliceCode := pairingCodeFor(t, srv, alice)
	bobCode := pairingCodeFor(t, srv, bob)
	if aliceCode == bobCode {
		t.Fatal("two users received the same pairing code")
	}

	_, aliceHost := pairHost(t, srv, aliceCode, "local", "Alice Mac")
	_, bobHost := pairHost(t, srv, bobCode, "local", "Bob Mac")
	if bobHost == aliceHost {
		t.Fatalf("second default hostId reused %q", bobHost)
	}

	// Each user sees only their own host. The admin account also only sees
	// hosts paired under root; user-owned hosts are visible only through
	// the management user list.
	status, out, raw := callJSON(t, srv, alice, http.MethodGet, "/api/hosts", nil)
	if status != 200 {
		t.Fatalf("alice hosts status=%d body=%s", status, raw)
	}
	hosts, _ := out["hosts"].([]any)
	if len(hosts) != 1 || hosts[0].(map[string]any)["hostName"] != "Alice Mac" {
		t.Fatalf("alice hosts = %s", raw)
	}
	status, out, raw = callJSON(t, srv, bob, http.MethodGet, "/api/hosts", nil)
	if status != 200 {
		t.Fatalf("bob hosts status=%d body=%s", status, raw)
	}
	hosts, _ = out["hosts"].([]any)
	if len(hosts) != 1 || hosts[0].(map[string]any)["hostName"] != "Bob Mac" {
		t.Fatalf("bob hosts = %s", raw)
	}
	status, out, raw = callJSON(t, srv, "admin-secret", http.MethodGet, "/api/hosts", nil)
	if status != 200 || len(out["hosts"].([]any)) != 0 {
		t.Fatalf("admin hosts before pairing own = %d %s", status, raw)
	}
	// Admin pairs its own host; its host list remains root-only.
	adminCode := pairingCodeFor(t, srv, "admin-secret")
	_, adminHost := pairHost(t, srv, adminCode, "admin-pc", "Admin Mac")
	status, out, raw = callJSON(t, srv, "admin-secret", http.MethodGet, "/api/hosts", nil)
	if status != 200 || len(out["hosts"].([]any)) != 1 {
		t.Fatalf("admin hosts after pairing own = %d %s", status, raw)
	}
	// The management user list carries each user's host pairing details.
	status, out, raw = callJSON(t, srv, "admin-secret", http.MethodGet, "/api/users", nil)
	if status != 200 {
		t.Fatalf("admin users = %d %s", status, raw)
	}
	for _, rawUser := range out["users"].([]any) {
		u := rawUser.(map[string]any)
		if u["id"] == aliceID || u["id"] == bobID {
			if len(u["hosts"].([]any)) != 1 {
				t.Fatalf("management user row missing host pairing: %v", u)
			}
		}
	}
	// Admin cannot address a user's host even though it owns its own host.
	if status, _, _ := callJSON(t, srv, "admin-secret", http.MethodGet, "/api/prompt?host="+aliceHost, nil); status != 403 {
		t.Fatalf("admin relay alice host = %d, want 403", status)
	}
	if status, _, _ := callJSON(t, srv, "admin-secret", http.MethodGet, "/api/events?host="+aliceHost+"&after=0", nil); status != 403 {
		t.Fatalf("admin events alice host = %d, want 403", status)
	}
	_ = adminHost

	// Cross-user host management and event access are denied.
	if status, _, _ := callJSON(t, srv, alice, http.MethodPost, "/api/hosts/"+bobHost+"/rename", map[string]any{"hostName": "hacked"}); status != 403 {
		t.Fatalf("alice rename bob host = %d, want 403", status)
	}
	if status, _, _ := callJSON(t, srv, alice, http.MethodDelete, "/api/hosts/"+bobHost, nil); status != 403 {
		t.Fatalf("alice delete bob host = %d, want 403", status)
	}
	if status, _, _ := callJSON(t, srv, alice, http.MethodGet, "/api/events?host="+bobHost+"&after=0", nil); status != 403 {
		t.Fatalf("alice events bob host = %d, want 403", status)
	}
	// Relay permission is checked before dispatch: another user's host is
	// 403; an owned but offline host reaches dispatch and returns 503.
	if status, _, _ := callJSON(t, srv, alice, http.MethodGet, "/api/prompt?host="+bobHost, nil); status != 403 {
		t.Fatalf("alice relay bob host = %d, want 403", status)
	}
	if status, _, _ := callJSON(t, srv, alice, http.MethodGet, "/api/prompt?host="+aliceHost, nil); status != 503 {
		t.Fatalf("alice relay own offline host = %d, want 503", status)
	}

	// Prefs are per-user.
	status, _, raw = callJSON(t, srv, alice, http.MethodPut, "/api/prefs", map[string]any{
		"prefs": map[string]any{"entries": map[string]any{"se:only-alice": map[string]any{"v": "1", "at": 10, "site": "alice"}}},
	})
	if status != 200 {
		t.Fatalf("alice prefs put = %d %s", status, raw)
	}
	_, out, _ = callJSON(t, srv, alice, http.MethodGet, "/api/prefs", nil)
	if len(out["prefs"].(map[string]any)["pinnedSessions"].([]any)) != 1 {
		t.Fatalf("alice prefs = %v", out)
	}
	_, out, _ = callJSON(t, srv, bob, http.MethodGet, "/api/prefs", nil)
	if got := out["prefs"].(map[string]any)["pinnedSessions"].([]any); len(got) != 0 {
		t.Fatalf("bob saw alice prefs: %v", got)
	}

	// Deleting a user unpairs every host it owned.
	if status, _, raw := callJSON(t, srv, "admin-secret", http.MethodPost, "/api/users/delete", map[string]any{"id": aliceID}); status != 200 {
		t.Fatalf("delete alice = %d %s", status, raw)
	}
	status, out, raw = callJSON(t, srv, "admin-secret", http.MethodGet, "/api/hosts", nil)
	if status != 200 || len(out["hosts"].([]any)) != 1 || out["hosts"].([]any)[0].(map[string]any)["hostName"] != "Admin Mac" {
		t.Fatalf("admin hosts after delete = %d %s", status, raw)
	}
	// Bob remains in the management list with his host pairing.
	status, out, raw = callJSON(t, srv, "admin-secret", http.MethodGet, "/api/users", nil)
	if status != 200 || len(out["users"].([]any)) != 1 {
		t.Fatalf("users after delete = %d %s", status, raw)
	}
	bobRow := out["users"].([]any)[0].(map[string]any)
	if bobRow["id"] != bobID || len(bobRow["hosts"].([]any)) != 1 {
		t.Fatalf("bob management row = %v", bobRow)
	}
	if status, _, _ = callJSON(t, srv, alice, http.MethodGet, "/api/access-role", nil); status != 401 {
		t.Fatalf("deleted user token status = %d, want 401", status)
	}
}
