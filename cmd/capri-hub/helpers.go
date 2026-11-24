package main

import (
	"encoding/json"
	"github.com/AgentsHarness/capri-hub/internal/hub"
	"io"
	"net/http"
	"strings"
	"time"
)

// ── helpers ───────────────────────────────────────────────────────────

// identity is who a browser-facing request speaks for. Admin = the
// deployment's FE_TOKEN. Guest = one record from guests.json, restricted
// to that record's session whitelist.
type identity struct {
	Role      string // "admin" | "user" | "guest"
	UserID    string // users.json id (user only; "root" for admin)
	TokenID   string // guests.json id (guest only)
	Label     string
	ExpiresAt int64
	Sessions  []hub.GuestSession
}

func (id identity) isAdmin() bool { return id.Role == "" || id.Role == "admin" }
func (id identity) isUser() bool  { return id.Role == "user" }
func (id identity) isGuest() bool { return id.Role == "guest" }

// prefsOwner returns the prefs document this identity owns. Admin and user
// both have one; guests have no prefs surface.
func (id identity) prefsOwner() string {
	if id.isUser() {
		return id.UserID
	}
	return "root"
}

// hostScope is the owner id whose hosts this identity may use. The admin
// account behaves as a normal user for host access: it only sees hosts
// paired under root. Its extra capability is the user-management view.
func (id identity) hostScope() string {
	if id.isUser() {
		return id.UserID
	}
	return "root"
}

// idemScope is the idempotency namespace this identity writes in. Both the
// key and the scope reach the host, which stores by (host, scope, key), so
// two users reusing the same key never collide. The browser cannot override
// it: handleRelay ignores its Idempotency-Scope header.
func (id identity) idemScope() string {
	switch {
	case id.isGuest():
		return "guest:" + id.TokenID
	case id.isUser():
		return "user:" + id.UserID
	default:
		return "root"
	}
}

// allowsHost reports whether this identity may address hostID. Admin and
// ordinary users can only use hosts they paired themselves; guests only
// hosts named by their whitelist.
func (id identity) allowsHost(h *hub.Hub, hostID string) bool {
	if id.isGuest() {
		for _, s := range id.Sessions {
			if s.HostID == hostID {
				return true
			}
		}
		return false
	}
	owner, ok := h.HostOwner(hostID)
	return ok && owner == id.hostScope()
}

// defaultHost is the host an identity falls back to when the request names
// none. Admin and users pick from their own host set; guests pick the first
// whitelisted session's host.
func (id identity) defaultHost(h *hub.Hub) string {
	if id.isGuest() {
		for _, s := range id.Sessions {
			if s.HostID != "" {
				return s.HostID
			}
		}
		return ""
	}
	return h.DefaultHostIDFor(id.hostScope())
}

// sessionFor resolves the (sessionId, cwd) a guest request must be
// rewritten to on hostID: the requested session when whitelisted, else the
// host's first whitelisted session. ("", "") when the host has none.
func (id identity) sessionFor(hostID, sessionID string) (string, string) {
	var first *hub.GuestSession
	for i := range id.Sessions {
		s := &id.Sessions[i]
		if s.HostID != hostID {
			continue
		}
		if first == nil {
			first = s
		}
		if sessionID != "" && s.SessionID == sessionID {
			return s.SessionID, s.Cwd
		}
	}
	if first == nil {
		return "", ""
	}
	return first.SessionID, first.Cwd
}

// asGuestToken rebuilds the guests.json record shape for subscription
// bookkeeping (the hub's subscriber filter wants the whitelist).
func (id identity) asGuestToken() hub.GuestToken {
	return hub.GuestToken{ID: id.TokenID, Label: id.Label, ExpiresAt: id.ExpiresAt, Sessions: id.Sessions}
}

// relayedSessionID reads the sessionId a (rewritten) relay body targets.
func relayedSessionID(body []byte) string {
	var obj struct {
		SessionID string `json:"sessionId"`
	}
	if json.Unmarshal(body, &obj) != nil {
		return ""
	}
	return obj.SessionID
}

// feAuth gates browser-facing routes. Empty FE_TOKEN leaves the admin door
// open (dev); guest tokens from guests.json are accepted regardless, since
// they are the whole point of the guest feature.
//
// Prefer short-lived tickets for WebSocket query auth.
type feAuth struct {
	token   string
	tickets *feTicketStore
	// hub resolves guest tokens and (for tickets) the identity behind a
	// guest id. Nil in tests that only exercise the admin path.
	hub *hub.Hub
	// limiter throttles failed token attempts per client IP. Nil in tests
	// that construct feAuth directly; production buildHandler supplies one.
	limiter *authLimiter
}

// identifyWithLimit is the production authentication entry point. It checks
// the failure throttle before looking at credentials and records only failed
// attempts that actually carried a credential, so the FE's token-less boot
// probes do not consume a user's failure budget.
func (a feAuth) identifyWithLimit(r *http.Request) (identity, bool) {
	ip := rateLimitIP(r)
	if a.limiter != nil && !a.limiter.allow(ip) {
		return identity{}, false
	}
	id, ok := a.identify(r)
	if a.limiter != nil {
		if ok {
			a.limiter.reset(ip)
		} else if credentialPresent(r) {
			a.limiter.fail(ip)
		}
	}
	return id, ok
}

func credentialPresent(r *http.Request) bool {
	return bearerToken(r.Header.Get("Authorization")) != "" ||
		strings.TrimSpace(r.Header.Get("X-Access-Token")) != "" ||
		strings.TrimSpace(r.URL.Query().Get("ticket")) != ""
}

// identify resolves the identity behind r, in this order:
//  1. admin Bearer / X-Access-Token (FE_TOKEN),
//  2. a user token in Bearer / X-Access-Token,
//  3. a guest token in Bearer / X-Access-Token,
//  4. a single-use ?ticket= (admin, user or guest identity).
//
// User and guest lookups reject revoked / expired records.
func (a feAuth) identify(r *http.Request) (identity, bool) {
	if a.token != "" {
		for _, tok := range []string{
			bearerToken(r.Header.Get("Authorization")),
			strings.TrimSpace(r.Header.Get("X-Access-Token")),
		} {
			if tokenEqual(tok, a.token) {
				return identity{Role: "admin", UserID: "root"}, true
			}
		}
	} else if strings.TrimSpace(r.Header.Get("Authorization")) == "" &&
		strings.TrimSpace(r.Header.Get("X-Access-Token")) == "" {
		// Open dev hub with no FE_TOKEN: anonymous = admin, as before.
		if r.URL.Query().Get("ticket") == "" {
			return identity{Role: "admin", UserID: "root"}, true
		}
	}

	if a.hub != nil {
		for _, tok := range []string{
			bearerToken(r.Header.Get("Authorization")),
			strings.TrimSpace(r.Header.Get("X-Access-Token")),
		} {
			if u, ok := a.hub.UserByToken(tok); ok {
				return userIdentity(u), true
			}
			if g, ok := a.hub.LookupGuestToken(tok); ok {
				return guestIdentity(g), true
			}
		}
	}

	// Short-lived ticket (preferred for WebSocket).
	if a.tickets != nil {
		if t := strings.TrimSpace(r.URL.Query().Get("ticket")); t != "" {
			rec, ok := a.tickets.consumeIdentity(t)
			if !ok {
				return identity{}, false
			}
			switch rec.role {
			case "admin":
				return identity{Role: "admin", UserID: "root"}, true
			case "user":
				if a.hub == nil {
					return identity{}, false
				}
				u, found := a.hub.UserByID(rec.userID)
				if !found {
					return identity{}, false
				}
				return userIdentity(u), true
			case "guest":
				if a.hub == nil {
					return identity{}, false
				}
				g, found := a.hub.GuestByID(rec.guestID)
				if !found || !g.Active(time.Now()) {
					return identity{}, false
				}
				return guestIdentity(g), true
			}
		}
	}
	return identity{}, false
}

// identityMayManageHost reports whether r's identity may unpair or rename
// hostID. Direct handler tests carry no identity and keep admin behaviour.
// A missing host is left to the handler's normal 404 path.
func identityMayManageHost(h *hub.Hub, r *http.Request, hostID string) bool {
	id, identified := identityOf(r)
	if !identified {
		return true
	}
	if id.isGuest() {
		return false
	}
	owner, exists := h.HostOwner(hostID)
	if !exists {
		return true
	}
	return owner == id.hostScope()
}

func userIdentity(u hub.User) identity {
	return identity{
		Role:   "user",
		UserID: u.ID,
		Label:  u.Label,
	}
}

func guestIdentity(g hub.GuestToken) identity {
	return identity{
		Role:      "guest",
		TokenID:   g.ID,
		Label:     g.Label,
		ExpiresAt: g.ExpiresAt,
		Sessions:  g.Sessions,
	}
}

// check is the boolean form (kept for tests / callers that only gate).
func (a feAuth) check(r *http.Request) bool {
	_, ok := a.identify(r)
	return ok
}

// requireAny allows admin and guest identities (access-role, ws-ticket).
// The resolved identity rides in the request context so downstream handlers
// never re-resolve (a ?ticket= is single-use — a second lookup would fail).
func (a feAuth) requireAny(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := a.identifyWithLimit(r)
		if !ok {
			writeJSON(w, 401, map[string]any{"ok": false, "error": "需要有效的访问 token"})
			return
		}
		next(w, r.WithContext(withIdentity(r.Context(), id)))
	}
}

// requireAdmin allows only the admin identity; users and guests get 403 so
// the FE can tell "you are not allowed to manage accounts" from "your token
// is dead".
func (a feAuth) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := a.identifyWithLimit(r)
		if !ok {
			writeJSON(w, 401, map[string]any{"ok": false, "error": "需要有效的访问 token"})
			return
		}
		if !id.isAdmin() {
			writeJSON(w, 403, map[string]any{"ok": false, "error": "仅管理员可执行该操作"})
			return
		}
		next(w, r.WithContext(withIdentity(r.Context(), id)))
	}
}

// requireMember allows admin and ordinary user identities. Guests are
// read-only and get 403 for host management, pairing codes, events and
// prefs endpoints.
func (a feAuth) requireMember(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := a.identifyWithLimit(r)
		if !ok {
			writeJSON(w, 401, map[string]any{"ok": false, "error": "需要有效的访问 token"})
			return
		}
		if id.isGuest() {
			writeJSON(w, 403, map[string]any{"ok": false, "error": "访客模式不支持该操作"})
			return
		}
		next(w, r.WithContext(withIdentity(r.Context(), id)))
	}
}

// requireAnyIdentity attaches the resolved identity to the request context
// so the relay can enforce host/session scope without resolving twice.
func (a feAuth) requireIdentified(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := a.identifyWithLimit(r)
		if !ok {
			writeJSON(w, 401, map[string]any{"ok": false, "error": "需要有效的访问 token"})
			return
		}
		next(w, r.WithContext(withIdentity(r.Context(), id)))
	}
}

// requireFEToken is kept for tests; production code uses feAuth.
func requireFEToken(expected string, next http.HandlerFunc) http.HandlerFunc {
	return feAuth{token: expected}.requireAdmin(next)
}

// checkFEToken is kept for tests.
func checkFEToken(r *http.Request, expected string) bool {
	return feAuth{token: expected}.check(r)
}

func bearerToken(auth string) string {
	auth = strings.TrimSpace(auth)
	const prefix = "Bearer "
	if len(auth) >= len(prefix) && strings.EqualFold(auth[:len(prefix)], prefix) {
		return strings.TrimSpace(auth[len(prefix):])
	}
	return ""
}

func tokenEqual(a, b string) bool {
	if a == "" || b == "" || len(a) != len(b) {
		return false
	}
	// Constant-time compare to avoid timing leaks on the shared secret.
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// authHost resolves the Bearer token to a hostId.
func authHost(h *hub.Hub, r *http.Request) (string, bool) {
	tok := bearerToken(r.Header.Get("Authorization"))
	return h.HostIDForToken(tok)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 5<<20))
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, dst)
}

// withCORS applies CORS. When origins is empty/nil, Allow-Origin is `*`
// (dev). When set (from CORS_ORIGINS), only listed origins are reflected.
func withCORS(next http.Handler, origins []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Access-Token, Idempotency-Key")
		if len(origins) == 0 {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else if origin := r.Header.Get("Origin"); origin != "" && corsOriginAllowed(origin, origins) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func corsOriginAllowed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if a == origin {
			return true
		}
	}
	return false
}
