package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/AgentsHarness/capri-hub/internal/hub"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── handlers ──────────────────────────────────────────────────────────

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true, "service": "capri-hub"})
}

// version is stamped at build time via
// go build -ldflags "-X main.version=<tag>".
// Plain `go build` leaves it "dev"; effectiveVersion then falls back to the
// VCS metadata Go embeds, so a local binary still identifies its revision.
var version = "dev"

// effectiveVersion is what /api/info and the startup log report.
func effectiveVersion() string {
	info, _ := debug.ReadBuildInfo()
	return resolveVersion(version, info)
}

// resolveVersion keeps a stamped release version untouched. For "dev" it
// derives dev-<shortsha> from the build's VCS settings; without VCS metadata
// (module zip, -buildvcs=false) it stays the plain "dev" fallback.
func resolveVersion(stamped string, info *debug.BuildInfo) string {
	if stamped != "dev" || info == nil {
		return stamped
	}
	var rev string
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			rev = s.Value
		}
	}
	if rev == "" {
		return stamped
	}
	if len(rev) > 7 {
		rev = rev[:7]
	}
	return "dev-" + rev
}

func handleInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"service": "capri-hub",
		"version": effectiveVersion(),
		"modes":   []string{"pair", "host-ws", "host-quic", "relay", "fe-ws"},
	})
}

// handleEvents: gap-pull endpoint — buffered events for a host with
// seq > after. GET /api/events?host=X&after=N
func handleEvents(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hostID := r.URL.Query().Get("host")
		if hostID == "" {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "需要 host 参数"})
			return
		}
		ident, _ := identityOf(r)
		if !ident.allowsHost(h, hostID) {
			writeJSON(w, 403, map[string]any{"ok": false, "error": "无权访问该 Host"})
			return
		}
		after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		evs := h.EventsAfter(hostID, after)
		// Buffered events may carry pre-encoded wire bytes (hub.MarshalEvent
		// returns them verbatim); hub-level frames marshal normally.
		raws := make([]json.RawMessage, len(evs))
		for i, ev := range evs {
			b, err := hub.MarshalEvent(ev)
			if err != nil {
				writeJSON(w, 500, map[string]any{"ok": false, "error": err.Error()})
				return
			}
			raws[i] = b
		}
		writeJSON(w, 200, map[string]any{"ok": true, "hostId": hostID, "events": raws})
	}
}

// handleStats: GET /api/stats — admin-only delivery diagnostics. Every
// degradation path in the relay claims it is recoverable (fan-out overflow
// is gap-pulled, a slow subscriber gets a resync); this endpoint is where
// those claims become observable numbers instead of host-side log
// archaeology.
func handleStats(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := h.Stats()
		writeJSON(w, 200, map[string]any{
			"ok":            true,
			"hosts":         st.Hosts,
			"pairedHosts":   st.PairedHosts,
			"subscribers":   st.Subscribers,
			"feDropped":     st.FEDropped,
			"feResyncs":     st.FEResyncs,
			"relay":         st.Relay,
			"uptimeSeconds": st.UptimeSeconds,
		})
	}
}

// handlePairing: GET /api/pairing — the caller's own pairing code. Admin
// gets the deployment-wide code; a user gets a private code that binds any
// host it pairs to that user.
func handlePairing(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ident, _ := identityOf(r)
		code, exp := h.UserPairingCode(ident.prefsOwner())
		writeJSON(w, 200, map[string]any{
			"code":      code,
			"expiresAt": exp,
			"ttl":       int(hub.PairingCodeTTL / time.Minute),
		})
	}
}

func handleRotate(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ident, _ := identityOf(r)
		code, exp := h.RotateUserPairingCode(ident.prefsOwner())
		writeJSON(w, 200, map[string]any{"code": code, "expiresAt": exp})
	}
}

// Brute-force guard for POST /api/pair: the pairing code is 6 chars from
// a 32-char alphabet (32^6 ≈ 1.07e9) and lives for 15 minutes, so an
// attacker must be throttled per IP. Normal flows are unaffected: hosts
// pair once at startup, and re-pair retries use exponential backoff
// (1s→30s), well under 10 attempts/minute.
//
// Rate limiting alone is enough — we do not sleep on failed attempts
// (that would pin handler goroutines under flood).
const (
	pairRateLimit  = 10          // attempts per window per IP
	pairRateWindow = time.Minute // sliding window
)

// pairLimiter is a per-client-IP sliding-window rate limiter for /api/pair.
//
// In production the hub listens on 127.0.0.1 behind nginx, so RemoteAddr is
// always the proxy address. rateLimitIP uses the proxy-provided real client
// address when (and only when) the peer is loopback; direct connections keep
// using RemoteAddr. Without this distinction every request behind nginx
// shares one hub-wide quota and one host's retry loop can lock out all new
// pairings.
type pairLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func newPairLimiter() *pairLimiter {
	return &pairLimiter{hits: make(map[string][]time.Time)}
}

// StartCleanup periodically drops expired IP entries until ctx is done.
func (l *pairLimiter) StartCleanup(ctx context.Context) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				l.mu.Lock()
				l.pruneLocked(time.Now().Add(-pairRateWindow))
				l.mu.Unlock()
			}
		}
	}()
}

func (l *pairLimiter) pruneLocked(cutoff time.Time) {
	for k, v := range l.hits {
		i := 0
		for i < len(v) && v[i].Before(cutoff) {
			i++
		}
		v = v[i:]
		if len(v) == 0 {
			delete(l.hits, k)
		} else {
			l.hits[k] = v
		}
	}
}

// allow records a request from ip and reports whether it stays within
// the window's budget. Stale entries are pruned on access.
func (l *pairLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-pairRateWindow)
	// Opportunistic full prune when the map is large (in addition to the
	// background cleaner).
	if len(l.hits) > 256 {
		l.pruneLocked(cutoff)
	}
	hs := l.hits[ip]
	i := 0
	for i < len(hs) && hs[i].Before(cutoff) {
		i++
	}
	hs = hs[i:]
	if len(hs) >= pairRateLimit {
		if len(hs) == 0 {
			delete(l.hits, ip)
		} else {
			l.hits[ip] = hs
		}
		return false
	}
	l.hits[ip] = append(hs, now)
	return true
}

// clientIP returns the client's IP without the port. The hub is
// deployed/run directly; no proxy forwarding headers are trusted.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// requestIP is the address to DISPLAY for a browser (the subscriber panel).
// It prefers forwarding headers when the peer is loopback: the deployed hub
// listens on 127.0.0.1 behind nginx, so every row would otherwise read
// 127.0.0.1. rateLimitIP applies the same trusted-proxy policy to rate
// limiting.
//
// Order matters on the deployed site: Cloudflare sits in front of nginx, so
// nginx's X-Real-IP is a CF edge address, while CF-Connecting-IP and the
// first X-Forwarded-For hop carry the real client. Headers from a
// non-loopback peer are ignored (direct dials cannot spoof the display).
func requestIP(r *http.Request) string {
	peer := clientIP(r)
	if isLoopbackHost(peer) {
		if real := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); real != "" {
			return real
		}
		if fwd := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); fwd != "" {
			first, _, _ := strings.Cut(fwd, ",")
			return strings.TrimSpace(first)
		}
		if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); real != "" {
			return real
		}
	}
	return peer
}

// rateLimitIP is the address used for authentication and pairing rate
// limits. It deliberately mirrors requestIP's trusted-proxy policy but only
// accepts values that parse as IP addresses: the deployed hub sits behind
// nginx on loopback, where RemoteAddr cannot identify the client, while a
// direct (non-loopback) peer can never spoof its identity through headers.
func rateLimitIP(r *http.Request) string {
	peer := clientIP(r)
	if !isLoopbackHost(peer) {
		return peer
	}
	for _, candidate := range []string{
		r.Header.Get("CF-Connecting-IP"),
		r.Header.Get("X-Real-IP"),
	} {
		if ip := net.ParseIP(strings.TrimSpace(candidate)); ip != nil {
			return ip.String()
		}
	}
	if fwd := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); fwd != "" {
		first, _, _ := strings.Cut(fwd, ",")
		if ip := net.ParseIP(strings.TrimSpace(first)); ip != nil {
			return ip.String()
		}
	}
	return peer
}

// authLimiter throttles failed authentication attempts per client IP. A
// correct token clears the bucket; failures accumulate in a sliding window
// and then impose a short block. This keeps online token guessing expensive
// without penalising a browser that makes normal successful requests.
type authLimiter struct {
	mu     sync.Mutex
	failed map[string][]time.Time
	block  map[string]time.Time
}

const (
	authFailureLimit  = 10
	authFailureWindow = time.Minute
	authBlockDuration = time.Minute
)

func newAuthLimiter() *authLimiter {
	return &authLimiter{failed: make(map[string][]time.Time), block: make(map[string]time.Time)}
}

// allow reports whether an authentication attempt from ip may be evaluated.
func (l *authLimiter) allow(ip string) bool {
	if l == nil || ip == "" {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if until, ok := l.block[ip]; ok {
		if now.Before(until) {
			return false
		}
		delete(l.block, ip)
		delete(l.failed, ip)
	}
	l.pruneLocked(now.Add(-authFailureWindow))
	return true
}

func (l *authLimiter) fail(ip string) {
	if l == nil || ip == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-authFailureWindow)
	hs := l.failed[ip]
	i := 0
	for i < len(hs) && hs[i].Before(cutoff) {
		i++
	}
	hs = append(hs[i:], now)
	l.failed[ip] = hs
	if len(hs) >= authFailureLimit {
		l.block[ip] = now.Add(authBlockDuration)
	}
}

func (l *authLimiter) reset(ip string) {
	if l == nil || ip == "" {
		return
	}
	l.mu.Lock()
	delete(l.failed, ip)
	delete(l.block, ip)
	l.mu.Unlock()
}

func (l *authLimiter) pruneLocked(cutoff time.Time) {
	for ip, hs := range l.failed {
		i := 0
		for i < len(hs) && hs[i].Before(cutoff) {
			i++
		}
		if i == len(hs) {
			delete(l.failed, ip)
		} else {
			l.failed[ip] = hs[i:]
		}
	}
}

// isLoopbackHost is a string test (the panel never dials back, so a parse
// failure simply means "not a proxy we trust").
func isLoopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func handlePair(h *hub.Hub, lim *pairLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Rate-limit before parsing the body: a flood of malformed
		// attempts must cost the same as valid ones.
		if !lim.allow(rateLimitIP(r)) {
			w.Header().Set("Retry-After", strconv.Itoa(int(pairRateWindow/time.Second)))
			writeJSON(w, 429, map[string]any{"ok": false, "error": "尝试过于频繁，请稍后再试"})
			return
		}
		var body struct {
			Code     string `json:"code"`
			HostID   string `json:"hostId"`
			HostName string `json:"hostName"`
			Port     int    `json:"port"` // optional local HTTP listen port
		}
		if err := readJSON(r, &body); err != nil || body.Code == "" || body.HostID == "" {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "需要 code 和 hostId"})
			return
		}
		ownerID, ok := h.OwnerForPairCode(body.Code)
		if !ok {
			writeJSON(w, 401, map[string]any{"ok": false, "error": hub.ErrCodeInvalid.Error()})
			return
		}
		token, actualHostID, err := h.PairAs(ownerID, body.Code, body.HostID, body.HostName, body.Port)
		if err != nil {
			status := 401
			if errors.Is(err, hub.ErrHostLimit) {
				status = 429
			} else if !errors.Is(err, hub.ErrCodeInvalid) {
				status = 400
			}
			writeJSON(w, status, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "token": token, "hostId": actualHostID})
	}
}

// feTicketTTL is long enough for a browser to open WS after minting,
// short enough that a leaked ticket in access logs ages out quickly.
const feTicketTTL = 2 * time.Minute

// feTicket is one single-use WS ticket. guestID is empty for an admin
// ticket; otherwise it names the guests.json record the ticket was minted
// for, so the WS can rebuild that identity without re-reading the header.
type feTicket struct {
	expires time.Time
	role    string
	userID  string
	guestID string
}

// feTicketStore issues single-use short-lived tickets for /ws/fe so the
// long-lived FE_TOKEN need not appear in query strings / proxy logs.
type feTicketStore struct {
	mu      sync.Mutex
	tickets map[string]feTicket
}

func newFETicketStore() *feTicketStore {
	return &feTicketStore{tickets: make(map[string]feTicket)}
}

// StartCleanup drops expired tickets until ctx is done.
func (s *feTicketStore) StartCleanup(ctx context.Context) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.mu.Lock()
				now := time.Now()
				for k, exp := range s.tickets {
					if !exp.expires.After(now) {
						delete(s.tickets, k)
					}
				}
				s.mu.Unlock()
			}
		}
	}()
}

// issue mints a legacy guest ticket. Empty guestID means admin; non-empty
// means a guest record. identity-based callers use issueIdentity.
func (s *feTicketStore) issue(guestID string) (ticket string, expires time.Time) {
	role := "admin"
	if guestID != "" {
		role = "guest"
	}
	return s.issueTicket(feTicket{role: role, guestID: guestID})
}

// issueIdentity mints a ticket for any authenticated identity.
func (s *feTicketStore) issueIdentity(id identity) (ticket string, expires time.Time) {
	return s.issueTicket(feTicket{role: id.Role, userID: id.UserID, guestID: id.TokenID})
}

func (s *feTicketStore) issueTicket(rec feTicket) (ticket string, expires time.Time) {
	var b [24]byte
	_, _ = rand.Read(b[:])
	ticket = hex.EncodeToString(b[:])
	rec.expires = time.Now().Add(feTicketTTL)
	expires = rec.expires
	s.mu.Lock()
	s.tickets[ticket] = rec
	s.mu.Unlock()
	return ticket, expires
}

// consume validates and burns a legacy ticket, returning the guest id (empty
// for admin).
func (s *feTicketStore) consume(ticket string) (guestID string, ok bool) {
	rec, ok := s.consumeIdentity(ticket)
	if !ok {
		return "", false
	}
	return rec.guestID, true
}

// consumeIdentity validates and burns a ticket, returning its full identity
// record.
func (s *feTicketStore) consumeIdentity(ticket string) (feTicket, bool) {
	if ticket == "" {
		return feTicket{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, found := s.tickets[ticket]
	if !found {
		return feTicket{}, false
	}
	delete(s.tickets, ticket)
	if !rec.expires.After(time.Now()) {
		return feTicket{}, false
	}
	return rec, true
}

func handleWSTicket(h *hub.Hub, tickets *feTicketStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// requireAny already resolved (and burned any ?ticket=) — reusing
		// the context identity keeps guest tickets pointable at their
		// guests.json record.
		ident, ok := identityFromRequest(r, h)
		if !ok {
			writeJSON(w, 401, map[string]any{"ok": false, "error": "需要有效的访问 token"})
			return
		}
		ticket, exp := tickets.issueIdentity(ident)
		writeJSON(w, 200, map[string]any{
			"ok":        true,
			"ticket":    ticket,
			"expiresAt": exp,
			"ttlSec":    int(feTicketTTL / time.Second),
			"role":      ident.Role,
		})
	}
}

// handlePrefsGet: GET /api/prefs — the calling identity's prefs document
// (pinned workspaces / sessions + per-session todo status). Admin uses the
// root prefs.json, ordinary users use their own prefs-users.json entry, so
// pins and todos never leak across accounts.
func handlePrefsGet(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ident, _ := identityOf(r)
		doc, version := h.PrefsFor(ident.prefsOwner())
		writeJSON(w, 200, map[string]any{"ok": true, "prefs": doc, "version": version})
	}
}

// handlePrefsPut: PUT /api/prefs {prefs: {...}} — fold a browser prefs write
// into the stored document.
//
// The hub MERGES per item (see internal/hub/prefs.go), so the write needs no
// condition; the doc is small (pins + todos) and no size cap is enforced.
// The success response carries the merged doc: a client uses its presence as
// proof that its write was folded in, and keeps its retry marker otherwise.
func handlePrefsPut(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Prefs *hub.BrowserPrefs `json:"prefs"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Prefs == nil {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "需要 prefs 字段"})
			return
		}
		ident, _ := identityOf(r)
		if _, err := h.SetPrefsFor(ident.prefsOwner(), *body.Prefs); err != nil {
			writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		// Read the doc+version as one pair: a concurrent writer may have
		// advanced past our SetPrefs, and returning that newer authoritative
		// state is still correct for the client's merge.
		doc, version := h.PrefsFor(ident.prefsOwner())
		writeJSON(w, 200, map[string]any{"ok": true, "version": version, "prefs": doc})
	}
}

// handleUnpair: DELETE /api/hosts/{hostId} — admin remove a paired host.
func handleUnpair(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hostID := strings.TrimSpace(r.PathValue("hostId"))
		if hostID == "" {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "需要 hostId"})
			return
		}
		if !identityMayManageHost(h, r, hostID) {
			writeJSON(w, 403, map[string]any{"ok": false, "error": "无权管理该 Host"})
			return
		}
		if err := h.Unpair(hostID); err != nil {
			if errors.Is(err, hub.ErrHostUnknown) {
				writeJSON(w, 404, map[string]any{"ok": false, "error": err.Error()})
				return
			}
			writeJSON(w, 500, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "hostId": hostID})
	}
}

// handleRenameHost: POST /api/hosts/{hostId}/rename {hostName} — update
// a paired host's display name without touching its token/connection.
func handleRenameHost(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hostID := strings.TrimSpace(r.PathValue("hostId"))
		if hostID == "" {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "需要 hostId"})
			return
		}
		if !identityMayManageHost(h, r, hostID) {
			writeJSON(w, 403, map[string]any{"ok": false, "error": "无权管理该 Host"})
			return
		}
		var body struct {
			HostName string `json:"hostName"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "请求体不是合法 JSON"})
			return
		}
		if err := h.RenameHost(hostID, body.HostName); err != nil {
			if errors.Is(err, hub.ErrHostUnknown) {
				writeJSON(w, 404, map[string]any{"ok": false, "error": err.Error()})
				return
			}
			writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "hostId": hostID, "hostName": body.HostName})
	}
}
