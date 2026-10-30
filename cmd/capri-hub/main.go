// capri-hub: 中心化中转服务器（relay）。
//
//		Browser (capri-fe) ──WS /ws/fe + HTTP /api/*──▶ capri-hub ──QUIC/WS /ws/host──▶ capri-host × N ──stdio──▶ grok
//
//	  - 配对：Host 用配对码换取 token（POST /api/pair），token 持久化在 ~/.capri-hub。
//	  - Host 出站连接（GET /ws/host 或 QUIC UDP）：v2 会话协议，下行 request/audience，上行 events/respond/hb。
//	  - 浏览器 WebSocket（GET /ws/fe）：聚合 live 事件；/api/* 按 ?host= 中转给对应 Host。
//	  - 可选 FE_TOKEN：部署时设置后，浏览器侧接口必须带同一 token（Bearer / 头）。
//	    WebSocket 优先用短期 ?ticket=（POST /api/ws-ticket）；仍兼容 ?token=。
//	  - 可靠性：事件带 seq（host 分配，会话按事件推进水位），hub 缓冲每 host
//	    最近的 gap-pull 环，GET /api/events?host=X&after=SEQ 供缺口补拉。
package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/AgentsHarness/capri-hub/internal/hub"
	"github.com/AgentsHarness/capri-wire"
	"github.com/coder/websocket"
	"github.com/quic-go/quic-go"
)

func main() {
	// Subcommands run and exit without starting a server. Only an exact
	// match is intercepted so any existing invocation (which passes no
	// arguments) keeps booting the hub.
	if len(os.Args) > 1 && os.Args[1] == "paircode" {
		os.Exit(runPairCode(os.Args[2:], os.Stdout, os.Stderr))
	}

	// Per-event detail is opt-in: a host that restarts mid-session otherwise
	// writes one line per rejected event into the journal.
	logLevel := hub.SetLogLevel(os.Getenv("CAPRI_LOG_LEVEL"))

	port := 8787
	if v := os.Getenv("PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			port = n
		}
	}
	quicPort := 8788
	if v := os.Getenv("QUIC_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			quicPort = n
		}
	}

	// Browser / FE access token. When set, browser-facing routes require it
	// (Authorization: Bearer, X-Access-Token; WS prefers short-lived ticket).
	// Host-facing routes keep their own pairing Bearer tokens.
	feToken := strings.TrimSpace(os.Getenv("FE_TOKEN"))
	if feToken == "" {
		feToken = strings.TrimSpace(os.Getenv("ACCESS_TOKEN"))
	}
	if feToken == "" && envTruthy("REQUIRE_FE_TOKEN") {
		log.Fatal("[capri-hub] FE_TOKEN is required (REQUIRE_FE_TOKEN=1). Set FE_TOKEN or unset REQUIRE_FE_TOKEN for local dev.")
	}

	corsOrigins := parseCORSOrigins(os.Getenv("CORS_ORIGINS"))

	h := hub.New()
	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	h.StartPairingCodeMaintainer(runCtx)

	code, exp := h.PairingCode()
	log.Printf("[capri-hub] pairing code: %s (expires %s)", code, exp.Format("15:04:05"))
	// The line above is stale within PairingCodeTTL, so point at the
	// command that always prints the live one — this log is often the
	// only thing an operator of a container ever reads.
	log.Printf("[capri-hub] 配对码 %d 分钟后自动轮换；随时查看当前码: capri-hub paircode",
		int(hub.PairingCodeTTL/time.Minute))
	if feToken != "" {
		log.Printf("[capri-hub] FE_TOKEN set — browser requests require Authorization: Bearer <token> (WS: prefer POST /api/ws-ticket + ?ticket=)")
	} else {
		log.Printf("[capri-hub] FE_TOKEN unset — browser routes are open (local/dev only; set REQUIRE_FE_TOKEN=1 in production)")
	}
	if len(corsOrigins) > 0 {
		log.Printf("[capri-hub] CORS origins: %s", strings.Join(corsOrigins, ", "))
	}
	log.Printf("[capri-hub] listening on http://localhost:%d", port)
	log.Printf("[capri-hub] log level: %s (per-event detail: CAPRI_LOG_LEVEL=debug)", logLevel)

	tickets := newFETicketStore()
	tickets.StartCleanup(runCtx)
	lim := newPairLimiter()
	lim.StartCleanup(runCtx)

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           buildHandler(h, feToken, tickets, lim, corsOrigins),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[capri-hub] server: %v", err)
		}
	}()

	// QUIC: production (FE_TOKEN set) requires real certs unless
	// QUIC_ALLOW_SELF_SIGNED=1. Dev without FE_TOKEN may self-sign.
	var quicLn *quic.Listener
	allowSelfSigned := feToken == "" || envTruthy("QUIC_ALLOW_SELF_SIGNED")
	qtls, err := quicTLSConfig(allowSelfSigned)
	if err != nil {
		log.Printf("[capri-hub] QUIC TLS 初始化失败: %v（跳过 QUIC；Host 可走 WS）", err)
	} else {
		ln, err := listenQUIC(quicPort, qtls)
		if err != nil {
			log.Printf("[capri-hub] QUIC listen :%d failed: %v（跳过 QUIC）", quicPort, err)
		} else {
			quicLn = ln
			mode := "cert-files"
			if allowSelfSigned && os.Getenv("QUIC_CERT") == "" {
				mode = "self-signed (dev)"
			}
			log.Printf("[capri-hub] QUIC host transport on udp://:%d (%s)", quicPort, mode)
			go serveQUIC(ln, h)
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	runCancel()
	// Stop accepting new work before draining HTTP handlers.
	if quicLn != nil {
		_ = quicLn.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

// buildHandler wires all HTTP routes (shared by main and integration tests).
func buildHandler(h *hub.Hub, feToken string, tickets *feTicketStore, lim *pairLimiter, corsOrigins []string) http.Handler {
	if tickets == nil {
		tickets = newFETicketStore()
	}
	if lim == nil {
		lim = newPairLimiter()
	}
	auth := feAuth{token: feToken, tickets: tickets, hub: h}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("GET /api/info", handleInfo)
	// Admin pairing endpoints: require FE token when configured.
	mux.HandleFunc("GET /api/pairing", auth.requireAdmin(handlePairing(h)))
	mux.HandleFunc("POST /api/pairing/rotate", auth.requireAdmin(handleRotate(h)))
	// Host-facing: authenticate with host pairing token (not FE_TOKEN).
	mux.HandleFunc("POST /api/pair", handlePair(h, lim))
	mux.HandleFunc("GET /ws/host", handleHostWS(h))
	// Browser-facing: FE token gate when FE_TOKEN is set.
	mux.HandleFunc("GET /api/hosts", auth.requireIdentified(handleHosts(h)))
	mux.HandleFunc("DELETE /api/hosts/{hostId}", auth.requireAdmin(handleUnpair(h)))
	mux.HandleFunc("POST /api/hosts/{hostId}/rename", auth.requireAdmin(handleRenameHost(h)))
	// Guests do not do sequence gap-pulls: the hub filters their stream by
	// session, so the per-host seq watermark is meaningless to them.
	mux.HandleFunc("GET /api/events", auth.requireAdmin(handleEvents(h)))
	mux.HandleFunc("GET /api/prefs", auth.requireAdmin(handlePrefsGet(h)))
	mux.HandleFunc("PUT /api/prefs", auth.requireAdmin(handlePrefsPut(h)))
	mux.HandleFunc("POST /api/ws-ticket", auth.requireAny(handleWSTicket(h, tickets)))
	mux.HandleFunc("GET /ws/fe", handleFeWS(h, auth))

	// Guest tokens (admin-only management; guests read their own identity).
	mux.HandleFunc("GET /api/guest-tokens", auth.requireAdmin(handleGuestTokenList(h)))
	mux.HandleFunc("POST /api/guest-tokens/create", auth.requireAdmin(handleGuestTokenCreate(h)))
	mux.HandleFunc("POST /api/guest-tokens/update", auth.requireAdmin(handleGuestTokenUpdate(h)))
	mux.HandleFunc("POST /api/guest-tokens/delete", auth.requireAdmin(handleGuestTokenDelete(h)))
	mux.HandleFunc("POST /api/guest-tokens/sessions/add", auth.requireAdmin(handleGuestSessionsAdd(h)))
	mux.HandleFunc("POST /api/guest-tokens/sessions/remove", auth.requireAdmin(handleGuestSessionsRemove(h)))
	mux.HandleFunc("POST /api/guest-tokens/refresh", auth.requireAdmin(handleGuestTokenRefresh(h)))
	mux.HandleFunc("GET /api/access-role", auth.requireAny(handleAccessRole(h)))
	mux.HandleFunc("GET /api/guest/sessions", auth.requireIdentified(handleGuestSessions(h)))
	// Live browser subscriber roster (admin only): the top-bar count is the
	// size of it, the panel behind the count lists the rows.
	mux.HandleFunc("GET /api/subscribers", auth.requireAdmin(handleSubscribers(h)))
	// Delivery diagnostics (admin only): per-host seq / buffer / drop
	// counters and the process-wide FE backpressure totals.
	mux.HandleFunc("GET /api/stats", auth.requireAdmin(handleStats(h)))

	// Catch-all: relay everything else under /api/* to the selected host.
	mux.HandleFunc("GET /api/{path...}", auth.requireIdentified(handleRelay(h)))
	mux.HandleFunc("POST /api/{path...}", auth.requireIdentified(handleRelay(h)))
	return withCORS(mux, corsOrigins)
}

func envTruthy(name string) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func parseCORSOrigins(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "*" {
		return nil // nil ⇒ allow all (*)
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ── handlers ──────────────────────────────────────────────────────────

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true, "service": "capri-hub"})
}

// version is stamped at build time via
// go build -ldflags "-X main.version=<git-sha>-<timestamp>".
// Fallback below is used for plain `go run` / `go build`.
var version = "dev"

func handleInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"service": "capri-hub",
		"version": version,
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
			"uptimeSeconds": st.UptimeSeconds,
		})
	}
}

// handlePairing: GET /api/pairing — the current pairing code (admin only).
func handlePairing(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code, exp := h.PairingCode()
		writeJSON(w, 200, map[string]any{
			"code":      code,
			"expiresAt": exp,
			"ttl":       int(hub.PairingCodeTTL / time.Minute),
		})
	}
}

func handleRotate(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code, exp := h.RotatePairingCode()
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

// pairLimiter is a per-IP sliding-window rate limiter for /api/pair.
//
// Deployment caveat: in production the hub listens on 127.0.0.1 behind
// nginx, and clientIP deliberately ignores forwarding headers, so every
// pairing request arrives as RemoteAddr 127.0.0.1. The 10/minute budget is
// therefore ONE hub-wide quota, not a per-client one: a burst of hosts
// behind that proxy can exhaust it and see 429s until the window slides.
// That is accepted because pairing is rare (once per host at startup);
// making the key trustworthy would mean trusting a forwarded header, which
// is exactly what keeps the limit unspoofable.
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
// Unlike clientIP — which feeds the pair rate limiter and therefore must not
// be spoofable — this one prefers forwarding headers when the peer is
// loopback: the deployed hub listens on 127.0.0.1 behind nginx, so every row
// would otherwise read 127.0.0.1.
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
		if !lim.allow(clientIP(r)) {
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
		token, err := h.Pair(body.Code, body.HostID, body.HostName, body.Port)
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
		writeJSON(w, 200, map[string]any{"ok": true, "token": token, "hostId": body.HostID})
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

// issue mints a ticket; guestID != "" marks it as a guest identity.
func (s *feTicketStore) issue(guestID string) (ticket string, expires time.Time) {
	var b [24]byte
	_, _ = rand.Read(b[:])
	ticket = hex.EncodeToString(b[:])
	expires = time.Now().Add(feTicketTTL)
	s.mu.Lock()
	s.tickets[ticket] = feTicket{expires: expires, guestID: guestID}
	s.mu.Unlock()
	return ticket, expires
}

// consume validates and burns a ticket (single-use), returning the identity
// it was minted for (guest id, or "" for admin).
func (s *feTicketStore) consume(ticket string) (guestID string, ok bool) {
	if ticket == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, found := s.tickets[ticket]
	if !found {
		return "", false
	}
	delete(s.tickets, ticket)
	if !rec.expires.After(time.Now()) {
		return "", false
	}
	return rec.guestID, true
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
		ticket, exp := tickets.issue(ident.TokenID)
		writeJSON(w, 200, map[string]any{
			"ok":        true,
			"ticket":    ticket,
			"expiresAt": exp,
			"ttlSec":    int(feTicketTTL / time.Second),
			"role":      ident.Role,
		})
	}
}

// handlePrefsGet: GET /api/prefs — the browser prefs document (pinned
// workspaces / sessions + per-session todo status), persisted by the hub in
// prefs.json. One shared document for all browsers; the FE merges it with its
// localStorage cache on boot. Carries the doc's version for diagnostics.
func handlePrefsGet(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		doc, version := h.Prefs()
		writeJSON(w, 200, map[string]any{"ok": true, "prefs": doc, "version": version})
	}
}

// handlePrefsPut: PUT /api/prefs {prefs: {...}} — fold a browser prefs write
// into the stored document.
//
// The hub MERGES per item (see internal/hub/prefs.go), so the write needs no
// condition; the doc is small (pins + todos) and no size cap is enforced.
func handlePrefsPut(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Prefs *hub.BrowserPrefs `json:"prefs"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Prefs == nil {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "需要 prefs 字段"})
			return
		}
		version, err := h.SetPrefs(*body.Prefs)
		if err != nil {
			writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "version": version})
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

// ── host transports ───────────────────────────────────────────────────
//
// One Transport adapter per wire. Both hand the hub a stream of JSON frames
// and let hub.ServeHost own the session — handshake, seq/ack, retransmit,
// liveness and the close reason all live there. Nothing below interprets the
// protocol.

// hostWriteTimeout caps one downlink write so a half-open peer cannot pin the
// session loop forever.
const hostWriteTimeout = 30 * time.Second

// hostFrameLimit bounds one frame (compressed or not) on either transport. A
// relayed respond carries up to 28MB of body, so a tighter cap would kill the
// link on a large history read.
const hostFrameLimit = 32 << 20

// ── WebSocket ─────────────────────────────────────────────────────────

// wsTransport adapts one /ws/host WebSocket. A text message is one plain JSON
// frame; a binary message is one raw-deflate stream of a JSON frame, allowed
// only after hello.caps.deflate was echoed in hello_ack.
type wsTransport struct {
	conn *websocket.Conn
	// deflate is set by the session once the capability was negotiated.
	deflate atomic.Bool
	// stop ends the transport keepalive loop.
	stop      chan struct{}
	closeOnce sync.Once
}

func newWSTransport(conn *websocket.Conn) *wsTransport {
	return &wsTransport{conn: conn, stop: make(chan struct{})}
}

func (t *wsTransport) Send(payload []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), hostWriteTimeout)
	defer cancel()
	return t.conn.Write(ctx, websocket.MessageText, payload)
}

func (t *wsTransport) Recv() ([]byte, error) {
	typ, data, err := t.conn.Read(context.Background())
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageBinary {
		return data, nil
	}
	if !t.deflate.Load() {
		return nil, fmt.Errorf("%w: binary frame without deflate negotiation", wire.ErrUnreadable)
	}
	out, err := inflateUplink(data)
	if err != nil {
		return nil, fmt.Errorf("%w: inflate: %v", wire.ErrUnreadable, err)
	}
	return out, nil
}

func (t *wsTransport) SetDeflate(v bool) { t.deflate.Store(v) }

// SetKeepalive runs WS control pings at the negotiated cadence. The ping is
// not a protocol signal: it keeps NAT bindings alive and surfaces half-open
// sockets. Idle is enforced by the session's own received-frame clock.
func (t *wsTransport) SetKeepalive(d time.Duration) {
	if d <= 0 {
		d = 10 * time.Second
	}
	go func() {
		ticker := time.NewTicker(d)
		defer ticker.Stop()
		for {
			select {
			case <-t.stop:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), d)
				err := t.conn.Ping(ctx)
				cancel()
				if err != nil {
					return // the session's next read or write ends it
				}
			}
		}
	}()
}

// Close maps the session verdict onto the one WS close table.
func (t *wsTransport) Close(r wire.CloseReason) error {
	t.closeOnce.Do(func() { close(t.stop) })
	code, reason := r.WS()
	return t.conn.Close(websocket.StatusCode(code), reason)
}

// handleHostWS: host outbound WebSocket. The bearer token authenticates the
// upgrade; hello carries the epoch and the same token, and the session checks
// the two agree.
func handleHostWS(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hostID, ok := authHost(h, r)
		if !ok {
			writeJSON(w, 401, map[string]any{"ok": false, "error": "token 无效"})
			return
		}
		if q := r.URL.Query().Get("host"); q != "" && q != hostID {
			writeJSON(w, 403, map[string]any{"ok": false, "error": "host 与 token 不匹配"})
			return
		}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			// Hosts are non-browser clients; skip Origin checks.
			InsecureSkipVerify: true,
		})
		if err != nil {
			log.Printf("[capri-hub] host ws accept: %v", err)
			return
		}
		conn.SetReadLimit(hostFrameLimit)
		reason := h.ServeHost(hostID, newWSTransport(conn))
		log.Printf("[capri-hub] host %s ws session ended (%s)", hostID, reason)
	}
}

// ── host→hub uplink flate compression ─────────────────────────────────
//
// Hub side: frames arrive either as bare JSON (WS text message / QUIC length
// prefix without the flag bit) or as one raw-deflate stream of the JSON
// payload (WS binary message / QUIC length prefix with the top bit set).
// Payloads below the host's compression floor are never compressed, but the
// hub accepts any flagged frame regardless of size.

// uplinkCompressedFlag is bit 31 of the QUIC 4-byte length prefix, marking the
// frame body as a raw-deflate stream.
const uplinkCompressedFlag = 1 << 31

// parseUplinkLen splits a QUIC uplink length prefix into the true frame length
// and the compressed flag (top bit).
func parseUplinkLen(n uint32) (length uint32, compressed bool) {
	return n &^ uplinkCompressedFlag, n&uplinkCompressedFlag != 0
}

// maxInflatedFrame caps the DECOMPRESSED size of one uplink frame. Both
// transports bound the compressed bytes only, and a deflate stream expands far
// beyond its input — a small frame could otherwise balloon to gigabytes inside
// the hub. It stays above the 28MB relay-response ceiling so a big but valid
// response is not mistaken for a bad frame.
var maxInflatedFrame = 32 << 20

// inflateUplink decompresses one raw-deflate uplink payload back into the
// original JSON frame bytes.
func inflateUplink(b []byte) ([]byte, error) {
	zr := flate.NewReader(bytes.NewReader(b))
	defer zr.Close()
	// One byte past the cap distinguishes "exactly at the cap" from over it.
	out, err := io.ReadAll(io.LimitReader(zr, int64(maxInflatedFrame)+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxInflatedFrame {
		return nil, fmt.Errorf("inflated uplink frame exceeds %d bytes", maxInflatedFrame)
	}
	return out, nil
}

// maxFESubscribers caps concurrent browser /ws/fe connections: each one
// costs a 512-event channel plus two goroutines, and with FE_TOKEN unset
// the endpoint is open to anyone. Excess connections get WS close 1013
// (Try Again Later).
const maxFESubscribers = 256

// minCompressSize: event frames below this size skip flate compression —
// the flate header + sync marker overhead is not worth it, and browsers
// get to skip a decompression step.
const minCompressSize = 256

// FE WS liveness cadence (T7): protocol-level Ping every interval, pong
// must arrive within the timeout or the subscriber is reclaimed. Vars
// (not consts) so tests can tighten them.
var (
	feLivenessInterval = 20 * time.Second
	feLivenessTimeout  = 10 * time.Second
)

// Pooled flate writers/buffers for the compressed /ws/fe path: under
// chunk storms writeEventsFrame runs per frame, and a fresh
// flate.Writer + bytes.Buffer per frame would hammer the GC.
// flate.Writer.Reset re-targets a writer after Close, so pooled writers
// are fully reusable.
var (
	flateWriterPool = sync.Pool{
		New: func() any {
			fw, _ := flate.NewWriter(io.Discard, flate.BestSpeed)
			return fw
		},
	}
	flateBufPool = sync.Pool{
		New: func() any { return new(bytes.Buffer) },
	}
)

// handleFeWS: aggregated live event stream for browsers.
//   - hello carries `seqs` (last event seq per host) so a reconnecting FE
//     knows what it missed and can gap-pull via GET /api/events.
//   - ?host=<id> scopes the stream to that one host: only its events (plus
//     hub-level frames like hosts_changed) fan out to this connection, and
//     the FE can retarget mid-session with a {"type":"subscribe"} frame.
//     Absent/empty keeps the pre-filter behaviour of every host's stream.
//   - events frames are flate-compressed binary when the client asks (?c=1).
//   - auth: prefer short-lived ?ticket= (from POST /api/ws-ticket); still
//     accepts Bearer / X-Access-Token / ?token= for the long-lived FE_TOKEN.
func handleFeWS(h *hub.Hub, auth feAuth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ident, ok := auth.identify(r)
		if !ok {
			writeJSON(w, 401, map[string]any{"ok": false, "error": "需要有效的访问 token"})
			return
		}
		compress := r.URL.Query().Get("c") == "1"
		hostID := strings.TrimSpace(r.URL.Query().Get("host"))
		if ident.isGuest() {
			// Pin the initial filter to a whitelisted host (the first one
			// when the FE names none) — the guest's ?host= is never trusted
			// verbatim.
			if hostID == "" || !ident.allowsHost(hostID) {
				hostID = ident.defaultHost()
			}
			if hostID == "" {
				writeJSON(w, 403, map[string]any{"ok": false, "error": "访客令牌没有可用会话"})
				return
			}
		}

		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			// Dev UIs may be on another origin; FE_TOKEN is the real gate.
			InsecureSkipVerify: true,
		})
		if err != nil {
			log.Printf("[capri-hub] fe ws accept: %v", err)
			return
		}
		conn.SetReadLimit(1 << 20)
		defer conn.Close(websocket.StatusNormalClosure, "")

		// Resource guard: reject (1013 Try Again Later) once the
		// subscriber cap is reached instead of degrading under load.
		//
		// The identity snapshot (address / browser / which credential) is
		// what the admin subscriber panel shows; it takes no part in
		// filtering.
		var ch chan hub.Event
		var unsub func()
		var subKicked <-chan struct{}
		info := subscriberInfoFor(ident, requestIP(r), r.UserAgent())
		if ident.isGuest() {
			ch, unsub, subKicked, ok = h.TrySubscribeGuestInfo(maxFESubscribers, hostID, ident.asGuestToken(), info)
		} else {
			ch, unsub, ok = h.TrySubscribeHostInfo(maxFESubscribers, hostID, info)
		}
		if !ok {
			_ = conn.Close(websocket.StatusTryAgainLater, "too many subscribers")
			return
		}
		defer unsub()

		// The admin page shows its own row in the subscriber panel; the id
		// lets it mark "this page" without guessing by address.
		subID, _ := h.SubscriberIDFor(ch)
		// The session the page opened with (?session=) — a guest names it at
		// connect time and only re-sends a subscribe frame when it switches.
		// Without this the panel shows a guest row with no transcript.
		if s := strings.TrimSpace(r.URL.Query().Get("session")); s != "" {
			h.SetSubscriberSession(ch, s)
		}

		var writeMu sync.Mutex
		writeFrame := func(b []byte, binary bool) error {
			writeMu.Lock()
			defer writeMu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			kind := websocket.MessageText
			if binary {
				kind = websocket.MessageBinary
			}
			return conn.Write(ctx, kind, b)
		}
		writeJSONFrame := func(v any) error {
			b, err := json.Marshal(v)
			if err != nil {
				return err
			}
			return writeFrame(b, false)
		}
		writeEventsFrame := func(evs []hub.Event) error {
			// Raw splice: pre-encoded events (host wire path) are
			// concatenated verbatim — no re-marshal of event bodies.
			// Semantically identical to the previous whole-frame marshal.
			raws := make([]json.RawMessage, len(evs))
			for i, ev := range evs {
				b, err := hub.MarshalEvent(ev)
				if err != nil {
					return err
				}
				raws[i] = b
			}
			b, err := json.Marshal(map[string]any{"v": 1, "type": "events", "events": raws})
			if err != nil {
				return err
			}
			// Tiny frames compress poorly (flate header + sync marker);
			// send them raw and let the browser skip decompression.
			if !compress || len(b) < minCompressSize {
				return writeFrame(b, false)
			}
			// flate (deflate-raw) — browsers decompress via
			// DecompressionStream. Writer/buffer come from sync.Pool
			// (see flateWriterPool / flateBufPool above).
			fw := flateWriterPool.Get().(*flate.Writer)
			buf := flateBufPool.Get().(*bytes.Buffer)
			buf.Reset()
			fw.Reset(buf)
			_, werr := fw.Write(b)
			cerr := fw.Close()
			flateWriterPool.Put(fw)
			if werr != nil {
				flateBufPool.Put(buf)
				return werr
			}
			if cerr != nil {
				flateBufPool.Put(buf)
				return cerr
			}
			// writeFrame consumes the slice synchronously; only after it
			// returns is the buffer safe to hand back to the pool.
			err = writeFrame(buf.Bytes(), true)
			buf.Reset()
			flateBufPool.Put(buf)
			return err
		}

		hello := map[string]any{
			"v":             1,
			"type":          "hello",
			"service":       "hub",
			"hosts":         helloHosts(h, ident),
			"defaultHostId": helloDefaultHost(h, ident),
			"seqs":          helloSeqs(h, ident),
			"role":          ident.Role,
			// This socket's row id in the admin subscriber panel (0 when
			// the registration was already gone). Guests get it too; it
			// is their own id, not anyone else's.
			"subscriberId": subID,
		}
		// Live browser /ws/fe clients, this connection included — the admin
		// top bar shows it beside the host block. Changes arrive as
		// hub-level `subscribers_changed` frames, which guests never receive
		// (hub-level fan-out is admin-only), so their hello stays without it.
		if !ident.isGuest() {
			hello["feSubscribers"] = h.SubscriberCount()
		}
		if err := writeJSONFrame(hello); err != nil {
			return
		}

		// Writer: batch events to cut frame overhead under chunk storms.
		// Instead of a free-running 25ms ticker (which wakes up to flush
		// nothing when idle), the flush timer is armed only when an
		// event arrives and stopped once the batch is flushed.
		batch := make([]hub.Event, 0, 16)
		const flushInterval = 25 * time.Millisecond
		var (
			flushTimer *time.Timer
			flushCh    <-chan time.Time // nil ⇒ the select case stays disabled
		)
		flush := func() error {
			if len(batch) == 0 {
				return nil
			}
			evs := batch
			batch = make([]hub.Event, 0, 16)
			if flushTimer != nil {
				flushTimer.Stop()
				select {
				case <-flushTimer.C:
				default:
				}
				flushTimer = nil
				flushCh = nil
			}
			return writeEventsFrame(evs)
		}
		defer func() {
			if flushTimer != nil {
				flushTimer.Stop()
			}
		}()

		ping := time.NewTicker(10 * time.Second)
		defer ping.Stop()
		// Snapshot once per connection: tests retune the package vars
		// between connections without racing in-flight handlers.
		livenessInterval, livenessTimeout := feLivenessInterval, feLivenessTimeout
		liveness := time.NewTicker(livenessInterval)
		defer liveness.Stop()

		ctx := r.Context()
		// readDone closes when the browser socket goes away. Without it a
		// closed tab stays in the subscriber set (and in the count the other
		// pages display) until the next write fails or the liveness ping
		// times out — up to 20s of a stale number.
		readDone := make(chan struct{})
		// Read FE frames in background so the read side does not stall.
		// This reader is also what processes the peer's WS pong for the
		// protocol-level Ping below — without an in-flight Read the pong
		// would never be dispatched. Besides the app-level pings it carries
		// one control frame: {"v":1,"type":"subscribe","host":ID}, which
		// retargets this connection's event filter when the page switches
		// hosts without reconnecting. The ack echoes the host's current seq
		// watermark so the FE can align instead of gap-pulling from 0 (the
		// whole per-host ring buffer).
		go func() {
			defer close(readDone)
			for {
				_, data, err := conn.Read(ctx)
				if err != nil {
					return
				}
				var ctl struct {
					Type    string `json:"type"`
					Host    string `json:"host"`
					Session string `json:"session"`
				}
				if json.Unmarshal(data, &ctl) != nil {
					continue
				}
				if ctl.Type == "viewing" {
					// 管理员页面单独声明「正在看哪个会话」：这是唯一会
					// 打开 host 上行过滤的帧（见 PROTOCOL.md §6.4）。不改
					// 事件过滤，故不回执。
					// 访客的会话走下面的 subscribe 帧，要过白名单校验。
					if ident.isGuest() {
						continue
					}
					h.SetSubscriberViewing(ch, strings.TrimSpace(ctl.Session))
					continue
				}
				if ctl.Type != "subscribe" {
					continue // pings and anything unrecognized stay a no-op
				}
				target := strings.TrimSpace(ctl.Host)
				session := strings.TrimSpace(ctl.Session)
				if ident.isGuest() {
					// A guest may only retarget within its whitelist. An
					// out-of-scope frame is ignored and the previous
					// subscription stays as it was — no ack, no state
					// change (the FE never learns about other hosts).
					if !ident.allowsHost(target) {
						continue
					}
					if session != "" && !hub.GuestAllowsSession(ident.asGuestToken(), target, session) {
						continue
					}
				}
				if !h.SetSubscriberHost(ch, target) {
					continue
				}
				// Both roles record the session they display: for a guest
				// it is whitelist bookkeeping (an out-of-scope name was
				// already rejected above), for an admin it is what the
				// subscriber panel lists under "viewing". An empty session
				// clears the row — a host switch starts before the page
				// names its next session, and a stale name would point at
				// a transcript on the host it just left.
				// This is roster state, not a viewing declaration: only the
				// explicit `viewing` frame may narrow the host's uplink.
				h.SetSubscriberSession(ch, session)
				// writeJSONFrame takes the same write mutex the event
				// batcher uses, so an ack cannot interleave a frame.
				ack := map[string]any{
					"v": 1, "type": "subscribed",
					"host": target, "seq": h.LastSeq(target),
				}
				if ident.isGuest() && session != "" {
					ack["session"] = session
				}
				_ = writeJSONFrame(ack)
			}
		}()

		for {
			select {
			case <-ctx.Done():
				_ = flush()
				return
			case <-readDone:
				// Browser closed the socket: drop the registration right
				// away (the deferred unsub is idempotent) so the other
				// pages' subscriber count corrects itself immediately.
				_ = flush()
				return
			case <-subKicked:
				// Guest token revoked / deleted: close the socket now.
				_ = flush()
				_ = conn.Close(websocket.StatusPolicyViolation, "guest token revoked")
				return
			case <-ping.C:
				if err := flush(); err != nil {
					return
				}
				if err := writeJSONFrame(map[string]any{"v": 1, "type": "ping", "ts": time.Now().Unix()}); err != nil {
					return
				}
			case <-liveness.C:
				// Protocol-level liveness (T7): a half-open FE connection
				// used to linger until a data write hit the 15s timeout —
				// and forever on an idle session. Ping waits for the peer's
				// pong (processed by the drain goroutine above); failure
				// frees the 512-event subscriber channel immediately.
				// Concurrent with writeFrame: the library serializes
				// control frames via its internal write mutex.
				pctx, pcancel := context.WithTimeout(ctx, livenessTimeout)
				err := conn.Ping(pctx)
				pcancel()
				if err != nil {
					return
				}
			case <-flushCh:
				if err := flush(); err != nil {
					return
				}
			case ev, ok := <-ch:
				if !ok {
					_ = flush()
					return
				}
				batch = append(batch, ev)
				if len(batch) >= 16 {
					if err := flush(); err != nil {
						return
					}
				} else if flushTimer == nil {
					// Arm the flush: if no further events arrive within
					// flushInterval, send what we have.
					flushTimer = time.NewTimer(flushInterval)
					flushCh = flushTimer.C
				}
			}
		}
	}
}

// guestRelayPaths is the read-only surface a guest token may relay. Every
// entry is a session-history / session-metadata read; anything else under
// /api/* is 403 for guests. Rewriting (sessionId/cwd forced into the
// whitelist) happens for the session-scoped subset below.
var guestRelayPaths = map[string]bool{
	"/api/session-updates":       true,
	"/api/session-running-tasks": true,
	"/api/session-stats":         true,
	"/api/session-plan":          true,
	"/api/session-info":          true,
	"/api/session/info":          true,
	"/api/session/usage":         true,
	"/api/git-info":              true,
	"/api/subagent/get":          true,
	"/api/subagent/list-running": true,
	"/api/task-list":             true,
	"/api/task-output":           true,
	"/api/status":                true,
}

// guestSessionPaths take a top-level sessionId, and most also a cwd. The
// guest relay force-rewrites both to a whitelisted (session, cwd) pair so a
// hand-crafted request cannot read another session.
var guestCwdPaths = map[string]bool{
	"/api/session-updates":       true,
	"/api/session-running-tasks": true,
	"/api/session-stats":         true,
	"/api/session-plan":          true,
	"/api/session-info":          true,
	"/api/git-info":              true,
	"/api/task-output":           true,
}

// guestSessionPaths are those whose body carries sessionId at the top level.
var guestSessionPaths = map[string]bool{
	"/api/session-updates":       true,
	"/api/session-running-tasks": true,
	"/api/session-stats":         true,
	"/api/session-plan":          true,
	"/api/session-info":          true,
	"/api/session/info":          true,
	"/api/session/usage":         true,
	"/api/git-info":              true,
	"/api/subagent/list-running": true,
	"/api/task-list":             true,
	"/api/task-output":           true,
}

// guestStatusAllowlist is what a guest sees of /api/status: the fields the
// read-only shell needs. roster / pendingRequests / authMeta are removed —
// roster enumerates every session on the host and pendingRequests carries
// other sessions' permission cards. The guest's own session state arrives
// separately as `sessionState` / `pendingInput` (see deriveGuestPending).
var guestStatusAllowlist = []string{
	"ready", "busy", "booting", "sessionId", "cwd", "hostId", "hostName",
	"homeDir", "models", "modes", "configOptions", "agentStartedAt",
	"permissionMode", "error", "bootError", "sessionMeta",
}

// guestPendingKinds maps a pending client-request method to the coarse kind a
// guest is allowed to see. A guest never learns the request's method, params,
// or id — only that the session it is watching is blocked on something.
var guestPendingKinds = map[string]string{
	"session/request_permission": "permission",
	"x.ai/ask_user_question":     "question",
	"x.ai/exit_plan_mode":        "plan",
	"x.ai/folder_trust/request":  "folder_trust",
	"x.ai/diff_review":           "diff_review",
	"x.ai/mcp/elicit":            "mcp_elicit",
}

// deriveGuestPending summarizes one session's pending client requests for the
// guest shell. kind is "" when nothing is pending; count / receivedAt cover
// all pending requests of that session, while kind names the oldest one (the
// one actually blocking the turn). Unrecognized methods still count — the
// guest should know the session is stuck, just not what on.
func deriveGuestPending(reqs []any, sessionID string) (kind string, count int, receivedAt int64) {
	oldest := int64(0)
	for _, raw := range reqs {
		req, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if sid, _ := req["sessionId"].(string); sid != sessionID {
			continue
		}
		count++
		switch at := req["receivedAt"].(type) {
		case float64:
			if oldest == 0 || int64(at) < oldest {
				oldest = int64(at)
				kind = guestPendingKind(req)
			}
		default:
			if kind == "" {
				kind = guestPendingKind(req)
			}
		}
	}
	if kind == "" && count > 0 {
		kind = "other"
	}
	return kind, count, oldest
}

func guestPendingKind(req map[string]any) string {
	method, _ := req["method"].(string)
	if k, ok := guestPendingKinds[method]; ok {
		return k
	}
	return "other"
}

// enforceGuestRelay checks the guest whitelist and rewrites the request body
// so the target session is always one the token was granted. Returns the
// (possibly new) body and whether the request may proceed.
//
// 子代理子会话：白名单通常只有父会话，而子代理的时间线读的是子会话的
// updates.jsonl。hub 在 subagent_spawned 时记下父子关系（NoteGuestChild），
// 这里对「父在白名单里」的子会话参数原样放行（子代理可能用自己 cwd），
// 其余参数照旧夹到白名单。
func enforceGuestRelay(h *hub.Hub, ident identity, hostID, path string, body []byte) ([]byte, bool) {
	if !guestRelayPaths[path] {
		return nil, false
	}
	if !ident.allowsHost(hostID) {
		return nil, false
	}
	if !guestSessionPaths[path] {
		return body, true
	}
	var obj map[string]any
	if len(bytes.TrimSpace(body)) > 0 {
		if json.Unmarshal(body, &obj) != nil || obj == nil {
			obj = map[string]any{}
		}
	} else {
		obj = map[string]any{}
	}
	requested, _ := obj["sessionId"].(string)
	// 子代理子会话：保留子会话 id，但 cwd 仍夹到白名单（父会话那条），
	// 别让访客自带的 cwd 参与 host 的路径拼接。host 找不到 (id, cwd) 时会
	// 按 id 回落到扫描，子代理真实的 cwd 由它自己解析。
	if requested != "" && h != nil && h.GuestChildAllowed(ident.asGuestToken(), hostID, requested) {
		if parent, parentCwd := ident.sessionFor(hostID, h.GuestParentOf(hostID, requested)); parent != "" {
			_, bodyHasCwd := obj["cwd"]
			if bodyHasCwd || guestCwdPaths[path] {
				if parentCwd != "" {
					obj["cwd"] = parentCwd
				} else {
					delete(obj, "cwd")
				}
			}
			out, err := json.Marshal(obj)
			if err != nil {
				return nil, false
			}
			return out, true
		}
	}
	sid, cwd := ident.sessionFor(hostID, requested)
	if sid == "" {
		return nil, false
	}
	obj["sessionId"] = sid
	_, bodyHasCwd := obj["cwd"]
	if bodyHasCwd || guestCwdPaths[path] {
		if cwd != "" {
			obj["cwd"] = cwd
		} else {
			delete(obj, "cwd")
		}
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, false
	}
	return out, true
}

// redactGuestStatus trims a /api/status body to the guest allowlist and
// pins the reported session to one the token may see (the host's active
// session may be someone else's, or another whitelisted session). `wanted`
// is the session the guest is displaying (?session= on the request); it
// wins when it is whitelisted for this host.
func redactGuestStatus(ident identity, hostID, wanted string, body []byte) []byte {
	var raw map[string]any
	if json.Unmarshal(body, &raw) != nil {
		return []byte(`{"ok":false,"error":"status unreadable"}`)
	}
	out := make(map[string]any, len(guestStatusAllowlist))
	for _, k := range guestStatusAllowlist {
		if v, ok := raw[k]; ok {
			out[k] = v
		}
	}
	g := ident.asGuestToken()
	sid, _ := out["sessionId"].(string)
	switch {
	case wanted != "" && hub.GuestAllowsSession(g, hostID, wanted):
		// The guest is looking at this whitelisted session: report it, with
		// the cwd the whitelist recorded for it.
		out["sessionId"] = wanted
		if _, cwd := ident.sessionFor(hostID, wanted); cwd != "" {
			out["cwd"] = cwd
		}
	case hub.GuestAllowsSession(g, hostID, sid):
		// The host's own active session is whitelisted — keep the live cwd.
	default:
		whitelisted, cwd := ident.sessionFor(hostID, "")
		if whitelisted == "" {
			delete(out, "sessionId")
			delete(out, "cwd")
		} else {
			out["sessionId"] = whitelisted
			if cwd != "" {
				out["cwd"] = cwd
			} else {
				delete(out, "cwd")
			}
		}
	}
	// The guest's own session state: the flat `busy` above is the host-wide
	// OR, which says nothing about the session this guest is watching. Report
	// that one session's busy/awaiting plus a countdown for whatever it is
	// blocked on — no request ids, methods, or params cross the wire.
	pending, _ := raw["pendingRequests"].([]any)
	if sid, _ := out["sessionId"].(string); sid != "" {
		// The roster describes every live session. A session it does not name
		// is idle, whatever the host-wide busy flag says (that flag describes
		// the ACTIVE session, which may be someone else's).
		busy := false
		awaiting := false
		roster, _ := raw["roster"].([]any)
		for _, row := range roster {
			rr, ok := row.(map[string]any)
			if !ok {
				continue
			}
			if id, _ := rr["sessionId"].(string); id != sid {
				continue
			}
			busy = boolOf(rr["busy"])
			awaiting = boolOf(rr["awaitingInput"])
			break
		}
		kind, count, receivedAt := deriveGuestPending(pending, sid)
		blocked := awaiting || kind != ""
		state := "idle"
		switch {
		case blocked:
			// A pending request is proof the session is stuck on it — report
			// awaiting even if the host's busy flag has not caught up yet.
			state = "awaiting"
		case busy:
			state = "active"
		}
		out["busy"] = busy
		out["sessionState"] = state
		out["awaitingInput"] = blocked
		if kind != "" {
			out["pendingInput"] = map[string]any{
				"kind":  kind,
				"count": count,
			}
			if receivedAt > 0 {
				out["pendingInput"].(map[string]any)["receivedAt"] = receivedAt
			}
		}
	}

	b, err := json.Marshal(out)
	if err != nil {
		return []byte(`{"ok":false,"error":"status unreadable"}`)
	}
	return b
}

// boolOf reads a JSON boolean without caring whether it decoded as bool or
// was absent (false for anything else).
func boolOf(v any) bool {
	b, _ := v.(bool)
	return b
}

// handleRelay forwards a browser request to the host selected by the
// ?host= query param (default: hub's default host) and streams the
// host's answer back. For guests the target host and session are forced
// onto the token's whitelist before anything reaches a host.
func handleRelay(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ident, _ := identityOf(r)
		hostID := r.URL.Query().Get("host")
		if ident.isGuest() {
			if hostID == "" {
				hostID = ident.defaultHost()
			}
			if hostID == "" || !ident.allowsHost(hostID) {
				writeJSON(w, 403, map[string]any{"ok": false, "error": "访客无权访问该 Host"})
				return
			}
		}
		if hostID == "" {
			hostID = h.DefaultHostID()
			if hostID == "" {
				writeJSON(w, 503, map[string]any{"ok": false, "error": hub.ErrNoHost.Error()})
				return
			}
		}
		const maxRelayBody = 5 << 20
		var body json.RawMessage
		if r.Body != nil {
			// Read one byte past the cap so an over-limit body is
			// rejected (413) instead of silently truncated into broken
			// JSON that the host then fails to parse.
			b, err := io.ReadAll(io.LimitReader(r.Body, maxRelayBody+1))
			if err != nil {
				writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
				return
			}
			if len(b) > maxRelayBody {
				writeJSON(w, 413, map[string]any{"ok": false, "error": "请求体过大（上限 5MB）"})
				return
			}
			body = b
		}
		if ident.isGuest() {
			next, ok := enforceGuestRelay(h, ident, hostID, r.URL.Path, body)
			if !ok {
				writeJSON(w, 403, map[string]any{"ok": false, "error": "访客无权访问该接口"})
				return
			}
			body = next
		}
		resp, err := h.Dispatch(r.Context(), hostID, r.Method, r.URL.Path, body)
		if err != nil {
			var re *hub.RelayError
			if errors.As(err, &re) {
				writeJSON(w, re.Status, map[string]any{"ok": false, "error": re.Message})
			} else {
				writeJSON(w, 500, map[string]any{"ok": false, "error": err.Error()})
			}
			return
		}
		// Guard against malformed host responses (e.g. missing/zero
		// status): net/http panics on WriteHeader(0), killing the request.
		status := resp.Status
		if status < 100 || status > 599 {
			status = 502
		}
		respBody := resp.Body
		if ident.isGuest() && status >= 200 && status < 300 {
			switch r.URL.Path {
			case "/api/status":
				respBody = redactGuestStatus(ident, hostID, r.URL.Query().Get("session"), respBody)
			case "/api/session-updates":
				// 访客读历史时才补父子关系：早于本次页面打开（或早于 hub
				// 重启）派出的子代理，subagent_spawned 事件没经过本进程，
				// 这里从父会话的 updates.jsonl 里补回来。回退用的父会话取
				// 改写后的请求体（那是 host 实际读的那条会话）。
				h.NoteHistoryChildren(hostID, relayedSessionID(body), respBody)
			case "/api/subagent/list-running":
				// 注册表同样带父子关系，且不受历史分页影响。
				h.NoteRunningSubagents(hostID, relayedSessionID(body), respBody)
			}
		}
		writeRelayResponse(w, r, status, respBody)
	}
}

// writeRelayResponse writes the host's answer to the browser, gzipping it
// when the client asked for it. The relay used to hand back the host's JSON
// verbatim: a multi-megabyte session-history page then crossed the last hop
// uncompressed (measured: 2.18 MB of JSON ≈ 5–15 s on a few-Mbps link, vs
// 1.6 s for the 66 KB gzipped equivalent). The host↔hub uplink already has
// its own flate layer, so nothing on this path compressed before now.
func writeRelayResponse(w http.ResponseWriter, r *http.Request, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Add, not Set: with CORS_ORIGINS configured, withCORS has already put
	// `Vary: Origin` on this very header map and overwriting it would let a
	// shared cache reuse an ACAO-bearing response for the wrong origin.
	w.Header().Add("Vary", "Accept-Encoding")
	// Same floor as the /ws/fe stream's minCompressSize: below it the gzip
	// header is not worth a round trip through the compressor.
	if len(body) >= minCompressSize && acceptsGzip(r) {
		var buf bytes.Buffer
		if err := gzipInto(&buf, body); err == nil && buf.Len() < len(body) {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
			w.WriteHeader(status)
			_, _ = w.Write(buf.Bytes())
			return
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// acceptsGzip is true only when the client names gzip explicitly. A bare
// `*` is not enough: non-browser callers (curl, server-side fetchers) send
// it while being perfectly happy with identity, and compressing for them
// would only burn hub CPU.
func acceptsGzip(r *http.Request) bool {
	for _, tok := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(tok), ";")
		if !strings.EqualFold(name, "gzip") {
			continue
		}
		for _, kv := range strings.Split(params, ";") {
			k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
			if !ok || !strings.EqualFold(k, "q") {
				continue
			}
			if q, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && q <= 0 {
				return false // "gzip;q=0" — explicitly refused
			}
		}
		return true
	}
	return false
}

// gzipBufPool reuses the deflate compressor state across responses; building
// it per call is a fixed multi-hundred-KB cost on a path that can carry
// tens of megabytes.
var gzipBufPool = sync.Pool{
	New: func() any {
		zw, err := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
		if err != nil {
			// Only a bad level reaches here, and the level is a constant.
			panic("capri-hub: invalid gzip level: " + err.Error())
		}
		return zw
	},
}

func gzipInto(dst *bytes.Buffer, b []byte) error {
	zw := gzipBufPool.Get().(*gzip.Writer)
	defer gzipBufPool.Put(zw)
	zw.Reset(dst)
	if _, err := zw.Write(b); err != nil {
		return err
	}
	return zw.Close()
}

// ── QUIC host transport ──────────────────────────────────────────────

// quicTLSConfig returns a TLS config for the QUIC listener: from
// QUIC_CERT/QUIC_KEY files when set, else a generated self-signed cert
// when allowSelfSigned is true. Production (FE_TOKEN set) should pass
// false so a missing cert fails closed and Hosts fall back to WS.
// Hosts typically use InsecureSkipVerify for self-signed (documented;
// FE never touches QUIC).
func quicTLSConfig(allowSelfSigned bool) (*tls.Config, error) {
	certFile := os.Getenv("QUIC_CERT")
	keyFile := os.Getenv("QUIC_KEY")
	// Shared ALPN so host clients can dial with the same protocol id.
	const alpn = "capri-hub"
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{alpn}}, nil
	}
	if !allowSelfSigned {
		return nil, fmt.Errorf("QUIC_CERT/QUIC_KEY required when FE_TOKEN is set (set QUIC_ALLOW_SELF_SIGNED=1 only for lab use)")
	}
	// Self-sign in memory (dev / explicit allow).
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "capri-hub"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{alpn}}, nil
}

// listenQUIC opens the UDP QUIC listener for host transport.
func listenQUIC(port int, tlsConf *tls.Config) (*quic.Listener, error) {
	addr := fmt.Sprintf(":%d", port)
	return quic.ListenAddr(addr, tlsConf, &quic.Config{KeepAlivePeriod: 10 * time.Second})
}

// serveQUIC accepts host connections over an already-open QUIC listener.
// One bidirectional stream per connection carries the same JSON frame
// protocol as /ws/host; auth is the first frame {type:"auth", token}.
// Closing the listener ends the accept loop (graceful shutdown).
func serveQUIC(ln *quic.Listener, h *hub.Hub) {
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			// Listener closed on shutdown, or unrecoverable accept error.
			if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "closed") {
				return
			}
			log.Printf("[capri-hub] QUIC accept: %v", err)
			continue
		}
		go serveQUICConn(conn, h)
	}
}

// quicTransport adapts one host QUIC connection. The control stream carries
// the session in both directions; request streams carry the host's `respond`
// frames only, and the hub never writes on them.
type quicTransport struct {
	conn      *quic.Conn
	control   *quic.Stream
	frames    chan []byte
	errs      chan error
	stop      chan struct{}
	closeOnce sync.Once
}

func newQUICTransport(conn *quic.Conn, control *quic.Stream) *quicTransport {
	t := &quicTransport{
		conn:    conn,
		control: control,
		frames:  make(chan []byte, 64),
		errs:    make(chan error, 1),
		stop:    make(chan struct{}),
	}
	go t.readControl()
	go t.acceptRequests()
	return t
}

func (t *quicTransport) fail(err error) {
	select {
	case t.errs <- err:
	default:
	}
}

func (t *quicTransport) Send(payload []byte) error {
	if err := t.control.SetWriteDeadline(time.Now().Add(hostWriteTimeout)); err != nil {
		return err
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := t.control.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := t.control.Write(payload)
	return err
}

func (t *quicTransport) Recv() ([]byte, error) {
	select {
	case b := <-t.frames:
		return b, nil
	case err := <-t.errs:
		return nil, err
	case <-t.stop:
		return nil, io.EOF
	}
}

// SetKeepalive is a no-op: QUIC's keepalive is a per-connection transport
// option set when the listener dials (see listenQUIC), not a per-stream one.
func (t *quicTransport) SetKeepalive(time.Duration) {}

func (t *quicTransport) Close(r wire.CloseReason) error {
	t.closeOnce.Do(func() { close(t.stop) })
	_ = t.control.Close()
	return t.conn.CloseWithError(quic.ApplicationErrorCode(r.QUICCode()), r.String())
}

func (t *quicTransport) readControl() {
	for {
		b, err := readQUICFrame(t.control, 0)
		if err != nil {
			t.fail(err)
			return
		}
		select {
		case t.frames <- b:
		case <-t.stop:
			return
		}
	}
}

// acceptRequests drains request streams. Each stream is silent by design
// between dispatch and the host's answer, so its read deadline tracks the
// relay budget; a stream ending is normal and must not end the session.
func (t *quicTransport) acceptRequests() {
	for {
		stream, err := t.conn.AcceptStream(context.Background())
		if err != nil {
			t.fail(err)
			return
		}
		go func(stream *quic.Stream) {
			defer stream.Close()
			for {
				b, err := readQUICFrame(stream, hub.RelayTimeout)
				if err != nil {
					return // EOF / timeout / reset: end of this stream only
				}
				select {
				case t.frames <- b:
				case <-t.stop:
					return
				}
			}
		}(stream)
	}
}

// serveQUICConn serves one host QUIC connection: accept the control stream,
// hand it to the session, and let the transport adapters do the rest.
func serveQUICConn(conn *quic.Conn, h *hub.Hub) {
	// A panic in a bare goroutine (no net/http recover) would kill the whole
	// hub; contain it and drop just this connection.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[capri-hub] quic conn panic recovered: %v", r)
			_ = conn.CloseWithError(quic.ApplicationErrorCode(wire.CloseNormal.QUICCode()), fmt.Sprint(r))
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	stream, err := conn.AcceptStream(ctx)
	cancel()
	if err != nil {
		_ = conn.CloseWithError(0, "no control stream")
		return
	}
	reason := h.ServeHost("", newQUICTransport(conn, stream))
	log.Printf("[capri-hub] host quic session ended (%s) %s", reason, conn.RemoteAddr())
}

// readQUICFrame reads one length-prefixed frame (bit 31 = raw deflate).
// readTimeout > 0 arms a per-read deadline for request streams.
func readQUICFrame(stream *quic.Stream, readTimeout time.Duration) ([]byte, error) {
	if readTimeout > 0 {
		if err := stream.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			return nil, err
		}
	}
	var lenBuf [4]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return nil, err
	}
	n, compressed := parseUplinkLen(binary.BigEndian.Uint32(lenBuf[:]))
	if n > hostFrameLimit {
		return nil, fmt.Errorf("%w: frame too large: %d", wire.ErrUnreadable, n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(stream, buf); err != nil {
		return nil, err
	}
	if !compressed {
		return buf, nil
	}
	out, err := inflateUplink(buf)
	if err != nil {
		return nil, fmt.Errorf("%w: inflate: %v", wire.ErrUnreadable, err)
	}
	return out, nil
}

// ── helpers ───────────────────────────────────────────────────────────

// identity is who a browser-facing request speaks for. Admin = the
// deployment's FE_TOKEN. Guest = one record from guests.json, restricted
// to that record's session whitelist.
type identity struct {
	Role      string // "admin" | "guest"
	TokenID   string // guests.json id (guest only)
	Label     string
	ExpiresAt int64
	Sessions  []hub.GuestSession
}

func (id identity) isGuest() bool { return id.Role == "guest" }

// allowsHost reports whether this identity may address hostID. Admins may
// address every paired host; guests only hosts named by their whitelist.
func (id identity) allowsHost(hostID string) bool {
	if !id.isGuest() {
		return true
	}
	for _, s := range id.Sessions {
		if s.HostID == hostID {
			return true
		}
	}
	return false
}

// defaultHost is the host a guest falls back to when the request names
// none: the first whitelisted session's host. Empty for admins (the hub's
// registry default applies).
func (id identity) defaultHost() string {
	for _, s := range id.Sessions {
		if s.HostID != "" {
			return s.HostID
		}
	}
	return ""
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
}

// identify resolves the identity behind r, in this order:
//  1. admin Bearer / X-Access-Token (FE_TOKEN),
//  2. a guest token in Bearer / X-Access-Token,
//  3. a single-use ?ticket= (guest or admin identity).
//
// A guest lookup also rejects revoked / expired records.
func (a feAuth) identify(r *http.Request) (identity, bool) {
	if a.token != "" {
		for _, tok := range []string{
			bearerToken(r.Header.Get("Authorization")),
			strings.TrimSpace(r.Header.Get("X-Access-Token")),
		} {
			if tokenEqual(tok, a.token) {
				return identity{Role: "admin"}, true
			}
		}
	} else if strings.TrimSpace(r.Header.Get("Authorization")) == "" &&
		strings.TrimSpace(r.Header.Get("X-Access-Token")) == "" {
		// Open dev hub with no FE_TOKEN: anonymous = admin, as before.
		if r.URL.Query().Get("ticket") == "" {
			return identity{Role: "admin"}, true
		}
	}

	// Guest bearer / header token.
	if a.hub != nil {
		for _, tok := range []string{
			bearerToken(r.Header.Get("Authorization")),
			strings.TrimSpace(r.Header.Get("X-Access-Token")),
		} {
			if g, ok := a.hub.LookupGuestToken(tok); ok {
				return guestIdentity(g), true
			}
		}
	}

	// Short-lived ticket (preferred for WebSocket).
	if a.tickets != nil {
		if t := strings.TrimSpace(r.URL.Query().Get("ticket")); t != "" {
			guestID, ok := a.tickets.consume(t)
			if !ok {
				return identity{}, false
			}
			if guestID == "" {
				return identity{Role: "admin"}, true
			}
			if a.hub == nil {
				return identity{}, false
			}
			g, found := a.hub.GuestByID(guestID)
			if !found || !g.Active(time.Now()) {
				return identity{}, false
			}
			return guestIdentity(g), true
		}
	}
	return identity{}, false
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
		id, ok := a.identify(r)
		if !ok {
			writeJSON(w, 401, map[string]any{"ok": false, "error": "需要有效的访问 token"})
			return
		}
		next(w, r.WithContext(withIdentity(r.Context(), id)))
	}
}

// requireAdmin allows only the admin identity; guests get 403 so the FE can
// tell "you are not allowed to manage tokens" from "your token is dead".
func (a feAuth) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := a.identify(r)
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
		id, ok := a.identify(r)
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
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Access-Token")
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
