// capri-hub: 中心化中转服务器（relay）。
//
//		Browser (capri-fe) ──WS /ws/fe + HTTP /api/*──▶ capri-hub ──QUIC/WS /ws/host──▶ capri-host × N ──stdio──▶ grok
//
//	  - 配对：Host 用配对码换取 token（POST /api/pair），token 持久化在 ~/.capri-hub。
//	  - Host 出站连接（GET /ws/host 或 QUIC UDP）：下行 request/subscribers，上行 events/respond。
//	  - 浏览器 WebSocket（GET /ws/fe）：聚合 live 事件；/api/* 按 ?host= 中转给对应 Host。
//	  - 可选 FE_TOKEN：部署时设置后，浏览器侧接口必须带同一 token（Bearer / 头）。
//	    WebSocket 优先用短期 ?ticket=（POST /api/ws-ticket）；仍兼容 ?token=。
//	  - 可靠性：事件带 seq（host 分配），hub 缓冲每 host 最近 4000 条，
//	    GET /api/events?host=X&after=SEQ 供缺口补拉。
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
	"syscall"
	"time"

	"github.com/AgentsHarness/capri-hub/internal/hub"
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
	auth := feAuth{token: feToken, tickets: tickets}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("GET /api/info", handleInfo)
	// Admin pairing endpoints: require FE token when configured.
	mux.HandleFunc("GET /api/pairing", auth.require(handlePairing(h)))
	mux.HandleFunc("POST /api/pairing/rotate", auth.require(handleRotate(h)))
	// Host-facing: authenticate with host pairing token (not FE_TOKEN).
	mux.HandleFunc("POST /api/pair", handlePair(h, lim))
	mux.HandleFunc("GET /ws/host", handleHostWS(h))
	// Browser-facing: FE token gate when FE_TOKEN is set.
	mux.HandleFunc("GET /api/hosts", auth.require(handleHosts(h)))
	mux.HandleFunc("DELETE /api/hosts/{hostId}", auth.require(handleUnpair(h)))
	mux.HandleFunc("POST /api/hosts/{hostId}/rename", auth.require(handleRenameHost(h)))
	mux.HandleFunc("GET /api/events", auth.require(handleEvents(h)))
	mux.HandleFunc("GET /api/prefs", auth.require(handlePrefsGet(h)))
	mux.HandleFunc("PUT /api/prefs", auth.require(handlePrefsPut(h)))
	mux.HandleFunc("POST /api/ws-ticket", auth.require(handleWSTicket(tickets)))
	mux.HandleFunc("GET /ws/fe", handleFeWS(h, auth))
	// Catch-all: relay everything else under /api/* to the selected host.
	mux.HandleFunc("GET /api/{path...}", auth.require(handleRelay(h)))
	mux.HandleFunc("POST /api/{path...}", auth.require(handleRelay(h)))
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
		// Raw fast path: buffered events may carry pre-encoded wire bytes
		// (hub.MarshalEvent returns them verbatim); legacy map events
		// marshal as before. Either way the JSON handed to the FE is
		// semantically identical to the old whole-frame marshal.
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

// feTicketStore issues single-use short-lived tickets for /ws/fe so the
// long-lived FE_TOKEN need not appear in query strings / proxy logs.
type feTicketStore struct {
	mu      sync.Mutex
	tickets map[string]time.Time // ticket → expiry
}

func newFETicketStore() *feTicketStore {
	return &feTicketStore{tickets: make(map[string]time.Time)}
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
					if !exp.After(now) {
						delete(s.tickets, k)
					}
				}
				s.mu.Unlock()
			}
		}
	}()
}

func (s *feTicketStore) issue() (ticket string, expires time.Time) {
	var b [24]byte
	_, _ = rand.Read(b[:])
	ticket = hex.EncodeToString(b[:])
	expires = time.Now().Add(feTicketTTL)
	s.mu.Lock()
	s.tickets[ticket] = expires
	s.mu.Unlock()
	return ticket, expires
}

// consume validates and burns a ticket (single-use).
func (s *feTicketStore) consume(ticket string) bool {
	if ticket == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.tickets[ticket]
	if !ok {
		return false
	}
	delete(s.tickets, ticket)
	return exp.After(time.Now())
}

func handleWSTicket(tickets *feTicketStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ticket, exp := tickets.issue()
		writeJSON(w, 200, map[string]any{
			"ok":        true,
			"ticket":    ticket,
			"expiresAt": exp,
			"ttlSec":    int(feTicketTTL / time.Second),
		})
	}
}

func handleHosts(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"hosts":         h.ListHosts(),
			"defaultHostId": h.DefaultHostID(),
		})
	}
}

// handlePrefsGet: GET /api/prefs — the browser prefs document (pinned
// workspaces / sessions + per-session todo status), persisted by the hub
// in prefs.json. One shared document for all browsers; the FE merges it
// with its localStorage cache on boot. Carries the doc's version — the
// CAS base for conditional PUTs (old FEs ignore it).
func handlePrefsGet(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		doc, version := h.Prefs()
		writeJSON(w, 200, map[string]any{"ok": true, "prefs": doc, "version": version})
	}
}

// handlePrefsPut: PUT /api/prefs {prefs: {...}, baseVersion?: N} — fold a
// browser prefs write into the stored document.
//
// With `entries` (current FE) the hub MERGES per item — see
// internal/hub/prefs.go — so the write needs no condition and the response
// carries the merged authoritative doc for the writer to converge on.
// Without entries (an FE from before entries existed) the write stays a
// whole-document replace, and baseVersion makes it conditional: a stale
// writer gets 409 + the current doc and version so it can rebase and retry.
// The doc is small (pins + todos), no size cap is enforced.
func handlePrefsPut(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Prefs       *hub.BrowserPrefs `json:"prefs"`
			BaseVersion *uint64           `json:"baseVersion"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Prefs == nil {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "需要 prefs 字段"})
			return
		}
		base := uint64(0)
		if body.BaseVersion != nil {
			base = *body.BaseVersion
		}
		version, err := h.SetPrefs(*body.Prefs, base, body.BaseVersion != nil)
		if err != nil {
			if errors.Is(err, hub.ErrPrefsConflict) {
				doc, cur := h.Prefs()
				writeJSON(w, 409, map[string]any{
					"ok":      false,
					"error":   err.Error(),
					"prefs":   doc,
					"version": cur,
				})
				return
			}
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

// Keepalive + half-open detection for host transports (WS and QUIC):
// the hub pings every 25s (the host replies "pong", and also sends
// host_status heartbeats on its own), so a healthy connection always
// produces uplink frames. If nothing arrives for hostReadTimeout — e.g.
// a network blackhole that never sends RST — the connection is dropped
// instead of leaving the host "online" with every relay stuck.
// hostWriteTimeout caps downlink writes so a half-open peer cannot pin
// writeMu / subscriber-notify goroutines forever (WS already used 30s;
// QUIC now matches).
const (
	hostPingInterval = 25 * time.Second
	hostReadTimeout  = 90 * time.Second
	hostWriteTimeout = 30 * time.Second
)

// handleHostWS: host outbound WebSocket. Downlink: hello / subscribers / request.
// Uplink: events / respond / ping.
func handleHostWS(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hostID, ok := authHost(h, r)
		if !ok {
			// Allow ?token= for environments that cannot set upgrade headers.
			if tok := strings.TrimSpace(r.URL.Query().Get("token")); tok != "" {
				hostID, ok = h.HostIDForToken(tok)
			}
		}
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
		// Long-lived relay; prompts can run tens of minutes. 32MB matches
		// the QUIC frame cap: host respond frames carry up to 16MB of
		// relayed body plus envelope, and a tighter limit would kill the
		// connection on large responses (e.g. fs/read-file of a big log).
		conn.SetReadLimit(32 << 20)
		defer conn.Close(websocket.StatusNormalClosure, "")

		var writeMu sync.Mutex
		write := func(payload []byte) error {
			writeMu.Lock()
			defer writeMu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), hostWriteTimeout)
			defer cancel()
			return conn.Write(ctx, websocket.MessageText, payload)
		}

		// Uplink flate negotiation (T2): the host asks for compression with
		// the X-Hub-Deflate: 1 header (or ?deflate=1); the hello echoes
		// "deflate":true to confirm. Only then may the host send
		// compressed (binary) frames. See internal/hub/PROTOCOL.md.
		upDeflate := r.Header.Get("X-Hub-Deflate") == "1" || r.URL.Query().Get("deflate") == "1"

		// hello must reach the host BEFORE ConnectStream registers it:
		// once registered, Dispatch may push a relayed request into the
		// stream, and a host that has not acked hello yet would miss it.
		// hello carries the subscriber count, so the host is never blind
		// to subscriber state either.
		if err := writeHostHello(h, hostID, upDeflate, write); err != nil {
			return
		}
		sc, stop, err := h.ConnectStream(hostID, write)
		if err != nil {
			_ = conn.Close(websocket.StatusPolicyViolation, err.Error())
			return
		}
		defer stop()
		log.Printf("[capri-hub] host %s connected (ws)", hostID)

		ctx := r.Context()
		frames := make(chan hostReadFrame, 16)
		readCtx, cancelRead := context.WithCancel(ctx)
		defer cancelRead()
		go func() {
			for {
				typ, data, err := conn.Read(readCtx)
				if err != nil {
					select {
					case frames <- hostReadFrame{err: err}:
					case <-readCtx.Done():
					}
					return
				}
				// WS wire rule (PROTOCOL.md): a BINARY message is one
				// raw-deflate stream of the JSON frame; TEXT is bare JSON.
				if typ == websocket.MessageBinary {
					if !upDeflate {
						log.Printf("[capri-hub] host %s: binary frame without deflate negotiation, dropping", hostID)
						continue
					}
					inflated, err := inflateUplink(data)
					if err != nil {
						log.Printf("[capri-hub] host %s: uplink inflate: %v", hostID, err)
						continue
					}
					data = inflated
				}
				select {
				case frames <- hostReadFrame{data: data}:
				case <-readCtx.Done():
					return
				}
			}
		}()

		ping := time.NewTicker(hostPingInterval)
		defer ping.Stop()
		idle := time.NewTimer(hostReadTimeout)
		defer idle.Stop()
		for {
			select {
			case f := <-frames:
				if f.err != nil {
					return
				}
				// Superseded connection (host reconnected, or a second
				// host process paired under the same hostId): its uplink
				// must not interleave with the current connection's seq
				// space — drop the stale transport on its next frame.
				if !h.IsCurrentConn(hostID, sc) {
					log.Printf("[capri-hub] host %s: superseded ws connection dropped", hostID)
					return
				}
				if !idle.Stop() {
					select {
					case <-idle.C:
					default:
					}
				}
				idle.Reset(hostReadTimeout)
				handleHostFrame(h, hostID, f.data, write)
			case <-ping.C:
				_ = writeHostPing(h, hostID, write)
			case <-idle.C:
				log.Printf("[capri-hub] host %s: no uplink for %s, dropping", hostID, hostReadTimeout)
				return
			case <-ctx.Done():
				return
			}
		}
	}
}

// hostReadFrame is one uplink frame (or terminal read error) delivered
// from the host WebSocket reader goroutine.
type hostReadFrame struct {
	data []byte
	err  error
}

// writeHostHello sends the hub hello (subscribers + last host seq) down a
// host transport. seq lets a reconnecting host resume events it buffered
// while offline. When the host requested uplink flate compression
// (QUIC auth frame / WS handshake, see internal/hub/PROTOCOL.md), the
// hello echoes "deflate":true — the host may only start compressing
// uplink frames after seeing the echo.
func writeHostHello(h *hub.Hub, hostID string, deflate bool, write func([]byte) error) error {
	hello := map[string]any{
		"v":           1,
		"type":        "hello",
		"service":     "hub",
		"subscribers": h.SubscriberCount(),
		"seq":         h.LastSeq(hostID),
	}
	if deflate {
		hello["deflate"] = true
	}
	b, err := json.Marshal(hello)
	if err != nil {
		return err
	}
	return write(b)
}

// ── host→hub uplink flate compression (T2) ───────────────────────────
//
// Negotiation and wire format are specified byte-precisely in
// internal/hub/PROTOCOL.md. Hub side: frames arrive either as bare JSON
// (WS text message / QUIC length prefix without the flag bit) or as one
// raw-deflate stream of the JSON payload (WS binary message / QUIC
// length prefix with the top bit set). Payloads below
// uplinkMinCompressSize are never compressed by the host, but the hub
// accepts any flagged frame regardless of size.

// uplinkCompressedFlag is bit 31 of the QUIC 4-byte length prefix,
// marking the frame body as a raw-deflate stream.
const uplinkCompressedFlag = 1 << 31

// parseUplinkLen splits a QUIC uplink length prefix into the true frame
// length and the compressed flag (top bit).
func parseUplinkLen(n uint32) (length uint32, compressed bool) {
	return n &^ uplinkCompressedFlag, n&uplinkCompressedFlag != 0
}

// inflateUplink decompresses one raw-deflate uplink payload back into the
// original JSON frame bytes.
func inflateUplink(b []byte) ([]byte, error) {
	return io.ReadAll(flate.NewReader(bytes.NewReader(b)))
}

// writeHostPing sends the hub→host liveness ping. It also RE-ASSERTS the
// browser subscriber count: the count drives whether the host uploads
// bridge events at all, and an edge-triggered `subscribers` frame can be
// lost (write error, superseded connection) — which would leave the host
// paused while a browser sits watching a frozen page. Piggy-backing the
// absolute value on the ping makes the state self-healing within one ping
// interval. `subsGen` lets the host discard an out-of-order delivery.
//
// `seq` piggy-backs the per-host data-plane watermark (same meaning as
// hello.seq): it is a delivery ACK for the host's uplink events, letting
// the host anchor its drop-repair at what actually reached the hub instead
// of what it managed to enqueue. Absent on old hubs — hosts treat a
// missing field as "no new ack".
func writeHostPing(h *hub.Hub, hostID string, write func([]byte) error) error {
	count, gen := h.SubscribersState()
	frame, err := json.Marshal(map[string]any{
		"v": 1, "type": "ping", "ts": time.Now().Unix(),
		"subscribers": count, "subsGen": gen,
		"seq": h.LastSeq(hostID),
	})
	if err != nil {
		return err
	}
	return write(frame)
}

// handleHostFrame processes one uplink frame from a host (events/respond/
// host_status/seq_reset/ping). Shared by the WebSocket and QUIC transports.
func handleHostFrame(h *hub.Hub, hostID string, data []byte, write func([]byte) error) {
	var frame struct {
		Type     string            `json:"type"`
		SeqStart *uint64           `json:"seqStart"`
		Events   []json.RawMessage `json:"events"`
		ReqID    string            `json:"reqId"`
		Status   int               `json:"status"`
		Body     json.RawMessage   `json:"body"`
		Ready    bool              `json:"ready"`
		// Transient registry fields (absent on older hosts → nil leaves
		// the hub's current value untouched).
		Busy         *bool `json:"busy"`
		Booting      *bool `json:"booting"`
		PendingCount *int  `json:"pendingCount"`
		Port         *int  `json:"port"`
	}
	if err := json.Unmarshal(data, &frame); err != nil {
		log.Printf("[capri-hub] host %s bad frame: %v", hostID, err)
		return
	}
	switch frame.Type {
	case "events":
		// Frame-level integrity check: the host stamps seqStart with the
		// first event's seq. A mismatch means the frame was corrupted or
		// assembled wrong (e.g. a bug in the batching/replay packing) —
		// rejecting the whole frame keeps the hub's per-host watermark
		// aligned with the host's own sequence instead of silently
		// accepting truncated/reordered events. Frames without per-event
		// seqs (legacy) are exempt.
		if frame.SeqStart != nil && len(frame.Events) > 0 {
			var first struct {
				Seq uint64 `json:"seq"`
			}
			if json.Unmarshal(frame.Events[0], &first) == nil && first.Seq > 0 && first.Seq != *frame.SeqStart {
				log.Printf("[capri-hub] host %s events frame seqStart mismatch: seqStart=%d first event seq=%d, rejecting %d events",
					hostID, *frame.SeqStart, first.Seq, len(frame.Events))
				return
			}
		}
		// Raw fast path: event bodies stay json.RawMessage — the hub
		// shallow-parses only seq/type/ready and splices its tags into
		// the original bytes for fan-out (no per-event map decode, no
		// re-encode per FE). Seq handling matches the legacy
		// RegisterEvent path exactly (see hub.RegisterRawEvents).
		h.RegisterRawEvents(hostID, frame.Events)
	case "host_status":
		// Control-plane status heartbeat: no seq, not an event. Updates
		// Ready/Busy/Booting/PendingCount + LastSeen (and hosts_changed
		// on any flip) without advancing the per-host counter or the
		// transcript buffer.
		h.UpdateHostStatus(hostID, hub.HostStatusPatch{
			Ready:        &frame.Ready,
			Busy:         frame.Busy,
			Booting:      frame.Booting,
			PendingCount: frame.PendingCount,
			Port:         frame.Port,
		})
	case "seq_reset":
		// Host process restarted: bridge seq recounts from 1. Clear the
		// hub watermark so new low seqs are not treated as stale and
		// dropped by RegisterEvent's s <= last skip.
		h.ResetHostSeq(hostID)
	case "respond":
		if frame.ReqID == "" {
			return
		}
		if !h.Respond(hostID, frame.ReqID, hub.RelayResponse{Status: frame.Status, Body: frame.Body}) {
			log.Printf("[capri-hub] host %s respond unknown reqId %s", hostID, frame.ReqID)
		}
	case "ping":
		pong, _ := json.Marshal(map[string]any{"v": 1, "type": "pong"})
		_ = write(pong)
	case "pong":
		// ignore
	default:
		// ignore unknown
	}
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
//   - events frames are flate-compressed binary when the client asks (?c=1).
//   - auth: prefer short-lived ?ticket= (from POST /api/ws-ticket); still
//     accepts Bearer / X-Access-Token / ?token= for the long-lived FE_TOKEN.
func handleFeWS(h *hub.Hub, auth feAuth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !auth.check(r) {
			writeJSON(w, 401, map[string]any{"ok": false, "error": "需要有效的访问 token"})
			return
		}
		compress := r.URL.Query().Get("c") == "1"

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
		ch, unsub, ok := h.TrySubscribe(maxFESubscribers)
		if !ok {
			_ = conn.Close(websocket.StatusTryAgainLater, "too many subscribers")
			return
		}
		defer unsub()

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

		if err := writeJSONFrame(map[string]any{
			"v":             1,
			"type":          "hello",
			"service":       "hub",
			"hosts":         h.ListHosts(),
			"defaultHostId": h.DefaultHostID(),
			"seqs":          h.SeqByHost(),
		}); err != nil {
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
		// Drain FE pings in background so the read side does not stall.
		// This reader is also what processes the peer's WS pong for the
		// protocol-level Ping below — without an in-flight Read the pong
		// would never be dispatched.
		go func() {
			for {
				_, _, err := conn.Read(ctx)
				if err != nil {
					return
				}
			}
		}()

		for {
			select {
			case <-ctx.Done():
				_ = flush()
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

// handleRelay forwards a browser request to the host selected by the
// ?host= query param (default: hub's default host) and streams the
// host's answer back.
func handleRelay(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hostID := r.URL.Query().Get("host")
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
		writeRelayResponse(w, r, status, resp.Body)
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

func serveQUICConn(conn *quic.Conn, h *hub.Hub) {
	// A panic in a bare goroutine (no net/http recover) would kill the
	// whole hub; contain it and drop just this connection.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[capri-hub] quic conn panic recovered: %v", r)
			_ = conn.CloseWithError(1, "internal error")
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	// The host opens the stream; we accept it.
	stream, err := conn.AcceptStream(ctx)
	cancel()
	if err != nil {
		_ = conn.CloseWithError(0, "no stream")
		return
	}
	defer stream.Close()
	defer conn.CloseWithError(0, "")

	readFrame := quicFrameReader(stream)
	// Match WS hostWriteTimeout: a half-open peer must not block writes
	// (and thus writeMu / notifyHostsSubscribers goroutines) forever.
	write := func(payload []byte) error {
		if err := stream.SetWriteDeadline(time.Now().Add(hostWriteTimeout)); err != nil {
			return err
		}
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
		if _, err := stream.Write(lenBuf[:]); err != nil {
			return err
		}
		_, err := stream.Write(payload)
		return err
	}

	// Auth: first frame must carry a valid host token.
	data, err := readFrame()
	if err != nil {
		return
	}
	var auth struct {
		Type    string `json:"type"`
		Token   string `json:"token"`
		Deflate bool   `json:"deflate"`
	}
	if json.Unmarshal(data, &auth) != nil || auth.Type != "auth" || auth.Token == "" {
		_ = write([]byte(`{"v":1,"type":"auth_error","error":"missing auth"}`))
		return
	}
	hostID, ok := h.HostIDForToken(auth.Token)
	if !ok {
		_ = write([]byte(`{"v":1,"type":"auth_error","error":"token 无效"}`))
		return
	}
	// Uplink flate negotiation (T2): confirmed via the hello echo; until
	// then the host must send bare JSON. See internal/hub/PROTOCOL.md.
	upDeflate := auth.Deflate

	var writeMu sync.Mutex
	wsafe := func(payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return write(payload)
	}

	// hello before ConnectStream registration: a relayed request must
	// never be pushed into a stream the host has not acked yet (see
	// handleHostWS for the same ordering on the WebSocket transport).
	if err := writeHostHello(h, hostID, upDeflate, wsafe); err != nil {
		return
	}
	sc, stop, err := h.ConnectStream(hostID, wsafe)
	if err != nil {
		return
	}
	defer stop()
	log.Printf("[capri-hub] host %s connected (quic %s)", hostID, conn.RemoteAddr())

	// Hub→host ping loop. The WebSocket transport has always had one; QUIC
	// did not, so this connection had no hub-side liveness probe and — more
	// importantly — no periodic re-assert of the browser subscriber count
	// (see writeHostPing), leaving a lost `subscribers` frame uncorrected
	// for the life of the connection.
	pingDone := make(chan struct{})
	defer close(pingDone)
	go func() {
		t := time.NewTicker(hostPingInterval)
		defer t.Stop()
		for {
			select {
			case <-pingDone:
				return
			case <-t.C:
				if err := writeHostPing(h, hostID, wsafe); err != nil {
					return
				}
			}
		}
	}()

	// Idle detection aligned with the WS transport (hostReadTimeout):
	// the read deadline is reset before every frame, so a host that
	// stops sending is dropped silently instead of lingering "online"
	// with every relay stuck.
	go func() {
		for {
			// Request-plane streams (T1): besides the control stream the
			// host opens further bidirectional streams — one per in-flight
			// relay request (or a shared request stream on older hosts).
			// They carry only host→hub `respond` frames plus a no-op
			// `pong` used to materialize the stream (OpenStream transmits
			// nothing until first write). The hub→host direction stays on
			// the control stream, so these are pure uplink: EOF when the
			// host finishes a request is NORMAL and must not tear down the
			// session — only the control stream's death does (below, or
			// via conn.CloseWithError when this session returns).
			rs, err := conn.AcceptStream(context.Background())
			if err != nil {
				return // connection closed with the session
			}
			go func(rs *quic.Stream) {
				defer rs.Close()
				rf := quicFrameReader(rs)
				for {
					// Per-stream idle cap: a stalled request stream is
					// dropped alone (hostReadTimeout, same budget as the
					// control plane).
					if err := rs.SetReadDeadline(time.Now().Add(hostReadTimeout)); err != nil {
						return
					}
					data, err := rf()
					if err != nil {
						return // EOF / timeout / reset: end of this stream only
					}
					if !h.IsCurrentConn(hostID, sc) {
						return
					}
					// handleHostFrame routes by frame type; `write`
					// replies (pong to a stray ping) go back over the
					// CONTROL stream via wsafe, never this stream.
					handleHostFrame(h, hostID, data, wsafe)
				}
			}(rs)
		}
	}()

	for {
		if err := stream.SetReadDeadline(time.Now().Add(hostReadTimeout)); err != nil {
			return
		}
		data, err := readFrame()
		if err != nil {
			return // includes the silent read-timeout close
		}
		// Superseded connection: drop the stale transport on its next
		// frame (see the WS transport for the same guard).
		if !h.IsCurrentConn(hostID, sc) {
			log.Printf("[capri-hub] host %s: superseded quic connection dropped", hostID)
			return
		}
		handleHostFrame(h, hostID, data, wsafe)
	}
}

// quicFrameReader returns a readFrame closure for one QUIC stream. The
// wire format is identical on every stream of the session (4-byte big
// endian length prefix, bit 31 = raw-deflate flag; see PROTOCOL.md §2).
func quicFrameReader(stream *quic.Stream) func() ([]byte, error) {
	return func() ([]byte, error) {
		var lenBuf [4]byte
		if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
			return nil, err
		}
		n, compressed := parseUplinkLen(binary.BigEndian.Uint32(lenBuf[:]))
		if n > 32<<20 {
			return nil, fmt.Errorf("frame too large: %d", n)
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(stream, buf); err != nil {
			return nil, err
		}
		if !compressed {
			return buf, nil
		}
		return inflateUplink(buf)
	}
}

// ── helpers ───────────────────────────────────────────────────────────

// feAuth gates browser-facing routes. Empty token disables the gate (dev).
// Prefer short-lived tickets for WebSocket query auth.
type feAuth struct {
	token   string
	tickets *feTicketStore
}

func (a feAuth) require(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.check(r) {
			writeJSON(w, 401, map[string]any{"ok": false, "error": "需要有效的访问 token"})
			return
		}
		next(w, r)
	}
}

// check reports whether r is allowed for browser routes.
// Order: long-lived Bearer/header, single-use ?ticket=, legacy ?token=.
func (a feAuth) check(r *http.Request) bool {
	if a.token == "" {
		return true
	}
	if tok := bearerToken(r.Header.Get("Authorization")); tokenEqual(tok, a.token) {
		return true
	}
	if tok := strings.TrimSpace(r.Header.Get("X-Access-Token")); tokenEqual(tok, a.token) {
		return true
	}
	// Prefer short-lived ticket for WebSocket (avoids FE_TOKEN in logs).
	if a.tickets != nil {
		if t := strings.TrimSpace(r.URL.Query().Get("ticket")); t != "" {
			return a.tickets.consume(t)
		}
	}
	// Legacy: long-lived secret in query (still accepted for back-compat).
	if tok := strings.TrimSpace(r.URL.Query().Get("token")); tokenEqual(tok, a.token) {
		return true
	}
	return false
}

// requireFEToken is kept for tests; production code uses feAuth.
func requireFEToken(expected string, next http.HandlerFunc) http.HandlerFunc {
	return feAuth{token: expected}.require(next)
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
