// capri-hub: 中心化中转服务器（relay）。
//
//		Browser (capri-fe) ──WS /ws/fe + HTTP /api/*──▶ capri-hub ──QUIC/WS /ws/host──▶ capri-host × N ──stdio──▶ grok
//
//	  - 配对：Host 用配对码换取 token（POST /api/pair），token 持久化在 ~/.capri-hub。
//	  - Host 出站连接（GET /ws/host 或 QUIC UDP）：v3 会话协议，下行 request/audience，上行 events/respond/hb。
//	  - 浏览器 WebSocket（GET /ws/fe）：聚合 live 事件；/api/* 按 ?host= 中转给对应 Host。
//	  - 可选 FE_TOKEN：部署时设置后，浏览器侧接口必须带同一 token（Bearer / 头）。
//	    WebSocket 优先用短期 ?ticket=（POST /api/ws-ticket）；仍兼容 ?token=。
//	  - 多用户：users.json 保存用户 token 的 SHA-256 哈希；用户用自己的 token
//	    登录后只看到自己配对的 host。admin 创建用户、重置 token、删除用户。
//	  - 可靠性：事件带 seq（host 分配，会话按事件推进水位），hub 缓冲每 host
//	    最近的 gap-pull 环，GET /api/events?host=X&after=SEQ 供缺口补拉。
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/AgentsHarness/capri-hub/internal/hub"
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
	log.Printf("[capri-hub] version %s", effectiveVersion())
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
	auth := feAuth{token: feToken, tickets: tickets, hub: h, limiter: newAuthLimiter()}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("GET /api/info", handleInfo)
	// Pairing codes are per identity: admin gets the deployment code, a
	// user gets a private code that binds paired hosts to that account.
	mux.HandleFunc("GET /api/pairing", auth.requireMember(handlePairing(h)))
	mux.HandleFunc("POST /api/pairing/rotate", auth.requireMember(handleRotate(h)))
	// Host-facing: authenticate with host pairing token (not FE_TOKEN).
	mux.HandleFunc("POST /api/pair", handlePair(h, lim))
	mux.HandleFunc("GET /ws/host", handleHostWS(h))
	// Browser-facing: FE token / user token gate when configured.
	mux.HandleFunc("GET /api/hosts", auth.requireIdentified(handleHosts(h)))
	mux.HandleFunc("DELETE /api/hosts/{hostId}", auth.requireMember(handleUnpair(h)))
	mux.HandleFunc("POST /api/hosts/{hostId}/rename", auth.requireMember(handleRenameHost(h)))
	// Guests do not do sequence gap-pulls: the hub filters their stream by
	// session, so the per-host seq watermark is meaningless to them. Users
	// may gap-pull their own hosts.
	mux.HandleFunc("GET /api/events", auth.requireMember(handleEvents(h)))
	mux.HandleFunc("GET /api/prefs", auth.requireMember(handlePrefsGet(h)))
	mux.HandleFunc("PUT /api/prefs", auth.requireMember(handlePrefsPut(h)))
	// User accounts: admin creates users and can reset/delete them. The
	// plaintext token is returned once, on create/reset; listing never
	// contains it.
	mux.HandleFunc("GET /api/users", auth.requireAdmin(handleUserList(h)))
	mux.HandleFunc("POST /api/users/create", auth.requireAdmin(handleUserCreate(h)))
	mux.HandleFunc("POST /api/users/reset", auth.requireAdmin(handleUserReset(h)))
	mux.HandleFunc("POST /api/users/delete", auth.requireAdmin(handleUserDelete(h)))
	// A user changes their own token; admin tokens live in deployment env.
	mux.HandleFunc("POST /api/me/token", auth.requireIdentified(handleMyToken(h)))
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
