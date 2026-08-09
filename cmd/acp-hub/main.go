// acp-hub: 中心化中转服务器（relay）。
//
//		Browser (acp-fe) ──HTTP/SSE──▶ acp-hub ──SSE+HTTP──▶ acp-host × N ──stdio──▶ grok
//
//	  - 配对：Host 用配对码换取 token（POST /api/pair），token 持久化在 ~/.acp-hub。
//	  - Host 出站连接：SSE 长连接（GET /api/hub/stream）接收中转请求，
//	    事件批量上报（POST /api/hub/events），请求应答（POST /api/hub/respond）。
//	  - 浏览器：/events 聚合事件流（事件带 hostId），/api/* 按 ?host= 中转给对应 Host。
//	  - 可选 FE_TOKEN：部署时设置后，浏览器侧接口必须带同一 token（Bearer / 头 / ?token=）。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/benin/acp-hub/internal/hub"
)

func main() {
	port := 8787
	if v := os.Getenv("PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			port = n
		}
	}

	// Browser / FE access token. When set, browser-facing routes require it
	// (Authorization: Bearer, X-Access-Token, or ?token= for EventSource).
	// Host-facing routes keep their own pairing Bearer tokens.
	feToken := strings.TrimSpace(os.Getenv("FE_TOKEN"))
	if feToken == "" {
		feToken = strings.TrimSpace(os.Getenv("ACCESS_TOKEN"))
	}

	h := hub.New()
	code, exp := h.PairingCode()
	log.Printf("[acp-hub] pairing code: %s (expires %s)", code, exp.Format("15:04:05"))
	if feToken != "" {
		log.Printf("[acp-hub] FE_TOKEN set — browser requests require Authorization: Bearer <token>")
	} else {
		log.Printf("[acp-hub] FE_TOKEN unset — browser routes are open (local/dev only)")
	}
	log.Printf("[acp-hub] listening on http://localhost:%d", port)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("GET /api/info", handleInfo)
	// Admin pairing endpoints: require FE token when configured.
	mux.HandleFunc("GET /api/pairing", requireFEToken(feToken, handlePairing(h)))
	mux.HandleFunc("POST /api/pairing/rotate", requireFEToken(feToken, handleRotate(h)))
	// Host-facing: authenticate with host pairing token (not FE_TOKEN).
	mux.HandleFunc("POST /api/pair", handlePair(h))
	mux.HandleFunc("GET /api/hub/stream", handleHostStream(h))
	mux.HandleFunc("POST /api/hub/events", handleHostEvents(h))
	mux.HandleFunc("POST /api/hub/respond", handleHostRespond(h))
	// Browser-facing: FE token gate when FE_TOKEN is set.
	mux.HandleFunc("GET /api/hosts", requireFEToken(feToken, handleHosts(h)))
	mux.HandleFunc("GET /events", requireFEToken(feToken, handleBrowserSSE(h)))
	// Catch-all: relay everything else under /api/* to the selected host.
	mux.HandleFunc("GET /api/{path...}", requireFEToken(feToken, handleRelay(h)))
	mux.HandleFunc("POST /api/{path...}", requireFEToken(feToken, handleRelay(h)))

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           withCORS(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[acp-hub] server: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

// ── handlers ──────────────────────────────────────────────────────────

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true, "service": "acp-hub"})
}

func handleInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"service": "acp-hub",
		"version": "0.2.0-relay",
		"modes":   []string{"pair", "host-stream", "relay", "events"},
	})
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

func handlePair(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Code     string `json:"code"`
			HostID   string `json:"hostId"`
			HostName string `json:"hostName"`
		}
		if err := readJSON(r, &body); err != nil || body.Code == "" || body.HostID == "" {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "需要 code 和 hostId"})
			return
		}
		token, err := h.Pair(body.Code, body.HostID, body.HostName)
		if err != nil {
			writeJSON(w, 401, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "token": token, "hostId": body.HostID})
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

// handleBrowserSSE: aggregated event stream for browsers. Events are
// tagged with their hostId; hub-level events (hello, hosts_changed) carry
// no hostId so the frontend can filter per host.
func handleBrowserSSE(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		writeSSE(w, flusher, map[string]any{
			"type":          "hello",
			"service":       "hub",
			"hosts":         h.ListHosts(),
			"defaultHostId": h.DefaultHostID(),
		})

		ch, unsub := h.Subscribe()
		defer unsub()
		ticker := time.NewTicker(25 * time.Second)
		defer ticker.Stop()

		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				fmt.Fprintf(w, ": ping\n\n")
				flusher.Flush()
			case ev, ok := <-ch:
				if !ok {
					return
				}
				writeSSE(w, flusher, ev)
			}
		}
	}
}

// handleHostStream: the host's outbound SSE connection. The hub pushes
// relayed browser requests (type:"request") to it.
func handleHostStream(h *hub.Hub) http.HandlerFunc {
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
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		var writeMu sync.Mutex
		write := func(payload []byte) error {
			writeMu.Lock()
			defer writeMu.Unlock()
			_, err := fmt.Fprintf(w, "data: %s\n\n", payload)
			flusher.Flush()
			return err
		}

		conn, stop, err := h.ConnectStream(hostID, write)
		if err != nil {
			writeJSON(w, 404, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		defer stop()
		_ = conn
		// Include current browser subscriber count so the host can pause
		// event upload when nobody is listening (see subscribers frames).
		hello, _ := json.Marshal(map[string]any{
			"type":        "hello",
			"service":     "hub",
			"subscribers": h.SubscriberCount(),
		})
		if err := write(hello); err != nil {
			return
		}
		<-r.Context().Done()
	}
}

// handleHostEvents: host → hub event batch (also the liveness heartbeat).
func handleHostEvents(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hostID, ok := authHost(h, r)
		if !ok {
			writeJSON(w, 401, map[string]any{"ok": false, "error": "token 无效"})
			return
		}
		var body struct {
			HostID string      `json:"hostId"`
			Events []hub.Event `json:"events"`
		}
		if err := readJSON(r, &body); err != nil {
			writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		if body.HostID != "" && body.HostID != hostID {
			writeJSON(w, 403, map[string]any{"ok": false, "error": "host 与 token 不匹配"})
			return
		}
		for _, ev := range body.Events {
			h.RegisterEvent(hostID, ev)
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

// handleHostRespond: host → hub answer for a relayed request.
func handleHostRespond(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hostID, ok := authHost(h, r)
		if !ok {
			writeJSON(w, 401, map[string]any{"ok": false, "error": "token 无效"})
			return
		}
		var body struct {
			HostID string          `json:"hostId"`
			ReqID  string          `json:"reqId"`
			Status int             `json:"status"`
			Body   json.RawMessage `json:"body"`
		}
		if err := readJSON(r, &body); err != nil || body.ReqID == "" {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "需要 reqId"})
			return
		}
		if body.HostID != "" && body.HostID != hostID {
			writeJSON(w, 403, map[string]any{"ok": false, "error": "host 与 token 不匹配"})
			return
		}
		if !h.Respond(hostID, body.ReqID, hub.RelayResponse{Status: body.Status, Body: body.Body}) {
			writeJSON(w, 404, map[string]any{"ok": false, "error": "未知 reqId（已超时或已应答）"})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
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
		var body json.RawMessage
		if r.Body != nil {
			b, err := io.ReadAll(io.LimitReader(r.Body, 5<<20))
			if err != nil {
				writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
				return
			}
			body = b
		}
		resp, err := h.Dispatch(hostID, r.Method, r.URL.Path, body)
		if err != nil {
			var re *hub.RelayError
			if errors.As(err, &re) {
				writeJSON(w, re.Status, map[string]any{"ok": false, "error": re.Message})
			} else {
				writeJSON(w, 500, map[string]any{"ok": false, "error": err.Error()})
			}
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(resp.Status)
		_, _ = w.Write(resp.Body)
	}
}

// ── helpers ───────────────────────────────────────────────────────────

// requireFEToken wraps a browser-facing handler. When expected is empty,
// auth is disabled (local/dev). Otherwise the request must carry the
// same token via Authorization: Bearer, X-Access-Token, or ?token=
// (the last for EventSource, which cannot set headers).
func requireFEToken(expected string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkFEToken(r, expected) {
			writeJSON(w, 401, map[string]any{"ok": false, "error": "需要有效的访问 token"})
			return
		}
		next(w, r)
	}
}

// checkFEToken reports whether r is allowed for browser routes.
// Empty expected disables the gate.
func checkFEToken(r *http.Request, expected string) bool {
	if expected == "" {
		return true
	}
	if tok := bearerToken(r.Header.Get("Authorization")); tokenEqual(tok, expected) {
		return true
	}
	if tok := strings.TrimSpace(r.Header.Get("X-Access-Token")); tokenEqual(tok, expected) {
		return true
	}
	// EventSource cannot send custom headers; allow query param.
	if tok := strings.TrimSpace(r.URL.Query().Get("token")); tokenEqual(tok, expected) {
		return true
	}
	return false
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

func writeSSE(w http.ResponseWriter, f http.Flusher, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", b)
	f.Flush()
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

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Access-Token")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
