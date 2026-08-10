// acp-hub: 中心化中转服务器（relay）。
//
//		Browser (acp-fe) ──WS /ws/fe + HTTP /api/*──▶ acp-hub ──QUIC/WS /ws/host──▶ acp-host × N ──stdio──▶ grok
//
//	  - 配对：Host 用配对码换取 token（POST /api/pair），token 持久化在 ~/.acp-hub。
//	  - Host 出站连接（GET /ws/host 或 QUIC UDP）：下行 request/subscribers，上行 events/respond。
//	  - 浏览器 WebSocket（GET /ws/fe）：聚合 live 事件；/api/* 按 ?host= 中转给对应 Host。
//	  - 可选 FE_TOKEN：部署时设置后，浏览器侧接口必须带同一 token（Bearer / 头 / ?token=）。
//	  - 可靠性：事件带 seq（host 分配），hub 缓冲每 host 最近 4000 条，
//	    GET /api/events?host=X&after=SEQ 供缺口补拉。
package main

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
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

	"github.com/benin/acp-hub/internal/hub"
	"github.com/coder/websocket"
	"github.com/quic-go/quic-go"
)

func main() {
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
	// (Authorization: Bearer, X-Access-Token, or ?token= for WebSocket).
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
	mux.HandleFunc("POST /api/pair", handlePair(h, newPairLimiter()))
	mux.HandleFunc("GET /ws/host", handleHostWS(h))
	// Browser-facing: FE token gate when FE_TOKEN is set.
	mux.HandleFunc("GET /api/hosts", requireFEToken(feToken, handleHosts(h)))
	mux.HandleFunc("GET /api/events", requireFEToken(feToken, handleEvents(h)))
	mux.HandleFunc("GET /ws/fe", handleFeWS(h, feToken))
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

	// QUIC transport for hosts (UDP, loss-resilient, connection-migrating).
	qtls, err := quicTLSConfig()
	if err != nil {
		log.Printf("[acp-hub] QUIC TLS 初始化失败: %v（跳过 QUIC）", err)
	} else {
		go serveQUIC(quicPort, qtls, h)
	}

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
		"version": "0.4.0-ws-quic",
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
		writeJSON(w, 200, map[string]any{"ok": true, "hostId": hostID, "events": evs})
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
const (
	pairRateLimit  = 10                     // attempts per window per IP
	pairRateWindow = time.Minute            // sliding window
	pairFailDelay  = 300 * time.Millisecond // extra delay per failed attempt
)

// pairLimiter is a per-IP sliding-window rate limiter for /api/pair.
type pairLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func newPairLimiter() *pairLimiter {
	return &pairLimiter{hits: make(map[string][]time.Time)}
}

// allow records a request from ip and reports whether it stays within
// the window's budget. Stale entries are pruned on access; the map is
// swept once it exceeds 1024 IPs so it cannot grow without bound.
func (l *pairLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-pairRateWindow)
	if len(l.hits) > 1024 {
		for k, v := range l.hits {
			if len(v) == 0 || v[len(v)-1].Before(cutoff) {
				delete(l.hits, k)
			}
		}
	}
	hs := l.hits[ip]
	i := 0
	for i < len(hs) && hs[i].Before(cutoff) {
		i++
	}
	hs = hs[i:]
	if len(hs) >= pairRateLimit {
		l.hits[ip] = hs
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
		}
		if err := readJSON(r, &body); err != nil || body.Code == "" || body.HostID == "" {
			time.Sleep(pairFailDelay)
			writeJSON(w, 400, map[string]any{"ok": false, "error": "需要 code 和 hostId"})
			return
		}
		token, err := h.Pair(body.Code, body.HostID, body.HostName)
		if err != nil {
			// Small per-failure delay: slows brute force down, while a
			// human retyping the code (or the host's backoff retry)
			// barely notices.
			time.Sleep(pairFailDelay)
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

// Keepalive + half-open detection for host transports (WS and QUIC):
// the hub pings every 25s (the host replies "pong", and also sends
// host_status heartbeats on its own), so a healthy connection always
// produces uplink frames. If nothing arrives for hostReadTimeout — e.g.
// a network blackhole that never sends RST — the connection is dropped
// instead of leaving the host "online" with every relay stuck.
const (
	hostPingInterval = 25 * time.Second
	hostReadTimeout  = 90 * time.Second
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
			log.Printf("[acp-hub] host ws accept: %v", err)
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
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			return conn.Write(ctx, websocket.MessageText, payload)
		}

		// hello must reach the host BEFORE ConnectStream registers it:
		// once registered, Dispatch may push a relayed request into the
		// stream, and a host that has not acked hello yet would miss it.
		// hello carries the subscriber count, so the host is never blind
		// to subscriber state either.
		if err := writeHostHello(h, hostID, write); err != nil {
			return
		}
		_, stop, err := h.ConnectStream(hostID, write)
		if err != nil {
			_ = conn.Close(websocket.StatusPolicyViolation, err.Error())
			return
		}
		defer stop()
		log.Printf("[acp-hub] host %s connected (ws)", hostID)

		ctx := r.Context()
		frames := make(chan hostReadFrame, 16)
		readCtx, cancelRead := context.WithCancel(ctx)
		defer cancelRead()
		go func() {
			for {
				_, data, err := conn.Read(readCtx)
				if err != nil {
					select {
					case frames <- hostReadFrame{err: err}:
					case <-readCtx.Done():
					}
					return
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
				if !idle.Stop() {
					select {
					case <-idle.C:
					default:
					}
				}
				idle.Reset(hostReadTimeout)
				handleHostFrame(h, hostID, f.data, write)
			case <-ping.C:
				frame, _ := json.Marshal(map[string]any{"v": 1, "type": "ping", "ts": time.Now().Unix()})
				_ = write(frame)
			case <-idle.C:
				log.Printf("[acp-hub] host %s: no uplink for %s, dropping", hostID, hostReadTimeout)
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
// while offline.
func writeHostHello(h *hub.Hub, hostID string, write func([]byte) error) error {
	hello, _ := json.Marshal(map[string]any{
		"v":           1,
		"type":        "hello",
		"service":     "hub",
		"subscribers": h.SubscriberCount(),
		"seq":         h.LastSeq(hostID),
	})
	return write(hello)
}

// handleHostFrame processes one uplink frame from a host (events/respond/
// ping). Shared by the WebSocket and QUIC transports.
func handleHostFrame(h *hub.Hub, hostID string, data []byte, write func([]byte) error) {
	var frame struct {
		Type     string          `json:"type"`
		SeqStart *uint64         `json:"seqStart"`
		Events   []hub.Event     `json:"events"`
		ReqID    string          `json:"reqId"`
		Status   int             `json:"status"`
		Body     json.RawMessage `json:"body"`
	}
	if err := json.Unmarshal(data, &frame); err != nil {
		log.Printf("[acp-hub] host %s bad frame: %v", hostID, err)
		return
	}
	switch frame.Type {
	case "events":
		// Events carry host-assigned seqs (frames carry seqStart = the
		// first event's seq), so preserve them: the per-host counter then
		// tracks the host's sequence exactly and hello.seq lets a
		// reconnecting host resume precisely where it left off. Seq-less
		// frames (direct callers / legacy clients) fall back to
		// RegisterEvent's counter advance — renumbering them from 1 here
		// would reset the counter and trigger a full replay (plus FE
		// re-emission) on the next reconnect.
		for _, ev := range frame.Events {
			h.RegisterEvent(hostID, ev)
		}
	case "respond":
		if frame.ReqID == "" {
			return
		}
		if !h.Respond(hostID, frame.ReqID, hub.RelayResponse{Status: frame.Status, Body: frame.Body}) {
			log.Printf("[acp-hub] host %s respond unknown reqId %s", hostID, frame.ReqID)
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
func handleFeWS(h *hub.Hub, feToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkFEToken(r, feToken) {
			writeJSON(w, 401, map[string]any{"ok": false, "error": "需要有效的访问 token"})
			return
		}
		compress := r.URL.Query().Get("c") == "1"

		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			// Dev UIs may be on another origin; FE_TOKEN is the real gate.
			InsecureSkipVerify: true,
		})
		if err != nil {
			log.Printf("[acp-hub] fe ws accept: %v", err)
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
			b, err := json.Marshal(map[string]any{"v": 1, "type": "events", "events": evs})
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

		ctx := r.Context()
		// Drain FE pings in background so the read side does not stall.
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
		// Guard against malformed host responses (e.g. missing/zero
		// status): net/http panics on WriteHeader(0), killing the request.
		status := resp.Status
		if status < 100 || status > 599 {
			status = 502
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write(resp.Body)
	}
}

// ── QUIC host transport ──────────────────────────────────────────────

// quicTLSConfig returns a TLS config for the QUIC listener: from
// QUIC_CERT/QUIC_KEY files when set, else a generated self-signed cert.
// Hosts connect with InsecureSkipVerify (documented; FE never touches QUIC).
func quicTLSConfig() (*tls.Config, error) {
	certFile := os.Getenv("QUIC_CERT")
	keyFile := os.Getenv("QUIC_KEY")
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}
	// Self-sign in memory (hosts skip verification).
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "acp-hub"},
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
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

// serveQUIC listens for host connections over QUIC (UDP). One
// bidirectional stream per connection carries the same JSON frame
// protocol as /ws/host; auth is the first frame {type:"auth", token}.
func serveQUIC(port int, tlsConf *tls.Config, h *hub.Hub) {
	addr := fmt.Sprintf(":%d", port)
	ln, err := quic.ListenAddr(addr, tlsConf, &quic.Config{KeepAlivePeriod: 10 * time.Second})
	if err != nil {
		log.Printf("[acp-hub] QUIC listen %s failed: %v", addr, err)
		return
	}
	log.Printf("[acp-hub] QUIC host transport on udp://%s", addr)
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("[acp-hub] QUIC accept: %v", err)
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
			log.Printf("[acp-hub] quic conn panic recovered: %v", r)
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

	readFrame := func() ([]byte, error) {
		var lenBuf [4]byte
		if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
			return nil, err
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n > 32<<20 {
			return nil, fmt.Errorf("frame too large: %d", n)
		}
		buf := make([]byte, n)
		_, err := io.ReadFull(stream, buf)
		return buf, err
	}
	write := func(payload []byte) error {
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
		Type  string `json:"type"`
		Token string `json:"token"`
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

	var writeMu sync.Mutex
	wsafe := func(payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return write(payload)
	}

	// hello before ConnectStream registration: a relayed request must
	// never be pushed into a stream the host has not acked yet (see
	// handleHostWS for the same ordering on the WebSocket transport).
	if err := writeHostHello(h, hostID, wsafe); err != nil {
		return
	}
	_, stop, err := h.ConnectStream(hostID, wsafe)
	if err != nil {
		return
	}
	defer stop()
	log.Printf("[acp-hub] host %s connected (quic %s)", hostID, conn.RemoteAddr())

	// Idle detection aligned with the WS transport (hostReadTimeout):
	// the read deadline is reset before every frame, so a host that
	// stops sending is dropped silently instead of lingering "online"
	// with every relay stuck.
	for {
		if err := stream.SetReadDeadline(time.Now().Add(hostReadTimeout)); err != nil {
			return
		}
		data, err := readFrame()
		if err != nil {
			return // includes the silent read-timeout close
		}
		handleHostFrame(h, hostID, data, wsafe)
	}
}

// ── helpers ───────────────────────────────────────────────────────────

// requireFEToken wraps a browser-facing handler. When expected is empty,
// auth is disabled (local/dev). Otherwise the request must carry the
// same token via Authorization: Bearer, X-Access-Token, or ?token=
// (the last for WebSocket, which cannot set headers in browsers).
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
	// WebSocket cannot send custom headers from the browser; allow query param.
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
