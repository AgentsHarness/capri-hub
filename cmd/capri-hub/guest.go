package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"github.com/AgentsHarness/capri-hub/internal/hub"
	"github.com/AgentsHarness/capri-hub/wire"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

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
	if !ident.allowsHost(h, hostID) {
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
		// Idempotency-Key 只做校验和透传；scope 由认证身份生成，浏览器带来的
		// Idempotency-Scope 一律忽略，避免一个用户拿别人的 scope 重放 key。
		idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if idemKey != "" {
			if err := wire.ValidateIdemKey(idemKey); err != nil {
				writeJSON(w, 400, map[string]any{"ok": false, "error": "invalid_idempotency_key"})
				return
			}
		}
		hostID := r.URL.Query().Get("host")
		if hostID == "" {
			hostID = ident.defaultHost(h)
		}
		if hostID == "" || !ident.allowsHost(h, hostID) {
			if hostID == "" {
				writeJSON(w, 503, map[string]any{"ok": false, "error": hub.ErrNoHost.Error()})
				return
			}
			msg := "无权访问该 Host"
			if ident.isGuest() {
				msg = "访客无权访问该 Host"
			}
			writeJSON(w, 403, map[string]any{"ok": false, "error": msg})
			return
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
		var opts hub.DispatchOptions
		if idemKey != "" {
			opts = hub.DispatchOptions{IdemKey: idemKey, IdemScope: ident.idemScope()}
		}
		resp, err := h.DispatchOpts(r.Context(), hostID, r.Method, r.URL.Path, body, opts)
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
