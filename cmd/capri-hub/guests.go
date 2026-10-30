package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/AgentsHarness/capri-hub/internal/hub"
)

// ── 访客身份（请求上下文） ─────────────────────────────────────────────

type identityCtxKey struct{}

func withIdentity(ctx context.Context, id identity) context.Context {
	return context.WithValue(ctx, identityCtxKey{}, id)
}

// identityOf returns the identity attached by requireIdentified.
func identityOf(r *http.Request) (identity, bool) {
	id, ok := r.Context().Value(identityCtxKey{}).(identity)
	return id, ok
}

// ── 管理员端点：/api/guest-tokens/* ───────────────────────────────────

func writeGuestErr(w http.ResponseWriter, err error) {
	if errors.Is(err, hub.ErrGuestUnknown) {
		writeJSON(w, 404, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
}

func handleGuestTokenList(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "tokens": h.GuestTokens()})
	}
}

func handleGuestTokenCreate(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Label     string             `json:"label"`
			ExpiresAt int64              `json:"expiresAt"`
			Sessions  []hub.GuestSession `json:"sessions"`
		}
		if err := readJSON(r, &body); err != nil {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "请求体不是合法 JSON"})
			return
		}
		g, err := h.CreateGuestToken(body.Label, body.ExpiresAt, body.Sessions)
		if err != nil {
			writeGuestErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "token": g})
	}
}

func handleGuestTokenUpdate(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID        string  `json:"id"`
			Label     *string `json:"label"`
			ExpiresAt *int64  `json:"expiresAt"`
			Revoked   *bool   `json:"revoked"`
		}
		if err := readJSON(r, &body); err != nil || strings.TrimSpace(body.ID) == "" {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "需要 id"})
			return
		}
		g, err := h.UpdateGuestToken(body.ID, body.Label, body.ExpiresAt, body.Revoked)
		if err != nil {
			writeGuestErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "token": g})
	}
}

func handleGuestTokenDelete(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID string `json:"id"`
		}
		if err := readJSON(r, &body); err != nil || strings.TrimSpace(body.ID) == "" {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "需要 id"})
			return
		}
		if err := h.DeleteGuestToken(body.ID); err != nil {
			writeGuestErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "id": body.ID})
	}
}

func handleGuestSessionsAdd(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID    string             `json:"id"`
			Items []hub.GuestSession `json:"items"`
		}
		if err := readJSON(r, &body); err != nil || strings.TrimSpace(body.ID) == "" {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "需要 id"})
			return
		}
		g, err := h.AddGuestSessions(body.ID, body.Items)
		if err != nil {
			writeGuestErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "token": g})
	}
}

func handleGuestSessionsRemove(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID    string                `json:"id"`
			Items []hub.GuestSessionRef `json:"items"`
		}
		if err := readJSON(r, &body); err != nil || strings.TrimSpace(body.ID) == "" {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "需要 id"})
			return
		}
		g, err := h.RemoveGuestSessions(body.ID, body.Items)
		if err != nil {
			writeGuestErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "token": g})
	}
}

// handleGuestTokenRefresh re-reads each involved host's session list through
// the hub's own relay, then refreshes titles / host names and marks sessions
// the host no longer lists as stale. No new host endpoint is needed: the
// existing POST /api/sessions is the source.
func handleGuestTokenRefresh(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID string `json:"id"`
		}
		if err := readJSON(r, &body); err != nil || strings.TrimSpace(body.ID) == "" {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "需要 id"})
			return
		}
		g, ok := h.GuestByID(body.ID)
		if !ok {
			writeJSON(w, 404, map[string]any{"ok": false, "error": hub.ErrGuestUnknown.Error()})
			return
		}
		hosts := hub.GuestHostIDs(g)
		// One dispatch per host, sequential but bounded: the FE awaits the
		// whole refresh, and a hub rarely serves more than a handful of
		// hosts. A failed host keeps its previous snapshot (stale=false) —
		// offline cannot be distinguished from "session was deleted", and
		// greying out every row on a transient blip would be misleading.
		type hostScan struct {
			titles map[string]string
			cwds   map[string]string
			ok     bool
		}
		scans := make(map[string]hostScan, len(hosts))
		names := make(map[string]string, len(hosts))
		for _, hi := range h.ListHosts() {
			names[hi.HostID] = hi.HostName
		}
		for _, hostID := range hosts {
			scan := hostScan{titles: map[string]string{}, cwds: map[string]string{}, ok: false}
			ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
			resp, err := h.Dispatch(ctx, hostID, http.MethodPost, "/api/sessions", json.RawMessage(`{}`))
			cancel()
			if err != nil || resp.Status < 200 || resp.Status > 299 {
				scans[hostID] = scan
				continue
			}
			var payload struct {
				Sessions []struct {
					SessionID string `json:"sessionId"`
					Cwd       string `json:"cwd"`
					Title     string `json:"title"`
				} `json:"sessions"`
			}
			if json.Unmarshal(resp.Body, &payload) != nil {
				scans[hostID] = scan
				continue
			}
			for _, s := range payload.Sessions {
				if s.SessionID == "" {
					continue
				}
				scan.titles[s.SessionID] = s.Title
				scan.cwds[s.SessionID] = s.Cwd
			}
			scan.ok = true
			scans[hostID] = scan
		}

		next := make([]hub.GuestSession, 0, len(g.Sessions))
		for _, s := range g.Sessions {
			upd := s
			if name := names[s.HostID]; name != "" {
				upd.HostName = name
			}
			if scan, seen := scans[s.HostID]; seen && scan.ok {
				if title, found := scan.titles[s.SessionID]; found {
					if title != "" {
						upd.Title = title
					}
					if cwd := scan.cwds[s.SessionID]; cwd != "" {
						upd.Cwd = cwd
					}
					upd.Stale = false
				} else {
					upd.Stale = true
				}
			}
			next = append(next, upd)
		}
		updated, err := h.ReplaceGuestSessionSnapshot(g.ID, next)
		if err != nil {
			writeGuestErr(w, err)
			return
		}
		// Echo fresh host liveness for the FE's session picker.
		live := make([]map[string]any, 0, len(hosts))
		byID := map[string]hub.HostInfo{}
		for _, hi := range h.ListHosts() {
			byID[hi.HostID] = hi
		}
		for _, hostID := range hosts {
			if hi, found := byID[hostID]; found {
				live = append(live, map[string]any{
					"hostId": hi.HostID, "hostName": hi.HostName, "online": hi.Online,
				})
			} else {
				live = append(live, map[string]any{"hostId": hostID, "online": false})
			}
		}
		writeJSON(w, 200, map[string]any{"ok": true, "token": updated, "hosts": live})
	}
}

// ── 管理员端点：/api/subscribers ──────────────────────────────────────

// handleSubscribers: GET /api/subscribers — every live browser /ws/fe
// socket, admin only. The top bar number says how many pages are watching;
// this endpoint says who they are (address, browser, which credential let
// them in, which session each is reading). Guest identity is reported by
// guests.json id + label — never the token.
func handleSubscribers(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows := h.Subscribers()
		writeJSON(w, 200, map[string]any{"ok": true, "subscribers": rows, "count": len(rows)})
	}
}

// subscriberInfoFor builds the display-only identity snapshot for one
// /ws/fe socket. remoteIP is resolved by the HTTP layer (proxy aware).
func subscriberInfoFor(ident identity, remoteIP, userAgent string) hub.SubscriberInfo {
	info := hub.SubscriberInfo{
		IP:   remoteIP,
		UA:   truncateUA(userAgent),
		Role: ident.Role,
	}
	if info.Role == "" {
		info.Role = "admin"
	}
	if ident.isGuest() {
		info.GuestID = ident.TokenID
		info.GuestLabel = ident.Label
	}
	return info
}

// truncateUA bounds a User-Agent for the panel. Real browser UAs run
// 100–200 chars; a hostile one could be a megabyte, and the row is only
// ever displayed, never parsed for control decisions.
func truncateUA(ua string) string {
	const max = 300
	ua = strings.TrimSpace(ua)
	if len(ua) <= max {
		return ua
	}
	return ua[:max] + "…"
}

// ── 访客端点 ──────────────────────────────────────────────────────────

// helloHosts is the registry a WS client is told about at connect time.
// Guests only learn the hosts their token's sessions live on; hub-level
// hosts_changed never reaches them (they render from /api/access-role).
func helloHosts(h *hub.Hub, ident identity) []hub.HostInfo {
	all := h.ListHosts()
	if !ident.isGuest() {
		return all
	}
	allowed := map[string]bool{}
	for _, s := range ident.Sessions {
		allowed[s.HostID] = true
	}
	out := make([]hub.HostInfo, 0, len(allowed))
	for _, hi := range all {
		if allowed[hi.HostID] {
			out = append(out, hi)
		}
	}
	return out
}

// helloDefaultHost is the ?host= the FE should start on. Guests always
// start on a whitelisted host.
func helloDefaultHost(h *hub.Hub, ident identity) string {
	if ident.isGuest() {
		return ident.defaultHost()
	}
	return h.DefaultHostID()
}

// helloSeqs carries per-host seq watermarks for gap-pull. Guests never
// gap-pull (their stream is filtered per session, so seqs would not line
// up), so the map is empty for them.
func helloSeqs(h *hub.Hub, ident identity) map[string]uint64 {
	if ident.isGuest() {
		return map[string]uint64{}
	}
	return h.SeqByHost()
}

// handleAccessRole: GET /api/access-role — the FE's role probe. Admin gets
// {role:"admin"}; a guest gets its label/expiry plus the whitelist.
func handleAccessRole(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identityFromRequest(r, h)
		if !ok {
			writeJSON(w, 401, map[string]any{"ok": false, "error": "需要有效的访问 token"})
			return
		}
		if !id.isGuest() {
			writeJSON(w, 200, map[string]any{"ok": true, "role": "admin"})
			return
		}
		writeJSON(w, 200, map[string]any{
			"ok":   true,
			"role": "guest",
			"guest": map[string]any{
				"id":        id.TokenID,
				"label":     id.Label,
				"expiresAt": id.ExpiresAt,
			},
			"sessions": guestSessionRows(id),
		})
	}
}

// identityFromRequest is a small helper for handlers that are also invoked
// without the requireAny middleware (tests / direct registration).
func identityFromRequest(r *http.Request, h *hub.Hub) (identity, bool) {
	if id, ok := identityOf(r); ok {
		return id, true
	}
	return feAuth{hub: h}.identify(r)
}

// guestSessionRows flattens the whitelist into the FE's wire shape.
func guestSessionRows(id identity) []map[string]any {
	out := make([]map[string]any, 0, len(id.Sessions))
	for _, s := range id.Sessions {
		row := map[string]any{
			"hostId":    s.HostID,
			"sessionId": s.SessionID,
		}
		if s.HostName != "" {
			row["hostName"] = s.HostName
		}
		if s.Cwd != "" {
			row["cwd"] = s.Cwd
		}
		if s.Title != "" {
			row["title"] = s.Title
		}
		if s.Stale {
			row["stale"] = true
		}
		out = append(out, row)
	}
	return out
}

// handleGuestSessions: GET /api/guest/sessions — same rows as access-role
// (the FE re-reads them when switching; optional, but cheap and keeps the
// picker authoritative without re-probing the role).
func handleGuestSessions(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identityFromRequest(r, h)
		if !ok {
			writeJSON(w, 401, map[string]any{"ok": false, "error": "需要有效的访问 token"})
			return
		}
		if !id.isGuest() {
			writeJSON(w, 403, map[string]any{"ok": false, "error": "仅访客令牌有此视图"})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "sessions": guestSessionRows(id)})
	}
}

// handleHosts is the registry listing. Guests only see the hosts their
// token's sessions live on; admin behaviour is unchanged.
func handleHosts(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, identified := identityOf(r)
		if !identified || !id.isGuest() {
			writeJSON(w, 200, map[string]any{
				"hosts":         h.ListHosts(),
				"defaultHostId": h.DefaultHostID(),
			})
			return
		}
		allowed := map[string]bool{}
		for _, s := range id.Sessions {
			allowed[s.HostID] = true
		}
		hosts := make([]hub.HostInfo, 0, len(allowed))
		for _, hi := range h.ListHosts() {
			if allowed[hi.HostID] {
				hosts = append(hosts, hi)
			}
		}
		// Deterministic order even when the registry is empty for a
		// whitelisted host: sort by id for stable FE rendering.
		sort.SliceStable(hosts, func(i, j int) bool { return hosts[i].HostID < hosts[j].HostID })
		writeJSON(w, 200, map[string]any{
			"hosts":         hosts,
			"defaultHostId": id.defaultHost(),
			"role":          "guest",
		})
	}
}
