package main

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/AgentsHarness/capri-hub/internal/hub"
)

// 用户账号管理。
//
// 管理员能创建用户、重置 token、删除用户；列表永远不含 token 明文，也不含
// 哈希。创建/重置/自助修改的响应会带一次 token，供当时复制。

type userHostView struct {
	HostID        string `json:"hostId"`
	HostName      string `json:"hostName"`
	Online        bool   `json:"online"`
	LastSeenAgeMs int64  `json:"lastSeenAgeMs,omitempty"`
}

type userView struct {
	ID         string         `json:"id"`
	Label      string         `json:"label"`
	CreatedAt  int64          `json:"createdAt"`
	LastUsedAt int64          `json:"lastUsedAt,omitempty"`
	HostCount  int            `json:"hostCount"`
	Hosts      []userHostView `json:"hosts"`
}

func userViewFor(h *hub.Hub, u hub.User) userView {
	hosts := h.ListHostsFor(u.ID)
	rows := make([]userHostView, 0, len(hosts))
	for _, hi := range hosts {
		rows = append(rows, userHostView{
			HostID:        hi.HostID,
			HostName:      hi.HostName,
			Online:        hi.Online,
			LastSeenAgeMs: hi.LastSeenAgeMs,
		})
	}
	return userView{
		ID:         u.ID,
		Label:      u.Label,
		CreatedAt:  u.CreatedAt,
		LastUsedAt: u.LastUsedAt,
		HostCount:  len(hosts),
		Hosts:      rows,
	}
}

func writeUserErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, hub.ErrUserUnknown):
		writeJSON(w, 404, map[string]any{"ok": false, "error": err.Error()})
	case errors.Is(err, hub.ErrUserLimit):
		writeJSON(w, 429, map[string]any{"ok": false, "error": err.Error()})
	case errors.Is(err, hub.ErrUserTokenWeak):
		writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
	default:
		writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
	}
}

// handleUserList: GET /api/users — admin-only account list. No token or
// token hash is ever serialized.
func handleUserList(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users := h.Users()
		out := make([]userView, 0, len(users))
		for _, u := range users {
			out = append(out, userViewFor(h, u))
		}
		writeJSON(w, 200, map[string]any{"ok": true, "users": out})
	}
}

// handleUserCreate: POST /api/users/create {label} → {user, token}. The
// token is shown once and never stored in plaintext.
func handleUserCreate(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Label string `json:"label"`
		}
		_ = readJSON(r, &body)
		u, token, err := h.CreateUser(body.Label)
		if err != nil {
			writeUserErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "user": userViewFor(h, u), "token": token})
	}
}

// handleUserReset: POST /api/users/reset {id} → {user, token}. The old token
// stops working immediately and any live page for that user is kicked.
func handleUserReset(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID string `json:"id"`
		}
		if err := readJSON(r, &body); err != nil || strings.TrimSpace(body.ID) == "" {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "需要 id"})
			return
		}
		u, token, err := h.ResetUserToken(body.ID)
		if err != nil {
			writeUserErr(w, err)
			return
		}
		h.DropUserSubscribers(u.ID)
		writeJSON(w, 200, map[string]any{"ok": true, "user": userViewFor(h, u), "token": token})
	}
}

// handleUserDelete: POST /api/users/delete {id}. The user's hosts are
// unpaired first (their host tokens become invalid), then the account is
// removed and its live pages are kicked.
func handleUserDelete(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID string `json:"id"`
		}
		if err := readJSON(r, &body); err != nil || strings.TrimSpace(body.ID) == "" {
			writeJSON(w, 400, map[string]any{"ok": false, "error": "需要 id"})
			return
		}
		id := strings.TrimSpace(body.ID)
		if _, ok := h.UserByID(id); !ok {
			writeJSON(w, 404, map[string]any{"ok": false, "error": hub.ErrUserUnknown.Error()})
			return
		}
		for _, hostID := range h.HostIDsForUser(id) {
			_ = h.Unpair(hostID)
		}
		if err := h.DeleteUser(id); err != nil {
			writeUserErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "id": id})
	}
}

// handleMyToken: POST /api/me/token {token?} — a user changes their own
// token. An empty token asks the hub to generate one. Admin FE_TOKEN is
// deployment configuration and cannot be rotated here.
func handleMyToken(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identityOf(r)
		if !ok {
			writeJSON(w, 401, map[string]any{"ok": false, "error": "需要有效的访问 token"})
			return
		}
		if !id.isUser() {
			writeJSON(w, 403, map[string]any{"ok": false, "error": "管理员 token 由部署环境管理"})
			return
		}
		var body struct {
			Token string `json:"token"`
		}
		_ = readJSON(r, &body)
		var (
			u        hub.User
			newToken string
			err      error
		)
		if strings.TrimSpace(body.Token) == "" {
			u, newToken, err = h.ResetUserToken(id.UserID)
		} else {
			u, err = h.SetUserToken(id.UserID, body.Token)
			newToken = strings.TrimSpace(body.Token)
		}
		if err != nil {
			writeUserErr(w, err)
			return
		}
		// Give the caller time to receive and store the new token before its
		// old live sockets are cut. The page reconnects with the new value.
		go func() {
			time.Sleep(1500 * time.Millisecond)
			h.DropUserSubscribers(id.UserID)
		}()
		writeJSON(w, 200, map[string]any{"ok": true, "user": userViewFor(h, u), "token": newToken})
	}
}
