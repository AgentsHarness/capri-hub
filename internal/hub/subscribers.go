package hub

import (
	"sort"
	"time"
)

// 在线订阅者面板的数据面。
//
// 顶栏那个数字回答「现在有几台浏览器在看」，管理员往往接着要问「都是谁、
// 从哪台设备、哪把钥匙进来、正在看哪个会话」。这个问题只有 hub 答得了：
// 每个 /ws/fe 注册时它就看到 peer 地址、User-Agent 和认证身份，之后又收到
// 页面主动声明的 host/session。于是注册时把这些一次性快照记在 feSubscriber
// 上，需要时按快照列表返回——不在事件路径上加锁，也不改 fan-out 语义。

// SubscriberInfo is the browser identity captured at /ws/fe registration.
// Every field is display-only: nothing here decides what a subscriber may
// receive (that is the identity the auth layer already enforced).
type SubscriberInfo struct {
	// IP is the client address without the port. A reverse proxy's
	// X-Real-IP wins when present — the hub itself listens on loopback
	// behind nginx in the deployed setup, so RemoteAddr would be 127.0.0.1
	// for every row.
	IP string
	// UA is the browser User-Agent, truncated by the caller.
	UA string
	// Role is "admin", "user" or "guest".
	Role string
	// UserID / UserLabel name the users.json record behind an ordinary
	// user socket. Empty for admin and guest sockets.
	UserID    string
	UserLabel string
	// GuestID / GuestLabel name the guests.json record behind a guest
	// socket. Both empty for admin sockets (the FE_TOKEN is the identity,
	// and it is not echoed back).
	GuestID    string
	GuestLabel string
}

// SubscriberRow is one row of the admin subscriber panel (GET
// /api/subscribers). Timestamps are epoch milliseconds to match the FE's
// other stamps.
type SubscriberRow struct {
	ID          int64  `json:"id"`
	IP          string `json:"ip,omitempty"`
	UserAgent   string `json:"userAgent,omitempty"`
	Role        string `json:"role"`
	UserID      string `json:"userId,omitempty"`
	UserLabel   string `json:"userLabel,omitempty"`
	GuestID     string `json:"guestId,omitempty"`
	GuestLabel  string `json:"guestLabel,omitempty"`
	HostID      string `json:"hostId,omitempty"`
	SessionID   string `json:"sessionId,omitempty"`
	ConnectedAt int64  `json:"connectedAt"`
}

// Subscribers returns a stable snapshot of every live browser subscriber,
// oldest registration first. Rows carry no secrets: a guest is identified
// by its record id and label, never by the token itself.
//
// Ordering by ID keeps successive polls diffable in the panel; the id is
// assigned monotonically at registration.
func (h *Hub) Subscribers() []SubscriberRow {
	cur := h.subs.Load()
	if cur == nil {
		return []SubscriberRow{}
	}
	out := make([]SubscriberRow, 0, len(*cur))
	for _, s := range *cur {
		hostID, _ := s.host.Load().(string)
		sessionID, _ := s.session.Load().(string)
		out = append(out, SubscriberRow{
			ID:          s.id,
			IP:          s.info.IP,
			UserAgent:   s.info.UA,
			Role:        s.info.Role,
			UserID:      s.info.UserID,
			UserLabel:   s.info.UserLabel,
			GuestID:     s.info.GuestID,
			GuestLabel:  s.info.GuestLabel,
			HostID:      hostID,
			SessionID:   sessionID,
			ConnectedAt: s.connectedAt.UnixMilli(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// SubscriberIDFor reports the registration id behind a subscriber channel.
// The /ws/fe handler puts it in `hello` so an admin page can mark its own
// row without guessing by address (two tabs on one machine look alike).
func (h *Hub) SubscriberIDFor(ch chan Event) (int64, bool) {
	cur := h.subs.Load()
	if cur == nil {
		return 0, false
	}
	for _, s := range *cur {
		if s.ch == ch {
			return s.id, true
		}
	}
	return 0, false
}

// nowStamp is a seam for tests that need deterministic registration times.
var nowStamp = time.Now
