package hub

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// 访客令牌（guests.json，与 hub.json 同级、同 0600 权限）。
//
// 一个令牌 = 一组可跨 host 的会话白名单。浏览器凭令牌登录后只能看到这些
// 会话，且在 hub 侧就被限制到白名单（中继改写 + WS 事件过滤），不依赖前端
// 自觉。token 明文落盘：hub.json 本来就明文存 host 配对 token，同一威胁
// 模型；好处是管理员随时能重新复制任意令牌的分享链接。
//
// 令牌与 FE_TOKEN 解耦：轮换 FE_TOKEN 不影响访客，作废必须显式吊销。
const guestsFileVersion = 1

// ErrGuestUnknown: 令牌 id 不存在。
var ErrGuestUnknown = errors.New("访客令牌不存在")

// GuestSession 是白名单里的一条会话快照。hostName / title 是加入时的快照，
// refresh 时按 host 的实时列表回填；Host 上已不存在的会话标 Stale。
type GuestSession struct {
	HostID    string `json:"hostId"`
	HostName  string `json:"hostName,omitempty"`
	SessionID string `json:"sessionId"`
	Cwd       string `json:"cwd,omitempty"`
	Title     string `json:"title,omitempty"`
	AddedAt   int64  `json:"addedAt"`
	// Stale 只由 refresh 置位：Host 的会话列表里已找不到该 sessionId。
	Stale bool `json:"stale,omitempty"`
}

// GuestToken 是一条访客令牌记录。
type GuestToken struct {
	ID        string `json:"id"`
	Token     string `json:"token"`
	Label     string `json:"label"`
	CreatedAt int64  `json:"createdAt"`
	// ExpiresAt 是 epoch 秒；0 = 永久。
	ExpiresAt  int64          `json:"expiresAt"`
	Revoked    bool           `json:"revoked"`
	Sessions   []GuestSession `json:"sessions"`
	LastUsedAt int64          `json:"lastUsedAt,omitempty"`
}

// Expired 报告令牌在 now 是否已过期。
func (g GuestToken) Expired(now time.Time) bool {
	return g.ExpiresAt > 0 && now.Unix() >= g.ExpiresAt
}

// Active 报告令牌是否仍可用于认证（未吊销、未过期）。
func (g GuestToken) Active(now time.Time) bool {
	return !g.Revoked && !g.Expired(now)
}

type guestFileDoc struct {
	Version int          `json:"version"`
	Tokens  []GuestToken `json:"tokens"`
}

// ── 持久化 ────────────────────────────────────────────────────────────

// loadGuests 读取 guests.json。文件缺失/损坏时从空表开始（下一次写入重建）。
func (h *Hub) loadGuests() {
	b, err := os.ReadFile(h.guestsFile)
	if err != nil {
		return
	}
	var doc guestFileDoc
	if json.Unmarshal(b, &doc) != nil {
		log.Printf("[capri-hub] guests: ignoring unreadable %s", h.guestsFile)
		return
	}
	h.guests = make([]GuestToken, 0, len(doc.Tokens))
	for _, g := range doc.Tokens {
		if g.ID == "" || g.Token == "" {
			continue
		}
		if g.Sessions == nil {
			g.Sessions = []GuestSession{}
		}
		h.guests = append(h.guests, g)
	}
}

// guestsPayloadLocked 序列化当前令牌表（调用方持 h.mu）。
func (h *Hub) guestsPayloadLocked() ([]byte, bool) {
	if h.guestsFile == "" {
		return nil, false
	}
	b, err := json.Marshal(guestFileDoc{Version: guestsFileVersion, Tokens: h.guests})
	if err != nil {
		return nil, false
	}
	return b, true
}

// persistGuestsNow serializes the CURRENT table and writes it atomically.
//
// The snapshot is taken under guestPersistMu → h.mu (never the reverse), so
// two concurrent writers cannot land out of order and lose each other's
// records: write A's snapshot is always newer than the state B's write
// started from. The disk write itself stays outside h.mu — a slow disk must
// not stall the hub.
func (h *Hub) persistGuestsNow() {
	h.guestPersistMu.Lock()
	defer h.guestPersistMu.Unlock()
	h.mu.Lock()
	payload, ok := h.guestsPayloadLocked()
	if ok {
		h.guestPersistedAt = time.Now()
	}
	h.mu.Unlock()
	if ok {
		h.persistGuests(payload)
	}
}

// persistGuests 原子写 guests.json（0600，与 hub.json 同款写盘）。调用方
// 已持 guestPersistMu 且不持 h.mu。
func (h *Hub) persistGuests(payload []byte) {
	if len(payload) == 0 {
		return
	}
	if err := writeFileAtomic(h.guestsFile, payload); err != nil {
		log.Printf("[capri-hub] guests persist: %v", err)
	}
}

// cloneGuestToken 深拷贝一条记录（调用方拿到的切片不与存储别名）。
func cloneGuestToken(g GuestToken) GuestToken {
	out := g
	out.Sessions = append([]GuestSession(nil), g.Sessions...)
	return out
}

func cloneGuestTokens(gs []GuestToken) []GuestToken {
	out := make([]GuestToken, len(gs))
	for i, g := range gs {
		out[i] = cloneGuestToken(g)
	}
	return out
}

// ── 查询 ──────────────────────────────────────────────────────────────

// GuestTokens 返回全部令牌（含明文 token），按创建时间升序。
func (h *Hub) GuestTokens() []GuestToken {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := cloneGuestTokens(h.guests)
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt < out[j].CreatedAt
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// GuestByID 按 id 取一条记录。
func (h *Hub) GuestByID(id string) (GuestToken, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, g := range h.guests {
		if g.ID == id {
			return cloneGuestToken(g), true
		}
	}
	return GuestToken{}, false
}

// GuestByToken 按 token 明文查表；只返回未吊销、未过期的记录。命中时刷新
// lastUsedAt（最多每分钟落盘一次，避免每个请求都写盘）。
func (h *Hub) GuestByToken(token string) (GuestToken, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return GuestToken{}, false
	}
	now := time.Now()
	h.mu.Lock()
	var hit *GuestToken
	for i := range h.guests {
		if h.guests[i].Token == token {
			hit = &h.guests[i]
			break
		}
	}
	if hit == nil || !hit.Active(now) {
		h.mu.Unlock()
		return GuestToken{}, false
	}
	hit.LastUsedAt = now.Unix()
	due := now.Sub(h.guestPersistedAt) >= time.Minute
	out := cloneGuestToken(*hit)
	h.mu.Unlock()
	if due {
		h.persistGuestsNow()
	}
	return out, true
}

// LookupGuestToken 是 GuestByToken 的布尔别名（auth 层语义更直白）。
func (h *Hub) LookupGuestToken(token string) (GuestToken, bool) {
	return h.GuestByToken(token)
}

// ── 写操作 ────────────────────────────────────────────────────────────

func newGuestID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return "g_" + hex.EncodeToString(b[:])[:6]
}

// newGuestToken 生成访客令牌：16 字节随机数（128 bit）的 base64url 无填充，
// 即 `g_` + 22 个字符。
//
// 旧格式是 32 字节 hex（`g_` + 64 字符，66 长）。管理员要把这串贴进分享链接
// 或手抄给访客，太长了；128 bit 熵对「可吊销、带到期」的分享令牌足够——它
// 不像 FE_TOKEN 那样是长期主密钥，且 hub 侧还按白名单强制会话范围。
// 旧令牌照旧能查（凭证明文按字符串匹配，长度不限），不需要数据迁移。
func newGuestToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "g_" + base64.RawURLEncoding.EncodeToString(b[:])
}

// sanitizeGuestSession 归一化一条白名单条目：host/session 必须有值，cwd
// 去掉尾部斜杠之外的修饰，AddedAt 缺省填当前时间。
func sanitizeGuestSession(in GuestSession, now int64) (GuestSession, bool) {
	in.HostID = strings.TrimSpace(in.HostID)
	in.SessionID = strings.TrimSpace(in.SessionID)
	in.HostName = strings.TrimSpace(in.HostName)
	in.Cwd = strings.TrimSpace(in.Cwd)
	in.Title = strings.TrimSpace(in.Title)
	if in.HostID == "" || in.SessionID == "" {
		return GuestSession{}, false
	}
	if in.AddedAt <= 0 {
		in.AddedAt = now
	}
	return in, true
}

// CreateGuestToken 新建一条令牌并立即落盘。
func (h *Hub) CreateGuestToken(label string, expiresAt int64, sessions []GuestSession) (GuestToken, error) {
	now := time.Now()
	items := make([]GuestSession, 0, len(sessions))
	for _, in := range sessions {
		if s, ok := sanitizeGuestSession(in, now.Unix()); ok {
			items = append(items, s)
		}
	}
	g := GuestToken{
		ID:        newGuestID(),
		Token:     newGuestToken(),
		Label:     strings.TrimSpace(label),
		CreatedAt: now.Unix(),
		ExpiresAt: expiresAt,
		Sessions:  items,
	}
	if g.Label == "" {
		g.Label = "访客令牌"
	}
	h.mu.Lock()
	// ID 极小概率碰撞：撞了就换一个，绝不让两条记录共用一个 id。
	for h.guestIDTakenLocked(g.ID) {
		g.ID = newGuestID()
	}
	h.guests = append(h.guests, g)
	h.mu.Unlock()
	h.persistGuestsNow()
	return cloneGuestToken(g), nil
}

func (h *Hub) guestIDTakenLocked(id string) bool {
	for _, g := range h.guests {
		if g.ID == id {
			return true
		}
	}
	return false
}

// UpdateGuestToken 改标签 / 到期 / 吊销。指针为 nil 的字段不动。
func (h *Hub) UpdateGuestToken(id string, label *string, expiresAt *int64, revoked *bool) (GuestToken, error) {
	h.mu.Lock()
	var hit *GuestToken
	for i := range h.guests {
		if h.guests[i].ID == id {
			hit = &h.guests[i]
			break
		}
	}
	if hit == nil {
		h.mu.Unlock()
		return GuestToken{}, ErrGuestUnknown
	}
	if label != nil {
		hit.Label = strings.TrimSpace(*label)
		if hit.Label == "" {
			hit.Label = "访客令牌"
		}
	}
	expiryChanged := expiresAt != nil && *expiresAt != hit.ExpiresAt
	wasActive := hit.Active(time.Now())
	if expiresAt != nil {
		hit.ExpiresAt = *expiresAt
	}
	if revoked != nil {
		hit.Revoked = *revoked
	}
	out := cloneGuestToken(*hit)
	// Any revocation or expiry change invalidates the live page's snapshot.
	// Dropping the socket forces re-authentication and a fresh whitelist
	// instead of leaving an expired/revoked token reading events.
	drop := wasActive && (out.Revoked || expiryChanged || out.Expired(time.Now()))
	h.mu.Unlock()
	h.persistGuestsNow()
	if drop {
		h.DropGuestSubscribers(id)
	}
	return out, nil
}

// DeleteGuestToken 彻底删除一条令牌。
func (h *Hub) DeleteGuestToken(id string) error {
	h.mu.Lock()
	idx := -1
	for i := range h.guests {
		if h.guests[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		h.mu.Unlock()
		return ErrGuestUnknown
	}
	h.guests = append(h.guests[:idx], h.guests[idx+1:]...)
	h.mu.Unlock()
	h.persistGuestsNow()
	h.DropGuestSubscribers(id)
	return nil
}

// AddGuestSessions 把会话加入白名单；同一 (hostId, sessionId) 已存在时
// 原位更新快照字段（标题 / cwd 可能刚变），不产生重复行。
func (h *Hub) AddGuestSessions(id string, items []GuestSession) (GuestToken, error) {
	now := time.Now()
	h.mu.Lock()
	var hit *GuestToken
	for i := range h.guests {
		if h.guests[i].ID == id {
			hit = &h.guests[i]
			break
		}
	}
	if hit == nil {
		h.mu.Unlock()
		return GuestToken{}, ErrGuestUnknown
	}
	for _, in := range items {
		s, ok := sanitizeGuestSession(in, now.Unix())
		if !ok {
			continue
		}
		replaced := false
		for j := range hit.Sessions {
			if hit.Sessions[j].HostID == s.HostID && hit.Sessions[j].SessionID == s.SessionID {
				// 保留首次加入时间；快照字段按本次内容刷新。
				if s.AddedAt == now.Unix() && hit.Sessions[j].AddedAt > 0 {
					s.AddedAt = hit.Sessions[j].AddedAt
				}
				if s.HostName == "" {
					s.HostName = hit.Sessions[j].HostName
				}
				if s.Title == "" {
					s.Title = hit.Sessions[j].Title
				}
				if s.Cwd == "" {
					s.Cwd = hit.Sessions[j].Cwd
				}
				hit.Sessions[j] = s
				replaced = true
				break
			}
		}
		if !replaced {
			hit.Sessions = append(hit.Sessions, s)
		}
	}
	out := cloneGuestToken(*hit)
	h.mu.Unlock()
	h.persistGuestsNow()
	return out, nil
}

// GuestSessionRef 是 remove 的定位键。
type GuestSessionRef struct {
	HostID    string `json:"hostId"`
	SessionID string `json:"sessionId"`
}

// RemoveGuestSessions 按 (hostId, sessionId) 精确移除白名单条目。
func (h *Hub) RemoveGuestSessions(id string, refs []GuestSessionRef) (GuestToken, error) {
	drop := make(map[string]bool, len(refs))
	for _, r := range refs {
		if r.HostID == "" || r.SessionID == "" {
			continue
		}
		drop[r.HostID+"\x00"+r.SessionID] = true
	}
	h.mu.Lock()
	var hit *GuestToken
	for i := range h.guests {
		if h.guests[i].ID == id {
			hit = &h.guests[i]
			break
		}
	}
	if hit == nil {
		h.mu.Unlock()
		return GuestToken{}, ErrGuestUnknown
	}
	kept := hit.Sessions[:0]
	for _, s := range hit.Sessions {
		if drop[s.HostID+"\x00"+s.SessionID] {
			continue
		}
		kept = append(kept, s)
	}
	hit.Sessions = kept
	out := cloneGuestToken(*hit)
	h.mu.Unlock()
	h.persistGuestsNow()
	// A live guest subscriber copied this whitelist at registration time.
	// Close it so a removed session cannot keep streaming until the tab
	// happens to reconnect and fetch a new access-role snapshot.
	h.DropGuestSubscribers(id)
	return out, nil
}

// ReplaceGuestSessionSnapshot 回填单条会话的 title/hostName/cwd 与 stale
// 标记（refresh 用）。
func (h *Hub) ReplaceGuestSessionSnapshot(id string, items []GuestSession) (GuestToken, error) {
	h.mu.Lock()
	var hit *GuestToken
	for i := range h.guests {
		if h.guests[i].ID == id {
			hit = &h.guests[i]
			break
		}
	}
	if hit == nil {
		h.mu.Unlock()
		return GuestToken{}, ErrGuestUnknown
	}
	byKey := make(map[string]GuestSession, len(items))
	for _, s := range items {
		byKey[s.HostID+"\x00"+s.SessionID] = s
	}
	for i := range hit.Sessions {
		cur := &hit.Sessions[i]
		if next, ok := byKey[cur.HostID+"\x00"+cur.SessionID]; ok {
			cur.Title = next.Title
			cur.HostName = next.HostName
			cur.Cwd = next.Cwd
			cur.Stale = next.Stale
		}
	}
	out := cloneGuestToken(*hit)
	h.mu.Unlock()
	h.persistGuestsNow()
	return out, nil
}

// GuestHostIDs 返回某条令牌白名单涉及到的 host id（去重）。
func GuestHostIDs(g GuestToken) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range g.Sessions {
		if s.HostID == "" || seen[s.HostID] {
			continue
		}
		seen[s.HostID] = true
		out = append(out, s.HostID)
	}
	return out
}

// GuestDefaultHost 是令牌的第一个 host（中继 request 不带 ?host= 时的落点）。
func GuestDefaultHost(g GuestToken) string {
	for _, s := range g.Sessions {
		if s.HostID != "" {
			return s.HostID
		}
	}
	return ""
}

// GuestSessionFor 在一台 host 的白名单里定位会话：
//   - 请求给的 sessionId 在白名单里 → 用它；
//   - 否则（未提供或越界）→ 该 host 下白名单的第一条；
//   - 该 host 没有任何白名单条目 → ("", "")，调用方按 403 处理。
func GuestSessionFor(g GuestToken, hostID, sessionID string) (string, string) {
	var first *GuestSession
	for i := range g.Sessions {
		s := &g.Sessions[i]
		if s.HostID != hostID {
			continue
		}
		if first == nil {
			first = s
		}
		if s.SessionID == sessionID && sessionID != "" {
			return s.SessionID, s.Cwd
		}
	}
	if first == nil {
		return "", ""
	}
	return first.SessionID, first.Cwd
}

// GuestAllowsHost 报告 hostID 是否在该令牌的白名单里。
func GuestAllowsHost(g GuestToken, hostID string) bool {
	for _, s := range g.Sessions {
		if s.HostID == hostID {
			return true
		}
	}
	return false
}

// GuestAllowsSession 报告 (hostID, sessionID) 是否在白名单里。
func GuestAllowsSession(g GuestToken, hostID, sessionID string) bool {
	for _, s := range g.Sessions {
		if s.HostID == hostID && s.SessionID == sessionID {
			return true
		}
	}
	return false
}

// GuestSessionKey 是事件过滤用的复合键。
func GuestSessionKey(hostID, sessionID string) string {
	return hostID + "\x00" + sessionID
}

// splitGuestSessionKey 是 GuestSessionKey 的逆运算（查看会话集合按 host
// 归组时用）。不含分隔符的键按「无 host」处理。
func splitGuestSessionKey(key string) (hostID, sessionID string, ok bool) {
	host, sid, found := strings.Cut(key, "\x00")
	if !found {
		return "", "", false
	}
	return host, sid, true
}

// GuestDataDir 便于测试/文档引用（与 hub.json 同级）。
func GuestDataDir(h *Hub) string {
	if h.guestsFile == "" {
		return ""
	}
	return filepath.Dir(h.guestsFile)
}
