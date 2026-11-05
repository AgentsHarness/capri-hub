package hub

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"sort"
	"strings"
	"time"
)

// 用户令牌（users.json，与 hub.json 同级、0600 权限）。
//
// 管理员创建用户时只拿到一次明文 token；hub 只保存 SHA-256 哈希，所以管理
// 界面之后无法再查看或复制别人的 token，只能重置出新 token 或删除用户。
// 用户可以用当前 token 登录后自行更换 token。
//
// 一个用户 = 一个独立的 host 归属域。host 在配对时记录 ownerID，浏览器按
// token 解析出的用户身份只能看到 ownerID 与自己一致的 host。
const usersFileVersion = 1

// MaxUsers caps the user table so unbounded user creation cannot grow the
// hub process without a bound.
const MaxUsers = 256

var (
	// ErrUserUnknown: 用户 id 不存在。
	ErrUserUnknown = errors.New("用户不存在")
	// ErrUserLimit: 用户数量达到上限。
	ErrUserLimit = errors.New("已达用户数量上限")
	// ErrUserTokenWeak: 用户提供的 token 太短或包含空白。
	ErrUserTokenWeak = errors.New("token 至少需要 16 个字符，且不能包含空白")
	// ErrUserTokenTaken: the token hash already belongs to another account.
	ErrUserTokenTaken = errors.New("token 已被其他用户使用")
)

// User is one browser-facing account. TokenHash is the only credential
// material persisted; the plaintext token exists only in the create/reset
// response.
type User struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	TokenHash  string `json:"tokenHash"`
	CreatedAt  int64  `json:"createdAt"`
	LastUsedAt int64  `json:"lastUsedAt,omitempty"`
}

type userFileDoc struct {
	Version int    `json:"version"`
	Users   []User `json:"users"`
}

// userPairCode is one live per-user pairing code. Codes live in memory only
// (the same lifetime model as the root code printed at startup).
type userPairCode struct {
	ownerID string
	expires time.Time
}

// ── 持久化 ────────────────────────────────────────────────────────────

func (h *Hub) loadUsers() {
	b, err := os.ReadFile(h.usersFile)
	if err != nil {
		return
	}
	var doc userFileDoc
	if json.Unmarshal(b, &doc) != nil {
		log.Printf("[capri-hub] users: ignoring unreadable %s", h.usersFile)
		return
	}
	h.users = make([]User, 0, len(doc.Users))
	for _, u := range doc.Users {
		if u.ID == "" || u.TokenHash == "" {
			continue
		}
		h.users = append(h.users, u)
	}
}

// usersPayloadLocked serializes the current table (caller holds h.mu).
func (h *Hub) usersPayloadLocked() ([]byte, bool) {
	if h.usersFile == "" {
		return nil, false
	}
	b, err := json.Marshal(userFileDoc{Version: usersFileVersion, Users: h.users})
	if err != nil {
		return nil, false
	}
	return b, true
}

// persistUsersNow snapshots and writes users.json. The lock order mirrors
// guests.go: userPersistMu → h.mu, never the reverse.
func (h *Hub) persistUsersNow() {
	h.userPersistMu.Lock()
	defer h.userPersistMu.Unlock()
	h.mu.Lock()
	payload, ok := h.usersPayloadLocked()
	if ok {
		h.userPersistedAt = time.Now()
	}
	h.mu.Unlock()
	if ok {
		h.persistUsers(payload)
	}
}

func (h *Hub) persistUsers(payload []byte) {
	if len(payload) == 0 {
		return
	}
	if err := writeFileAtomic(h.usersFile, payload); err != nil {
		log.Printf("[capri-hub] users persist: %v", err)
	}
}

func cloneUser(u User) User { return u }

func cloneUsers(us []User) []User {
	out := make([]User, len(us))
	copy(out, us)
	return out
}

// ── token helpers ─────────────────────────────────────────────────────

func newUserID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return "u_" + hex.EncodeToString(b[:])[:6]
}

// newUserToken generates a 256-bit bearer token. It is returned to the
// caller once; only its hash is stored.
func newUserToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return "u_" + base64.RawURLEncoding.EncodeToString(b[:])
}

func hashUserToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// normalizeUserToken validates a user-supplied token. Generated tokens are
// longer; requiring 16 characters keeps hand-set tokens out of the
// trivially guessable range while staying copy-paste friendly.
func normalizeUserToken(token string) (string, error) {
	token = strings.TrimSpace(token)
	if len(token) < 16 || len(token) > 256 {
		return "", ErrUserTokenWeak
	}
	if strings.ContainsAny(token, " \t\r\n") {
		return "", ErrUserTokenWeak
	}
	return token, nil
}

// ── 查询 ──────────────────────────────────────────────────────────────

// Users returns a copy of every user record (without token plaintext, which
// the hub does not retain). Sorted by creation time then id.
func (h *Hub) Users() []User {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := cloneUsers(h.users)
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt < out[j].CreatedAt
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// UserByID returns one user record.
func (h *Hub) UserByID(id string) (User, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, u := range h.users {
		if u.ID == id {
			return cloneUser(u), true
		}
	}
	return User{}, false
}

// UserByToken resolves a bearer token by hash. LastUsedAt is refreshed at
// most once a minute, mirroring GuestByToken, so frequent browser requests
// do not rewrite users.json on every call.
func (h *Hub) UserByToken(token string) (User, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return User{}, false
	}
	hash := hashUserToken(token)
	now := time.Now()
	h.mu.Lock()
	var hit *User
	for i := range h.users {
		if h.users[i].TokenHash == hash {
			hit = &h.users[i]
			break
		}
	}
	if hit == nil {
		h.mu.Unlock()
		return User{}, false
	}
	hit.LastUsedAt = now.Unix()
	due := now.Sub(h.userPersistedAt) >= time.Minute
	out := cloneUser(*hit)
	h.mu.Unlock()
	if due {
		h.persistUsersNow()
	}
	return out, true
}

// ── 写操作 ────────────────────────────────────────────────────────────

// CreateUser creates an account and returns the plaintext token exactly
// once. The token is not stored in memory or on disk after this call.
func (h *Hub) CreateUser(label string) (User, string, error) {
	label = strings.TrimSpace(label)
	if label == "" {
		label = "用户"
	}
	h.mu.Lock()
	if len(h.users) >= MaxUsers {
		h.mu.Unlock()
		return User{}, "", ErrUserLimit
	}
	var token string
	for {
		token = newUserToken()
		if !h.tokenHashTakenLocked(hashUserToken(token), "") {
			break
		}
	}
	u := User{
		ID:        newUserID(),
		Label:     label,
		TokenHash: hashUserToken(token),
		CreatedAt: time.Now().Unix(),
	}
	for h.userIDTakenLocked(u.ID) {
		u.ID = newUserID()
	}
	h.users = append(h.users, u)
	h.mu.Unlock()
	h.persistUsersNow()
	return cloneUser(u), token, nil
}

func (h *Hub) userIDTakenLocked(id string) bool {
	for _, u := range h.users {
		if u.ID == id {
			return true
		}
	}
	return false
}

func (h *Hub) userExistsLocked(id string) bool {
	for _, u := range h.users {
		if u.ID == id {
			return true
		}
	}
	return false
}

// tokenHashTakenLocked reports whether hash already belongs to a different
// account. exceptID is the account being updated ("" when creating).
func (h *Hub) tokenHashTakenLocked(hash, exceptID string) bool {
	for _, u := range h.users {
		if u.ID != exceptID && u.TokenHash == hash {
			return true
		}
	}
	return false
}

// ResetUserToken generates a new random token for id, invalidating the old
// one. The new plaintext is returned once.
func (h *Hub) ResetUserToken(id string) (User, string, error) {
	h.mu.Lock()
	var hit *User
	for i := range h.users {
		if h.users[i].ID == id {
			hit = &h.users[i]
			break
		}
	}
	if hit == nil {
		h.mu.Unlock()
		return User{}, "", ErrUserUnknown
	}
	var token string
	for {
		token = newUserToken()
		if !h.tokenHashTakenLocked(hashUserToken(token), id) {
			break
		}
	}
	hit.TokenHash = hashUserToken(token)
	out := cloneUser(*hit)
	h.mu.Unlock()
	h.persistUsersNow()
	return out, token, nil
}

// SetUserToken lets a user replace their own token with a caller-supplied
// value. The previous token stops working immediately.
func (h *Hub) SetUserToken(id, token string) (User, error) {
	token, err := normalizeUserToken(token)
	if err != nil {
		return User{}, err
	}
	h.mu.Lock()
	var hit *User
	for i := range h.users {
		if h.users[i].ID == id {
			hit = &h.users[i]
			break
		}
	}
	if hit == nil {
		h.mu.Unlock()
		return User{}, ErrUserUnknown
	}
	hash := hashUserToken(token)
	if h.tokenHashTakenLocked(hash, id) {
		h.mu.Unlock()
		return User{}, ErrUserTokenTaken
	}
	hit.TokenHash = hash
	out := cloneUser(*hit)
	h.mu.Unlock()
	h.persistUsersNow()
	return out, nil
}

// DeleteUser removes the account record. Callers must unpair the user's
// hosts first (the HTTP layer does this through Hub.Unpair) so no orphan
// host keeps a live credential.
func (h *Hub) DeleteUser(id string) error {
	h.mu.Lock()
	idx := -1
	for i := range h.users {
		if h.users[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		h.mu.Unlock()
		return ErrUserUnknown
	}
	h.users = append(h.users[:idx], h.users[idx+1:]...)
	delete(h.userPrefs, id)
	if code := h.userPairCodeByOwner[id]; code != "" {
		delete(h.userPairCodes, code)
		delete(h.userPairCodeByOwner, id)
	}
	h.mu.Unlock()
	h.persistUsersNow()
	h.persistUserPrefsNow()
	h.DropUserSubscribers(id)
	return nil
}
