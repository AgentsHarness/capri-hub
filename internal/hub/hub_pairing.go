package hub

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"github.com/AgentsHarness/capri-hub/wire"
	"log"
	"strings"
	"time"
)

// ── pairing ───────────────────────────────────────────────────────────

// PairingCode returns the current pairing code and its expiry. If the
// code has already expired it is rotated first so callers never see a
// dead code advertised as current.
func (h *Hub) PairingCode() (code string, expiresAt time.Time) {
	return h.ensureFreshPairingCode()
}

func (h *Hub) rotateCode() {
	for {
		code := randomString(codeAlphabet, 6)
		// Root and user codes share one alphabet and Pair resolves the root
		// code first, so a collision would silently steal a user's code.
		if h.userPairCodes != nil {
			if _, exists := h.userPairCodes[code]; exists {
				continue
			}
		}
		h.pairingCode = code
		h.codeExpires = time.Now().Add(PairingCodeTTL)
		return
	}
}

// ensureFreshPairingCode rotates when expired; returns the live code.
func (h *Hub) ensureFreshPairingCode() (code string, expiresAt time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if time.Now().After(h.codeExpires) {
		h.rotateCode()
		log.Printf("[capri-hub] pairing code auto-rotated (expired): %s (expires %s)",
			h.pairingCode, h.codeExpires.Format("15:04:05"))
	}
	return h.pairingCode, h.codeExpires
}

// RotatePairingCode replaces the pairing code (old one stops working).
func (h *Hub) RotatePairingCode() (code string, expiresAt time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.rotateCode()
	log.Printf("[capri-hub] pairing code rotated: %s (expires %s)", h.pairingCode, h.codeExpires.Format("15:04:05"))
	return h.pairingCode, h.codeExpires
}

// StartPairingCodeMaintainer periodically rotates expired pairing codes
// until ctx is cancelled. Safe to call once per Hub.
func (h *Hub) StartPairingCodeMaintainer(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(pairingCodeCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.ensureFreshPairingCode()
			}
		}
	}()
}

// Pair exchanges a pairing code for a host token. Re-pairing an existing
// hostId revokes every previous token for that host (not only hs.token),
// so a restart that left multiple map entries cannot keep old credentials
// alive. State is snapshotted under the lock but written to disk outside
// it, so flaky storage never stalls the hub.
//
// Optional port (variadic): when the first extra arg is in 1..65535 it is
// stored as HostInfo.Port (local HTTP listen port for FE localhost probe).
// Omitted or out of range leaves any existing Port untouched on re-pair.
func (h *Hub) Pair(code, hostID, hostName string, port ...int) (string, error) {
	token, _, err := h.PairAs("root", code, hostID, hostName, port...)
	return token, err
}

// PairAs is Pair for a user-owned host. ownerID is "root" for the deployment
// admin or a users.json id. The code must be either the root pairing code
// (for root) or that user's own live pairing code. The returned hostID is
// the actual registry key: if another owner already uses the requested
// hostId, the hub derives a unique suffixed id instead of hijacking it.
func (h *Hub) PairAs(ownerID, code, hostID, hostName string, port ...int) (string, string, error) {
	ownerID = hostOwnerOrDefault(strings.TrimSpace(ownerID))
	listenPort := 0
	if len(port) > 0 {
		listenPort = port[0]
	}
	h.mu.Lock()
	if ownerID == "root" {
		// Constant-time compare: the pairing code is a short-lived secret and
		// POST /api/pair is internet-reachable, so the comparison must not
		// leak how many leading bytes matched. (subtle.ConstantTimeCompare
		// still returns 0 immediately for differing lengths — the code length
		// is fixed public knowledge, so that leak is harmless.)
		if subtle.ConstantTimeCompare([]byte(strings.ToUpper(strings.TrimSpace(code))), []byte(h.pairingCode)) != 1 {
			h.mu.Unlock()
			return "", "", ErrCodeInvalid
		}
		if time.Now().After(h.codeExpires) {
			h.mu.Unlock()
			return "", "", ErrCodeInvalid
		}
	} else {
		entry, ok := h.userPairCodes[strings.ToUpper(strings.TrimSpace(code))]
		if !ok || entry.ownerID != ownerID || time.Now().After(entry.expires) || !h.userExistsLocked(ownerID) {
			h.mu.Unlock()
			return "", "", ErrCodeInvalid
		}
	}
	hostID = strings.TrimSpace(hostID)
	hostName = strings.TrimSpace(hostName)
	if hostID == "" {
		h.mu.Unlock()
		return "", "", errors.New("hostId 不能为空")
	}
	if len(hostID) > maxHostIDLen {
		h.mu.Unlock()
		return "", "", fmt.Errorf("hostId 过长（上限 %d）", maxHostIDLen)
	}
	if len(hostName) > maxHostNameLen {
		h.mu.Unlock()
		return "", "", fmt.Errorf("hostName 过长（上限 %d）", maxHostNameLen)
	}
	actualID := h.resolveHostIDLocked(ownerID, hostID)
	if hs, ok := h.hosts[actualID]; ok {
		// Same owner re-pairing its host: revoke every token for this
		// hostId (covers multi-token legacy after a pre-fix restart load).
		h.revokeTokensForHostLocked(actualID)
		hs.ownerID = ownerID
		hs.info.OwnerID = ownerID
		hs.info.HostName = hostName
		hs.info.LastSeen = time.Now()
		if listenPort > 0 && listenPort <= 65535 {
			hs.info.Port = listenPort
		}
	} else {
		if len(h.hosts) >= MaxHosts {
			h.mu.Unlock()
			return "", "", ErrHostLimit
		}
		info := HostInfo{HostID: actualID, HostName: hostName, OwnerID: ownerID, LastSeen: time.Now()}
		if listenPort > 0 && listenPort <= 65535 {
			info.Port = listenPort
		}
		h.hosts[actualID] = &hostState{info: info, ownerID: ownerID}
	}
	token := randomToken()
	h.tokens[token] = actualID
	h.hosts[actualID].token = token
	// A pairing code is a one-shot credential. Consume it only after the
	// host was created/re-paired successfully, so a failed validation does
	// not burn the operator's code. Root rotates to a fresh deployment-wide
	// code; a user's code is removed until they request a new one.
	if ownerID == "root" {
		h.rotateCode()
	} else {
		codeKey := strings.ToUpper(strings.TrimSpace(code))
		delete(h.userPairCodes, codeKey)
		delete(h.userPairCodeByOwner, ownerID)
	}
	h.mu.Unlock()

	h.persistNow()
	log.Printf("[capri-hub] host paired: %s (%s, owner %s)", actualID, hostName, ownerID)
	return token, actualID, nil
}

// resolveHostIDLocked returns requested when it is free or already belongs
// to ownerID. A hostId owned by another account gets a stable suffix based
// on that account id, so two default "local" installations never collide.
// Caller holds h.mu.
func (h *Hub) resolveHostIDLocked(ownerID, requested string) string {
	hs, taken := h.hosts[requested]
	if !taken || hostOwnerOrDefault(hs.ownerID) == ownerID {
		return requested
	}
	suffix := strings.TrimPrefix(ownerID, "u_")
	if suffix == "" {
		suffix = "root"
	}
	base := requested
	if len(base)+len(suffix)+2 > maxHostIDLen {
		base = base[:maxHostIDLen-len(suffix)-2]
	}
	candidate := base + "-" + suffix
	for i := 2; ; i++ {
		if _, exists := h.hosts[candidate]; !exists {
			return candidate
		}
		suffix = fmt.Sprintf("%s-%d", strings.TrimPrefix(ownerID, "u_"), i)
		if suffix == "" || suffix == "-" {
			suffix = fmt.Sprintf("root-%d", i)
		}
		if len(base)+len(suffix)+2 > maxHostIDLen {
			base = requested[:maxHostIDLen-len(suffix)-2]
		}
		candidate = base + "-" + suffix
	}
}

// UserPairingCode returns the live six-character pairing code for a user,
// creating or rotating it when absent or expired. The root owner uses the
// deployment-wide code printed at startup; users get their own code from the
// FE pair dialog.
func (h *Hub) UserPairingCode(ownerID string) (code string, expiresAt time.Time) {
	ownerID = hostOwnerOrDefault(strings.TrimSpace(ownerID))
	if ownerID == "root" {
		return h.PairingCode()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if cur := h.userPairCodeByOwner[ownerID]; cur != "" {
		if entry, ok := h.userPairCodes[cur]; ok && entry.ownerID == ownerID && now.Before(entry.expires) {
			return cur, entry.expires
		}
	}
	code = h.newUniquePairCodeLocked()
	expiresAt = now.Add(PairingCodeTTL)
	h.userPairCodes[code] = userPairCode{ownerID: ownerID, expires: expiresAt}
	h.userPairCodeByOwner[ownerID] = code
	return code, expiresAt
}

// RotateUserPairingCode invalidates a user's current code and returns a new
// one. Root keeps the existing RotatePairingCode path.
func (h *Hub) RotateUserPairingCode(ownerID string) (code string, expiresAt time.Time) {
	ownerID = hostOwnerOrDefault(strings.TrimSpace(ownerID))
	if ownerID == "root" {
		return h.RotatePairingCode()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if cur := h.userPairCodeByOwner[ownerID]; cur != "" {
		delete(h.userPairCodes, cur)
		delete(h.userPairCodeByOwner, ownerID)
	}
	code = h.newUniquePairCodeLocked()
	expiresAt = time.Now().Add(PairingCodeTTL)
	h.userPairCodes[code] = userPairCode{ownerID: ownerID, expires: expiresAt}
	h.userPairCodeByOwner[ownerID] = code
	return code, expiresAt
}

// newUniquePairCodeLocked returns a code not used by root or any user.
func (h *Hub) newUniquePairCodeLocked() string {
	for {
		code := randomString(codeAlphabet, 6)
		if code == h.pairingCode {
			continue
		}
		if _, exists := h.userPairCodes[code]; exists {
			continue
		}
		return code
	}
}

// OwnerForPairCode resolves a six-character code to its owner without
// consuming it. Expired entries are rejected.
func (h *Hub) OwnerForPairCode(code string) (string, bool) {
	code = strings.ToUpper(strings.TrimSpace(code))
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if code == h.pairingCode && now.Before(h.codeExpires) {
		return "root", true
	}
	entry, ok := h.userPairCodes[code]
	if !ok || now.After(entry.expires) {
		return "", false
	}
	return entry.ownerID, true
}

// Unpair removes a host from the registry: revokes all its tokens, fails
// in-flight relayed requests, drops its stream registration, and persists.
// An active transport is left to close itself (auth is already revoked;
// further events/dispatches for this hostId fail).
func (h *Hub) Unpair(hostID string) error {
	hostID = strings.TrimSpace(hostID)
	h.mu.Lock()
	hs := h.hosts[hostID]
	if hs == nil {
		h.mu.Unlock()
		return ErrHostUnknown
	}
	h.revokeTokensForHostLocked(hostID)
	h.failPendingLocked(hostID)
	if hs.session != nil {
		// The transport is left to unwind on its own; its detach finds the
		// host gone and does nothing.
		hs.session.requestStop(wire.CloseAuth)
		hs.session = nil
	}
	delete(h.hosts, hostID)
	delete(h.relayTombstones, hostID)
	hs.mu.Lock()
	hs.evBuf = nil
	hs.evBufBytes = 0
	hs.mu.Unlock()
	h.broadcast(hostsChanged())
	h.mu.Unlock()

	h.dropSubscribersForHost(hostID)
	h.persistNow()
	log.Printf("[capri-hub] host unpaired: %s", hostID)
	return nil
}

// RenameHost updates a paired host's display name only — no token
// revocation, no connection teardown (unlike re-pairing via /api/pair,
// which would kick the host offline). Broadcasts hosts_changed so
// browsers refresh the registry live.
func (h *Hub) RenameHost(hostID, hostName string) error {
	hostID = strings.TrimSpace(hostID)
	hostName = strings.TrimSpace(hostName)
	if hostID == "" {
		return errors.New("hostId 不能为空")
	}
	if hostName == "" {
		return errors.New("hostName 不能为空")
	}
	if len(hostName) > maxHostNameLen {
		return fmt.Errorf("hostName 过长（上限 %d）", maxHostNameLen)
	}
	h.mu.Lock()
	hs := h.hosts[hostID]
	if hs == nil {
		h.mu.Unlock()
		return ErrHostUnknown
	}
	hs.info.HostName = hostName
	h.broadcast(hostsChanged())
	h.mu.Unlock()

	h.persistNow()
	log.Printf("[capri-hub] host renamed: %s → %s", hostID, hostName)
	return nil
}

// revokeTokensForHostLocked removes every token → hostID mapping and
// clears hostState.token. Caller must hold h.mu.
func (h *Hub) revokeTokensForHostLocked(hostID string) {
	for tok, hid := range h.tokens {
		if hid == hostID {
			delete(h.tokens, tok)
		}
	}
	if hs := h.hosts[hostID]; hs != nil {
		hs.token = ""
	}
}

// HostIDForToken resolves a host token to its hostId.
func (h *Hub) HostIDForToken(token string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	hid, ok := h.tokens[token]
	return hid, ok
}
