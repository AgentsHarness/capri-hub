package hub

import (
	"sort"
	"time"
)

// ── registry / browsers ───────────────────────────────────────────────

// ListHosts returns the registry, online hosts first, most recently seen
// first.
func (h *Hub) ListHosts() []HostInfo {
	return h.listHostsLocked("")
}

// ListHostsFor returns only the hosts owned by ownerID. The deployment admin
// ("root") sees every host through ListHosts; this is the user-scoped view.
func (h *Hub) ListHostsFor(ownerID string) []HostInfo {
	return h.listHostsLocked(hostOwnerOrDefault(ownerID))
}

func (h *Hub) listHostsLocked(ownerID string) []HostInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]HostInfo, 0, len(h.hosts))
	for _, hs := range h.hosts {
		if ownerID != "" && hostOwnerOrDefault(hs.ownerID) != ownerID {
			continue
		}
		info := hs.info
		info.OwnerID = hostOwnerOrDefault(info.OwnerID)
		// Age is computed here, not in the browser: LastSeen comes from this
		// process's clock and is meaningless against a client's clock.
		if !info.LastSeen.IsZero() {
			if age := time.Since(info.LastSeen); age > 0 {
				info.LastSeenAgeMs = age.Milliseconds()
			}
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Online != out[j].Online {
			return out[i].Online
		}
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].HostID < out[j].HostID
	})
	return out
}

// HostOwner returns the user id that paired hostID.
func (h *Hub) HostOwner(hostID string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	hs := h.hosts[hostID]
	if hs == nil {
		return "", false
	}
	return hostOwnerOrDefault(hs.ownerID), true
}

// HostIDsForUser returns every host id owned by ownerID.
func (h *Hub) HostIDsForUser(ownerID string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, 0)
	for id, hs := range h.hosts {
		if hostOwnerOrDefault(hs.ownerID) == ownerID {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// HostCountForUser counts hosts owned by ownerID.
func (h *Hub) HostCountForUser(ownerID string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, hs := range h.hosts {
		if hostOwnerOrDefault(hs.ownerID) == ownerID {
			n++
		}
	}
	return n
}

// DefaultHostID picks the host for requests that don't name one: the most
// recently seen online host, else the most recently seen one overall.
func (h *Hub) DefaultHostID() string {
	return h.defaultHostIDLocked("")
}

// DefaultHostIDFor is DefaultHostID within one user's host set.
func (h *Hub) DefaultHostIDFor(ownerID string) string {
	return h.defaultHostIDLocked(hostOwnerOrDefault(ownerID))
}

func (h *Hub) defaultHostIDLocked(ownerID string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	eligible := func(hs *hostState) bool {
		return ownerID == "" || hostOwnerOrDefault(hs.ownerID) == ownerID
	}
	var best string
	for _, hs := range h.hosts {
		if !eligible(hs) {
			continue
		}
		if hs.info.Online {
			if best == "" || hs.info.LastSeen.After(h.hosts[best].info.LastSeen) {
				best = hs.info.HostID
			}
		}
	}
	if best != "" {
		return best
	}
	for _, hs := range h.hosts {
		if !eligible(hs) {
			continue
		}
		if best == "" || hs.info.LastSeen.After(h.hosts[best].info.LastSeen) {
			best = hs.info.HostID
		}
	}
	return best
}

// Subscribe returns a buffered channel of relayed events; call the
// returned func to unsubscribe.
//
// Subscribe/unsubscribe notify connected hosts of the browser subscriber
// count so they can pause event upload when nobody is listening (the
// heartbeat and the registry it feeds keep running on the host side).
func (h *Hub) Subscribe() (ch chan Event, unsubscribe func()) {
	ch, unsub, _ := h.TrySubscribe(0) // 0 = unlimited
	return ch, unsub
}

// feDropStats is the hub-level aggregate of the per-subscriber drop path
// (see feSubscriber.noteDrop / pump). Atomics because both are touched on
// the fan-out/pump hot path, where a lock is forbidden.
