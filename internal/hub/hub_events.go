package hub

import (
	"bytes"
	"encoding/json"
	"sort"
)

// ── raw (pre-encoded) event fast path ─────────────────────────────────
//
// Events arriving over the wire used to be fully decoded into Event maps
// (one map + one allocation per leaf value per event — chunk storms burn
// most of the hub's CPU there) and then re-encoded per FE on fan-out. The
// raw path instead keeps the event body as json.RawMessage end-to-end:
// only the fields the hub itself needs (seq/type/ready) are shallow
// parsed, and the FE-bound wire bytes are produced once by splicing the
// hub's hostId/hostName tags into the original bytes.
//
// rawWireKey is the reserved Event key under which the canonical wire
// bytes travel through the fan-out channel and the gap-pull buffer. An
// Event carrying it is opaque: consumers must serialize it via
// MarshalEvent (which returns the bytes verbatim) instead of
// json.Marshal. The key starts with NUL so it can never collide with a
// wire field name. Alongside the raw bytes the map carries the few
// shallow fields hub/FE code inspects: type, seq, hostId, hostName.
const rawWireKey = "\x00wire"

// MarshalEvent serializes one event to its canonical wire bytes: the
// pre-encoded bytes verbatim for raw-path events, a plain marshal for
// hub-level events (hosts_changed, prefs_changed, resync).
func MarshalEvent(ev Event) ([]byte, error) {
	if raw, ok := ev[rawWireKey].(json.RawMessage); ok {
		return raw, nil
	}
	return json.Marshal(ev)
}

// rawEventMeta is the shallow header the hub needs from every raw event.
type rawEventMeta struct {
	Seq  uint64 `json:"seq"`
	Type string `json:"type"`
	// SessionID is lifted for the guest whitelist filter: raw events keep
	// their original bytes (see rawWireKey), so the map itself has no
	// sessionId member to filter on.
	SessionID string `json:"sessionId"`
	// Only tool_call_update has a payload member here; every other event
	// type leaves it zero. Read for the drop-tier decision (criticalEvent) —
	// the alternative is decoding the body per subscriber.
	ToolCallUpdate struct {
		Status string `json:"status"`
	} `json:"toolCallUpdate"`
}

// spawnMeta is decoded only for subagent_spawned frames (see
// noteSpawnFromRaw): carrying `update` in rawEventMeta would make every raw
// event pay a full decode of its payload, including tool outputs.
type spawnMeta struct {
	SessionID string `json:"sessionId"`
	Update    struct {
		ChildSessionID string `json:"child_session_id"`
		SubagentID     string `json:"subagent_id"`
	} `json:"update"`
}

// noteSpawnFromRaw records the child/parent relation of one raw
// subagent_spawned frame (see noteGuestChild).
func (h *Hub) noteSpawnFromRaw(hostID string, raw json.RawMessage) {
	var m spawnMeta
	if json.Unmarshal(raw, &m) != nil {
		return
	}
	h.noteGuestChild(hostID, m.SessionID, m.Update.ChildSessionID, m.Update.SubagentID)
}

// rawSessionKey carries the shallow-parsed sessionId of a raw event through
// the fan-out path without touching the wire bytes (MarshalEvent returns the
// original bytes verbatim, so this key never reaches a browser).
const rawSessionKey = "\x00sessionId"

// eventSessionID reads an event's top-level sessionId (map path or the
// lifted raw-path copy).
func eventSessionID(ev Event) string {
	if s, ok := ev["sessionId"].(string); ok && s != "" {
		return s
	}
	s, _ := ev[rawSessionKey].(string)
	return s
}

// ── 子代理子会话台账 ──────────────────────────────────────────────────
//
// 访客白名单按「host + session」授权。子代理是独立会话，事件与
// updates.jsonl 都挂在子会话 id 下，白名单里通常只有父会话。这里记录
// subagent_spawned 给出的父子关系，让白名单父会话的访客能读到该子代理的
// 时间线（WS 事件 + /api/session-updates），只跟一层：子代理再派出的子代理
// 不自动继承，授权范围保持与管理员分享的那条会话一致。

// guestChildCap bounds the relation table (FIFO). Spawns are rare; the cap
// exists so a long-lived hub cannot grow without limit.
const guestChildCap = 4096

// noteGuestChild records that childSID (and its subagent id, when it differs)
// belongs to parentSID on hostID.
func (h *Hub) noteGuestChild(hostID, parentSID, childSID, subagentID string) {
	if hostID == "" || parentSID == "" || childSID == "" || parentSID == childSID {
		return
	}
	h.mu.Lock()
	next := make(map[string]string, guestChildCap)
	if cur := h.guestChildren.Load(); cur != nil {
		for k, v := range *cur {
			next[k] = v
		}
	}
	ids := []string{childSID}
	if subagentID != "" && subagentID != childSID {
		ids = append(ids, subagentID)
	}
	for _, id := range ids {
		key := GuestSessionKey(hostID, id)
		if _, ok := next[key]; ok {
			continue
		}
		next[key] = parentSID
		h.guestChildKeys = append(h.guestChildKeys, key)
	}
	if over := len(h.guestChildKeys) - guestChildCap; over > 0 {
		for _, key := range h.guestChildKeys[:over] {
			delete(next, key)
		}
		h.guestChildKeys = append([]string(nil), h.guestChildKeys[over:]...)
	}
	h.guestChildren.Store(&next)
	h.mu.Unlock()
}

// guestParentOf returns the parent session recorded for (host, session), or "".
// Lock-free: readers get the whole map snapshot.
func (h *Hub) guestParentOf(hostID, sessionID string) string {
	cur := h.guestChildren.Load()
	if cur == nil || sessionID == "" {
		return ""
	}
	return (*cur)[GuestSessionKey(hostID, sessionID)]
}

// GuestChildAllowed reports whether sessionID on hostID is a subagent child of
// a session the token was granted. The whitelist itself stays read-only: this
// only widens the READ scope to the child transcripts of shared sessions.
func (h *Hub) GuestChildAllowed(g GuestToken, hostID, sessionID string) bool {
	parent := h.guestParentOf(hostID, sessionID)
	if parent == "" {
		return false
	}
	return GuestAllowsSession(g, hostID, parent)
}

// GuestParentOf is GuestChildAllowed's building block: the parent session
// recorded for a child, "" when unknown.
func (h *Hub) GuestParentOf(hostID, sessionID string) string {
	return h.guestParentOf(hostID, sessionID)
}

// NoteHistoryChildren learns parent/child links from a session history page
// relayed to a guest. Live spawns fill the same table from
// subagent_spawned events; this covers subagents that spawned before the
// guest's page opened (or before a hub restart), which is exactly when the
// timeline is fetched from disk. fallbackParent is the session the page was
// requested for (envelopes of older hosts may omit params.sessionId).
//
// Cheap by construction: no "subagent_spawned" substring ⇒ nothing is
// unmarshalled.
func (h *Hub) NoteHistoryChildren(hostID, fallbackParent string, body []byte) {
	if hostID == "" || !bytes.Contains(body, []byte(`subagent_spawned`)) {
		return
	}
	var page struct {
		Updates []struct {
			Params struct {
				SessionID string `json:"sessionId"`
				Update    struct {
					SessionUpdate  string `json:"sessionUpdate"`
					ChildSessionID string `json:"child_session_id"`
					SubagentID     string `json:"subagent_id"`
				} `json:"update"`
			} `json:"params"`
		} `json:"updates"`
	}
	if json.Unmarshal(body, &page) != nil {
		return
	}
	for _, u := range page.Updates {
		if u.Params.Update.SessionUpdate != "subagent_spawned" {
			continue
		}
		parent := u.Params.SessionID
		if parent == "" {
			parent = fallbackParent
		}
		h.noteGuestChild(hostID, parent, u.Params.Update.ChildSessionID, u.Params.Update.SubagentID)
	}
}

// NoteRunningSubagents learns parent/child links from a subagent registry
// response relayed to a guest (`x.ai/subagent/list_running` →
// {ok, result:{subagents:[{subagentId, childSessionId, parentSessionId}]}}).
// Spawn events and history pages feed the same table; the registry is the
// source that still knows a child whose spawn envelope is missing from the
// history page the guest happened to load.
func (h *Hub) NoteRunningSubagents(hostID, fallbackParent string, body []byte) {
	if hostID == "" || !bytes.Contains(body, []byte(`subagents`)) {
		return
	}
	var doc struct {
		Result struct {
			Subagents []struct {
				SubagentID      string `json:"subagentId"`
				ChildSessionID  string `json:"childSessionId"`
				ParentSessionID string `json:"parentSessionId"`
			} `json:"subagents"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return
	}
	for _, row := range doc.Result.Subagents {
		parent := row.ParentSessionID
		if parent == "" {
			parent = fallbackParent
		}
		h.noteGuestChild(hostID, parent, row.ChildSessionID, row.SubagentID)
	}
}

// spliceRawEvent builds the FE-bound wire bytes for one raw event by
// appending the hub's tags before the closing brace of the original
// object. Appending (rather than prepending) means duplicate keys resolve
// in the hub's favor — hostId / hostName always win (encoding/json keeps
// the LAST occurrence). Returns nil when raw is not a JSON object (caller
// skips).
func spliceRawEvent(raw, idJSON, nameJSON []byte) json.RawMessage {
	r := bytes.TrimRight(raw, " \t\r\n")
	if len(r) < 2 || r[0] != '{' || r[len(r)-1] != '}' {
		return nil
	}
	out := make([]byte, 0, len(r)+len(idJSON)+len(nameJSON)+48)
	out = append(out, r[:len(r)-1]...)
	if len(out) > 1 { // non-empty object: separate from existing members
		out = append(out, ',')
	}
	out = append(out, `"hostId":`...)
	out = append(out, idJSON...)
	out = append(out, `,"hostName":`...)
	out = append(out, nameJSON...)
	out = append(out, '}')
	return json.RawMessage(out)
}

// ingestRawEvents applies one contiguous run of host events in their original
// wire form: each body stays json.RawMessage, only the fields the hub needs are
// shallow-parsed, and the FE-bound bytes are spliced once instead of
// decode-map + re-encode per subscriber.
//
// The receiver has already validated that the run is gapless and in order
// (wire.ValidateEvents), so seqs are used verbatim and nothing here may skip
// one. Returns false when s is no longer the host's session: its epoch was
// superseded while the frame was parked, and the events must not be applied to
// the new epoch's buffer.
func (h *Hub) ingestRawEvents(s *session, raws []json.RawMessage) bool {
	h.mu.Lock()
	hs := h.hosts[s.hostID]
	if hs == nil || hs.session != s {
		h.mu.Unlock()
		return false
	}
	hostName := hs.info.HostName
	h.mu.Unlock()

	idJSON, _ := json.Marshal(s.hostID)
	nameJSON, _ := json.Marshal(hostName)
	for _, raw := range raws {
		r := bytes.TrimRight(raw, " \t\r\n")
		if len(r) < 2 || r[0] != '{' || r[len(r)-1] != '}' {
			Verbosef("[capri-hub] host %s non-object event skipped", s.hostID)
			continue
		}
		var meta rawEventMeta
		if err := json.Unmarshal(r, &meta); err != nil {
			continue
		}
		wireBytes := spliceRawEvent(r, idJSON, nameJSON)
		if wireBytes == nil {
			Verbosef("[capri-hub] host %s non-object event skipped", s.hostID)
			continue
		}
		ev := Event{
			rawWireKey: wireBytes,
			"type":     meta.Type,
			"seq":      meta.Seq,
			"hostId":   s.hostID,
			"hostName": hostName,
		}
		if meta.SessionID != "" {
			ev[rawSessionKey] = meta.SessionID
		}
		switch meta.ToolCallUpdate.Status {
		case "completed", "failed":
			ev[terminalToolUpdateKey] = true
		}
		hs.mu.Lock()
		if hs.epoch.Load() != s.epoch {
			hs.mu.Unlock()
			return false
		}
		hs.bufferEventLocked(s.hostID, ev)
		hs.mu.Unlock()
		// 子代理派发：记下子会话归属，访客才能顺着白名单父会话读到这条
		// 时间线（见 noteGuestChild）。同一事件既带顶层 sessionId（父）也带
		// update 里的 child_session_id（子）。放在入环/扇出之前：该事件本身
		// 是父会话的（白名单直接放行），但紧跟着到达的子会话事件要能命中。
		if meta.Type == "subagent_spawned" {
			h.noteSpawnFromRaw(s.hostID, r)
		}
		// The epoch gate above is released before the enqueue, so an attach
		// may install a new epoch right here. Tagging the item with the epoch
		// it was gated on lets the drain drop it instead of delivering a
		// retired-epoch seq behind the new epoch's reset. Dropping it is safe:
		// the FE rebuilds from host history.
		hs.enqueueFanout(h, s.hostID, ev, s.epoch)
	}
	return true
}

// LastSeq returns the delivery watermark for hostID: the highest N for which
// 1..N all arrived (0 when unknown / nothing seen yet). It is the only number
// a wire field may present as an ack; a higher one would erase the replay
// copies of events the hub never received.
func (h *Hub) LastSeq(hostID string) uint64 {
	h.mu.Lock()
	hs := h.hosts[hostID]
	h.mu.Unlock()
	if hs == nil {
		return 0
	}
	return hs.lastSeq()
}

// SeqByHost returns the per-host delivery watermark (see LastSeq) for the FE
// hello frame, so a browser works on the same gapless coordinate as the hub.
func (h *Hub) SeqByHost() map[string]uint64 {
	return h.seqByHostLocked("")
}

// SeqByHostFor returns seq watermarks for one user's hosts.
func (h *Hub) SeqByHostFor(ownerID string) map[string]uint64 {
	return h.seqByHostLocked(hostOwnerOrDefault(ownerID))
}

func (h *Hub) seqByHostLocked(ownerID string) map[string]uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]uint64, len(h.hosts))
	for id, hs := range h.hosts {
		if ownerID != "" && hostOwnerOrDefault(hs.ownerID) != ownerID {
			continue
		}
		out[id] = hs.upAcked.Load()
	}
	return out
}

// EventsAfter returns buffered events for hostID whose seq > after, in
// ascending order. The returned slice shares storage with the hub buffer;
// callers must not mutate the events.
func (h *Hub) EventsAfter(hostID string, after uint64) []Event {
	h.mu.Lock()
	hs := h.hosts[hostID]
	h.mu.Unlock()
	if hs == nil {
		return nil
	}
	hs.mu.Lock()
	defer hs.mu.Unlock()
	// evBuf is append-only in strictly increasing seq order (appendEvent
	// drops anything <= the watermark), so the cut point can be found by
	// binary search instead of scanning up to evBufHighWater events on
	// every reconnect gap-pull.
	i := sort.Search(len(hs.evBuf), func(i int) bool {
		return evSeq(hs.evBuf[i]) > after
	})
	if i >= len(hs.evBuf) {
		return nil
	}
	out := make([]Event, len(hs.evBuf)-i)
	copy(out, hs.evBuf[i:])
	return out
}
