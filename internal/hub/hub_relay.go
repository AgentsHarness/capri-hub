package hub

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AgentsHarness/capri-hub/wire"
	"log"
	"sort"
	"time"
)

// ── request relay ─────────────────────────────────────────────────────

// DispatchOptions carries the relay envelope that is not part of the HTTP
// shape. IdemKey/IdemScope let the host execute the same logical write at
// most once across browser retries and reconnects; empty means no key.
type DispatchOptions struct {
	IdemKey   string
	IdemScope string
}

// Dispatch relays a browser request with no idempotency key.
func (h *Hub) Dispatch(ctx context.Context, hostID, method, path string, body json.RawMessage) (RelayResponse, error) {
	return h.DispatchOpts(ctx, hostID, method, path, body, DispatchOptions{})
}

// DispatchOpts relays a browser request to a host and waits for its answer.
//
// ctx is the BROWSER's request context. When it is cancelled (tab closed,
// navigation, mobile network drop) the wait is abandoned and the pending
// slot freed immediately. Without that, an abandoned request pinned a
// goroutine, a pending map entry and a 45-minute timer (RelayTimeout) for
// the full timeout — a flaky client retrying prompts accumulates them until
// the hub runs out of room. Cancelling the WAIT deliberately does NOT
// cancel the host-side work: the prompt keeps running on the agent (that is
// the point of the server-authoritative design) and its output still
// reaches browsers over the event stream.
//
// Delivery is the session's problem: the frame is logged and retransmitted
// until the host's cumulative ack covers it. The request stays pending until
// the host answers, the epoch changes, the detach grace expires, or
// RelayTimeout fires. There is no separate ack deadline that could answer 503
// while the host is still running the request.
func (h *Hub) DispatchOpts(ctx context.Context, hostID, method, path string, body json.RawMessage, opts DispatchOptions) (resp RelayResponse, err error) {
	start := time.Now()
	reqID := fmt.Sprintf("%d", h.nextReq.Add(1))
	h.relayStats.begin()
	log.Printf("[relay] req=%s boot=%d host=%s begin method=%s path=%s body=%dB", reqID, h.hubBoot, hostID, method, path, len(body))
	defer func() {
		status := resp.Status
		if err != nil {
			var relayErr *RelayError
			if errors.As(err, &relayErr) {
				status = relayErr.Status
			} else {
				status = 500
			}
		}
		if status <= 0 {
			status = 200
		}
		duration := time.Since(start)
		log.Printf("[relay] req=%s boot=%d host=%s end status=%d bytes=%d duration_ms=%d err=%v", reqID, h.hubBoot, hostID, status, len(resp.Body), duration.Milliseconds(), err)
		h.relayStats.end(duration, err)
	}()

	// A scope without a key would key the host's store by the empty string,
	// and an out-of-envelope key/scope cannot be encoded into a request frame.
	// Reject both before any host work rather than surfacing a 503 from the
	// frame encoder.
	if opts.IdemKey == "" {
		if opts.IdemScope != "" {
			return RelayResponse{}, &RelayError{Status: 400, Message: "invalid_idempotency_key"}
		}
	} else if err := wire.ValidateIdemKey(opts.IdemKey); err != nil {
		return RelayResponse{}, &RelayError{Status: 400, Message: "invalid_idempotency_key"}
	} else if err := wire.ValidateIdemScope(opts.IdemScope); err != nil {
		return RelayResponse{}, &RelayError{Status: 400, Message: "invalid_idempotency_scope"}
	}

	h.mu.Lock()
	hs := h.hosts[hostID]
	if hs == nil {
		h.mu.Unlock()
		return RelayResponse{}, &RelayError{Status: 404, Message: ErrHostUnknown.Error()}
	}
	sess := hs.session
	if sess == nil {
		h.mu.Unlock()
		return RelayResponse{}, &RelayError{Status: 503, Message: fmt.Sprintf("host %s 当前离线", hostID)}
	}
	// Each in-flight request can buffer up to a full 28MB answer chunked
	// across frames, so an unbounded pending table is an unbounded memory
	// commitment per host. Refuse new work with 429 instead of queueing it:
	// the browser sees a retryable error, existing requests keep running.
	if len(h.pending[hostID]) >= maxPendingRelayPerHost {
		h.mu.Unlock()
		return RelayResponse{}, &RelayError{Status: 429, Message: "host 在途中继请求过多"}
	}
	h.mu.Unlock()

	// Fast liveness preflight. "Online" only means a transport object exists;
	// a half-open link would otherwise swallow the request frame and leave the
	// browser waiting for RelayTimeout. A session that just received a frame
	// is trusted; a silent one must answer a probe before a prompt (which is
	// not cancellable once it starts) is sent.
	if !sess.healthy(relayHealthWindow) {
		if err := sess.probe(ctx, relayProbeTimeout); err != nil {
			if ctx.Err() != nil {
				return RelayResponse{}, &RelayError{Status: 499, Message: "客户端已取消"}
			}
			return RelayResponse{}, &RelayError{Status: 503, Message: "host 正在重连"}
		}
	}

	// The probe may have taken a while: re-check that the same session is
	// still attached and that the pending table still has room.
	h.mu.Lock()
	hs = h.hosts[hostID]
	if hs == nil {
		h.mu.Unlock()
		return RelayResponse{}, &RelayError{Status: 404, Message: ErrHostUnknown.Error()}
	}
	if hs.session != sess {
		h.mu.Unlock()
		return RelayResponse{}, &RelayError{Status: 503, Message: fmt.Sprintf("host %s 当前离线", hostID)}
	}
	if len(h.pending[hostID]) >= maxPendingRelayPerHost {
		h.mu.Unlock()
		return RelayResponse{}, &RelayError{Status: 429, Message: "host 在途中继请求过多"}
	}
	pr := &pendingReq{
		resp: make(chan RelayResponse, 1),
		done: make(chan struct{}),
	}
	if h.pending[hostID] == nil {
		h.pending[hostID] = make(map[string]*pendingReq)
	}
	h.pending[hostID][reqID] = pr
	h.mu.Unlock()

	// Delivery is the session's problem: the frame is logged and retransmitted
	// until the host's cumulative ack covers it. A failure here means the
	// frame was never appended, so the host cannot have executed it.
	if err := sess.dispatch(reqID, method, path, body, opts); err != nil {
		h.dropPending(hostID, reqID)
		return RelayResponse{}, &RelayError{Status: 503, Message: fmt.Sprintf("host %s 已断开", hostID)}
	}

	timer := time.NewTimer(RelayTimeout)
	defer timer.Stop()
	// A response that already arrived must win over a concurrently firing
	// timeout: select would otherwise pick the timer branch at random and drop
	// an answer that is already here.
	select {
	case resp := <-pr.resp:
		return resp, nil
	default:
	}
	for {
		select {
		case resp := <-pr.resp:
			return resp, nil
		case <-pr.done:
			return RelayResponse{}, &RelayError{Status: 503, Message: fmt.Sprintf("host %s 已断开", hostID)}
		case <-ctx.Done():
			// Browser gone: stop waiting and release the pending slot. The host
			// keeps executing; its late respond simply finds no pending entry.
			h.dropPending(hostID, reqID)
			return RelayResponse{}, &RelayError{Status: 499, Message: "客户端已取消"}
		case <-timer.C:
			h.dropPending(hostID, reqID)
			return RelayResponse{}, &RelayError{Status: 504, Message: "中继超时"}
		}
	}
}

func (h *Hub) dropPending(hostID, reqID string) {
	h.mu.Lock()
	pr := h.takePendingLocked(hostID, reqID)
	if pr != nil {
		h.addAbortTombstoneLocked(hostID, reqID)
		pr.parked = nil
	}
	var sess *session
	if hs := h.hosts[hostID]; hs != nil {
		sess = hs.session
	}
	h.mu.Unlock()
	// Browser cancel / relay timeout also creates an abort: tell the host
	// immediately so a late request is not executed after the browser left.
	if pr != nil && sess != nil {
		sess.notifyAckTable()
	}
}

// takePendingLocked removes one pending request and reports it, or nil when
// the host/reqId is unknown (a late or duplicate respond). Callers hold h.mu.
func (h *Hub) takePendingLocked(hostID, reqID string) *pendingReq {
	m := h.pending[hostID]
	if m == nil {
		return nil
	}
	pr, ok := m[reqID]
	if !ok {
		return nil
	}
	delete(m, reqID)
	if len(m) == 0 {
		delete(h.pending, hostID)
	}
	return pr
}

// relayAcks returns the hub's per-request acknowledgement table for hostID:
// every pending request with its highest contiguous chunk, every recently
// resolved request marked done, and every aborted request marked abort. It is
// carried by hello_ack (same-epoch resume) and by every hb the session sends.
func (h *Hub) relayAcks(hostID string) []wire.RelayAck {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.relayAcksLocked(hostID)
}

// relayAcksLocked is relayAcks with the caller holding h.mu.
func (h *Hub) relayAcksLocked(hostID string) []wire.RelayAck {
	now := time.Now()
	pend := h.pending[hostID]
	out := make([]wire.RelayAck, 0, len(pend))
	for reqID, pr := range pend {
		out = append(out, wire.RelayAck{ReqID: reqID, Chunk: pr.nextChunk})
	}
	for reqID, ts := range h.relayTombstones[hostID] {
		if now.Sub(ts.at) > relayTombstoneTTL {
			delete(h.relayTombstones[hostID], reqID)
			continue
		}
		if _, live := pend[reqID]; live {
			continue
		}
		out = append(out, ts.ack)
	}
	if len(h.relayTombstones[hostID]) == 0 {
		delete(h.relayTombstones, hostID)
	}
	// Stable order: the host matches by reqId, but a deterministic frame is
	// easier to assert in tests and to diff in logs.
	sort.Slice(out, func(i, j int) bool { return out[i].ReqID < out[j].ReqID })
	return out
}

// addRelayTombstoneLocked records how one request ended. Bounded by count
// (oldest evicted) so a long-running hub with many short relay calls cannot
// grow the ack table without limit. Callers hold h.mu.
func (h *Hub) addRelayTombstoneLocked(hostID string, ack wire.RelayAck) {
	if ack.ReqID == "" {
		return
	}
	m := h.relayTombstones[hostID]
	if m == nil {
		m = make(map[string]relayTombstone)
		h.relayTombstones[hostID] = m
	}
	m[ack.ReqID] = relayTombstone{ack: ack, at: time.Now()}
	if len(m) <= maxRelayTombstonesPerHost {
		return
	}
	oldestID := ""
	var oldest time.Time
	for id, ts := range m {
		if oldestID == "" || ts.at.Before(oldest) {
			oldestID, oldest = id, ts.at
		}
	}
	delete(m, oldestID)
}

// addAbortTombstoneLocked tells the host to drop an answer. A request that
// already completed keeps its done tombstone: a late duplicate chunk must not
// turn a delivered answer into an aborted one.
func (h *Hub) addAbortTombstoneLocked(hostID, reqID string) {
	if m := h.relayTombstones[hostID]; m != nil {
		if ts, ok := m[reqID]; ok && ts.ack.Done {
			return
		}
	}
	h.addRelayTombstoneLocked(hostID, wire.RelayAck{ReqID: reqID, Abort: true})
}

func (h *Hub) addDoneTombstoneLocked(hostID, reqID string, chunk uint64) {
	h.addRelayTombstoneLocked(hostID, wire.RelayAck{ReqID: reqID, Chunk: chunk, Done: true})
}

// resolvePendingLocked delivers a completed answer, removes the pending entry
// and records the done tombstone, all under one h.mu so a reconnecting host
// sees exactly one terminal state. Callers hold h.mu.
func (h *Hub) resolvePendingLocked(hostID, reqID string, pr *pendingReq, resp RelayResponse, finalChunk uint64) {
	if pr == nil || h.pending[hostID][reqID] != pr {
		return
	}
	h.takePendingLocked(hostID, reqID)
	pr.parked = nil
	h.addDoneTombstoneLocked(hostID, reqID, finalChunk)
	pr.resp <- resp
}

// hostParkedLocked returns the out-of-order chunk count and byte weight parked
// across every pending request for hostID.
func (h *Hub) hostParkedLocked(hostID string) (chunks, bytes int) {
	for _, pr := range h.pending[hostID] {
		chunks += len(pr.parked)
		bytes += pr.parkedBytes
	}
	return chunks, bytes
}

// acceptRespond applies one respond frame in the relay plane's per-request
// chunk order. It returns known=false for a reqId with no pending entry
// (recorded as an abort tombstone so the host drops its answer) and
// notify=true when the per-request ack advanced or the request reached a
// terminal state, so the session can push a fresh hb immediately.
//
// Out-of-order chunks are parked (bounded per host); a gap that overflows the
// bounds fails only that request with 502 + abort, never the session.
func (h *Hub) acceptRespond(hostID string, f wire.Frame) (known, notify bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	pr := h.pending[hostID][f.ReqID]
	if pr == nil {
		h.lateRelayChunks.Add(1)
		h.addAbortTombstoneLocked(hostID, f.ReqID)
		return false, false
	}
	if f.ChunkSeq <= pr.nextChunk {
		// Duplicate: the ack table already covers it.
		return true, false
	}
	if f.ChunkSeq > pr.nextChunk+1 {
		weight := len(f.Chunk) + len(f.Body)
		chunks, bytes := h.hostParkedLocked(hostID)
		if chunks+1 > maxParkedRelayChunksPerHost || bytes+weight > maxParkedRelayBytesPerHost {
			log.Printf("[capri-hub] host %s req %s: out-of-order relay chunks over budget (chunk %d, %d parked, %d bytes), failing this request only",
				hostID, f.ReqID, f.ChunkSeq, chunks, bytes)
			h.failRelayRequestLocked(hostID, f.ReqID, "中继响应乱序分块过多")
			return true, true
		}
		if pr.parked == nil {
			pr.parked = make(map[uint64]wire.Frame)
		}
		if _, dup := pr.parked[f.ChunkSeq]; !dup {
			pr.parked[f.ChunkSeq] = f
			pr.parkedBytes += weight
		}
		return true, false
	}

	resolved, applied := h.applyRespondLocked(hostID, f.ReqID, pr, f)
	notify = applied
	for !resolved {
		next, ok := pr.parked[pr.nextChunk+1]
		if !ok {
			break
		}
		pr.parkedBytes -= len(next.Chunk) + len(next.Body)
		delete(pr.parked, pr.nextChunk+1)
		var applied bool
		resolved, applied = h.applyRespondLocked(hostID, f.ReqID, pr, next)
		notify = notify || applied
	}
	return true, notify
}

// applyRespondLocked applies one in-order chunk. resolved reports that the
// pending entry is gone (answer delivered or request failed); applied reports
// that the per-request ack moved or the request ended, so the caller knows to
// push an hb. Callers hold h.mu.
func (h *Hub) applyRespondLocked(hostID, reqID string, pr *pendingReq, f wire.Frame) (resolved, applied bool) {
	status := f.RespondStatus()
	if !pr.chunkStatusSet {
		pr.chunkStatus = status
		pr.chunkStatusSet = true
	}

	if f.Chunk != "" || f.Encoding != "" {
		pr.chunked = true
		// The only encoding defined today. An empty or unknown encoding with
		// a chunk is a protocol error too: guessing would hand raw bytes to
		// the response writer as if they were the body.
		if f.Encoding != "base64" {
			log.Printf("[capri-hub] host %s req %s: respond chunk encoding %q unsupported", hostID, reqID, f.Encoding)
			h.failRelayRequestLocked(hostID, reqID, fmt.Sprintf("中继响应分块编码不受支持: %q", f.Encoding))
			return true, true
		}
		decoded, err := base64.StdEncoding.DecodeString(f.Chunk)
		if err != nil {
			log.Printf("[capri-hub] host %s req %s: respond chunk base64 decode: %v", hostID, reqID, err)
			h.failRelayRequestLocked(hostID, reqID, "中继响应分块无法解码")
			return true, true
		}
		if len(pr.chunks)+len(decoded) > maxChunkedRelayBody {
			log.Printf("[capri-hub] host %s req %s: chunked relay body over %d bytes, failing this request only",
				hostID, reqID, maxChunkedRelayBody)
			h.failRelayRequestLocked(hostID, reqID, fmt.Sprintf("中继响应超过 %dMB 上限", maxChunkedRelayBody>>20))
			return true, true
		}
		pr.chunks = append(pr.chunks, decoded...)
	} else if f.More || pr.chunked || pr.nextChunk > 0 {
		// A raw-body fragment (no base64) is only meaningful as part of a
		// multi-frame answer; a lone frame keeps the legacy Body path below.
		pr.chunked = true
		pr.chunks = append(pr.chunks, f.Body...)
	}

	pr.nextChunk = f.ChunkSeq
	applied = true
	if f.More {
		return false, applied
	}
	pr.finalChunk = f.ChunkSeq

	if !pr.chunked && f.ChunkSeq == 1 {
		// Single-frame answer: preserve the original shape exactly, including
		// an absent body and no JSON re-validation.
		h.resolvePendingLocked(hostID, reqID, pr, RelayResponse{Status: status, Body: f.Body}, f.ChunkSeq)
		return true, applied
	}

	body := pr.chunks
	if !json.Valid(body) {
		// The host wraps non-JSON bodies as JSON strings, so invalid bytes
		// here are a protocol bug. A 502 is better than handing the FE
		// bytes its JSON writer would choke on.
		log.Printf("[capri-hub] host %s req %s: assembled relay body is not valid JSON (%d bytes)", hostID, reqID, len(body))
		h.failRelayRequestLocked(hostID, reqID, "拼接后的中继响应不是合法 JSON")
		return true, applied
	}
	h.resolvePendingLocked(hostID, reqID, pr, RelayResponse{Status: pr.chunkStatus, Body: body}, f.ChunkSeq)
	return true, applied
}

// failRelayRequestLocked drops one pending request and answers it with a 502
// JSON error. Unlike failPendingLocked it does not touch the host's other
// requests or the session: one oversized or malformed answer must not fail
// everything else in flight. The abort tombstone tells the host to stop
// sending chunks for it. Callers hold h.mu.
func (h *Hub) failRelayRequestLocked(hostID, reqID, reason string) {
	pr := h.takePendingLocked(hostID, reqID)
	if pr == nil {
		return
	}
	h.addAbortTombstoneLocked(hostID, reqID)
	pr.chunks = nil
	pr.parked = nil
	body, _ := json.Marshal(map[string]any{"ok": false, "error": reason})
	pr.resp <- RelayResponse{Status: 502, Body: body}
}

// maxChunkedRelayBody caps the assembled size of a chunked relay response.
// The host already refuses to relay a local body over its own 28MB ceiling,
// so anything larger here is a broken or hostile chunk stream; dropping the
// request keeps hub memory bounded instead of buffering without limit. A var
// so tests can shrink it.
var maxChunkedRelayBody = 28 << 20

// Respond resolves a relayed request with a complete answer. It is the
// in-process API used by tests and embedders; the wire path goes through
// acceptRespond with the frame's real ChunkSeq.
func (h *Hub) Respond(hostID, reqID string, resp RelayResponse) bool {
	h.mu.Lock()
	seq := uint64(1)
	if pr := h.pending[hostID][reqID]; pr != nil {
		seq = pr.nextChunk + 1
	}
	h.mu.Unlock()

	f := wire.Frame{V: wire.ProtocolVersion, Type: wire.TypeRespond, ReqID: reqID, ChunkSeq: seq}
	f.SetRespondStatus(resp.Status)
	if len(resp.Body) > 0 {
		f.Body = resp.Body
	}
	known, _ := h.acceptRespond(hostID, f)
	return known
}

// RespondChunk feeds one chunk of a chunked relay response. It returns true
// when the chunk belonged to a pending request — including the case where it
// failed that request — and false for an unknown reqId, which is logged,
// counted and tombstoned: a chunk can legitimately arrive after the browser
// gave up and the pending entry was dropped.
//
// The assembled bytes are handed to the waiting relay caller as a normal
// RelayResponse, so the browser and FE never see the split.
func (h *Hub) RespondChunk(hostID, reqID string, status int, encoding, chunk string, more bool) bool {
	h.mu.Lock()
	seq := uint64(1)
	if pr := h.pending[hostID][reqID]; pr != nil {
		seq = pr.nextChunk + 1
	}
	h.mu.Unlock()

	f := wire.Frame{
		V: wire.ProtocolVersion, Type: wire.TypeRespond,
		ReqID: reqID, ChunkSeq: seq, Encoding: encoding, Chunk: chunk, More: more,
	}
	f.SetRespondStatus(status)
	known, _ := h.acceptRespond(hostID, f)
	return known
}
