package main

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/json"
	"github.com/AgentsHarness/capri-hub/internal/hub"
	"github.com/coder/websocket"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// handleFeWS: aggregated live event stream for browsers.
//   - hello carries `seqs` (last event seq per host) so a reconnecting FE
//     knows what it missed and can gap-pull via GET /api/events.
//   - ?host=<id> scopes the stream to that one host: only its events (plus
//     hub-level frames like hosts_changed) fan out to this connection, and
//     the FE can retarget mid-session with a {"type":"subscribe"} frame.
//     Absent/empty keeps the pre-filter behaviour of every host's stream.
//   - events frames are flate-compressed binary when the client asks (?c=1).
//   - auth: prefer short-lived ?ticket= (from POST /api/ws-ticket); still
//     accepts Bearer / X-Access-Token / ?token= for the long-lived FE_TOKEN.
func handleFeWS(h *hub.Hub, auth feAuth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ident, ok := auth.identifyWithLimit(r)
		if !ok {
			writeJSON(w, 401, map[string]any{"ok": false, "error": "需要有效的访问 token"})
			return
		}
		compress := r.URL.Query().Get("c") == "1"
		hostID := strings.TrimSpace(r.URL.Query().Get("host"))
		// Pin the initial filter to a host this identity may see. Admin and
		// user ?host= values are checked against live ownership; a guest's
		// against the session whitelist. Out-of-scope values fall back to
		// the identity's default host.
		if hostID == "" || !ident.allowsHost(h, hostID) {
			hostID = ident.defaultHost(h)
		}
		// A user or admin with no hosts still gets a valid empty event
		// socket: the FE has to stay connected to receive hosts_changed
		// after its first host is paired. A guest with no whitelisted
		// session has nothing to render, so it keeps the 403.
		if hostID == "" && ident.isGuest() {
			writeJSON(w, 403, map[string]any{"ok": false, "error": "访客令牌没有可用会话"})
			return
		}

		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			// Dev UIs may be on another origin; FE_TOKEN is the real gate.
			InsecureSkipVerify: true,
		})
		if err != nil {
			log.Printf("[capri-hub] fe ws accept: %v", err)
			return
		}
		conn.SetReadLimit(1 << 20)
		defer conn.Close(websocket.StatusNormalClosure, "")

		// Resource guard: reject (1013 Try Again Later) once the
		// subscriber cap is reached instead of degrading under load.
		//
		// The identity snapshot (address / browser / which credential) is
		// what the admin subscriber panel shows; it takes no part in
		// filtering.
		var ch chan hub.Event
		var unsub func()
		var subKicked <-chan struct{}
		info := subscriberInfoFor(ident, requestIP(r), r.UserAgent())
		switch {
		case ident.isGuest():
			ch, unsub, subKicked, ok = h.TrySubscribeGuestInfo(maxFESubscribers, hostID, ident.asGuestToken(), info)
		default:
			// Admin and ordinary users both receive only their own host
			// events. Admin's extra reach is the management API, not the
			// event stream.
			ch, unsub, subKicked, ok = h.TrySubscribeScopedInfo(maxFESubscribers, hostID,
				ident.hostScope(), ident.Role, h.HostIDsForUser(ident.hostScope()), info)
		}
		if !ok {
			_ = conn.Close(websocket.StatusTryAgainLater, "too many subscribers")
			return
		}
		defer unsub()

		// The admin page shows its own row in the subscriber panel; the id
		// lets it mark "this page" without guessing by address.
		subID, _ := h.SubscriberIDFor(ch)
		// The session the page opened with (?session=) — a guest names it at
		// connect time and only re-sends a subscribe frame when it switches.
		// Without this the panel shows a guest row with no transcript.
		if s := strings.TrimSpace(r.URL.Query().Get("session")); s != "" {
			h.SetSubscriberSession(ch, s)
		}

		var writeMu sync.Mutex
		writeFrame := func(b []byte, binary bool) error {
			writeMu.Lock()
			defer writeMu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			kind := websocket.MessageText
			if binary {
				kind = websocket.MessageBinary
			}
			return conn.Write(ctx, kind, b)
		}
		writeJSONFrame := func(v any) error {
			b, err := json.Marshal(v)
			if err != nil {
				return err
			}
			return writeFrame(b, false)
		}
		writeEventsFrame := func(evs []hub.Event) error {
			// Raw splice: pre-encoded events (host wire path) are
			// concatenated verbatim — no re-marshal of event bodies.
			// Semantically identical to the previous whole-frame marshal.
			raws := make([]json.RawMessage, len(evs))
			for i, ev := range evs {
				b, err := hub.MarshalEvent(ev)
				if err != nil {
					return err
				}
				raws[i] = b
			}
			b, err := json.Marshal(map[string]any{"v": 1, "type": "events", "events": raws})
			if err != nil {
				return err
			}
			// Tiny frames compress poorly (flate header + sync marker);
			// send them raw and let the browser skip decompression.
			if !compress || len(b) < minCompressSize {
				return writeFrame(b, false)
			}
			// flate (deflate-raw) — browsers decompress via
			// DecompressionStream. Writer/buffer come from sync.Pool
			// (see flateWriterPool / flateBufPool above).
			fw := flateWriterPool.Get().(*flate.Writer)
			buf := flateBufPool.Get().(*bytes.Buffer)
			buf.Reset()
			fw.Reset(buf)
			_, werr := fw.Write(b)
			cerr := fw.Close()
			flateWriterPool.Put(fw)
			if werr != nil {
				flateBufPool.Put(buf)
				return werr
			}
			if cerr != nil {
				flateBufPool.Put(buf)
				return cerr
			}
			// writeFrame consumes the slice synchronously; only after it
			// returns is the buffer safe to hand back to the pool.
			err = writeFrame(buf.Bytes(), true)
			buf.Reset()
			flateBufPool.Put(buf)
			return err
		}
		// writeBatch keeps wire order across the two shapes a subscriber
		// receives. `subscribed` is the only control frame the FE reads as a
		// TOP-LEVEL frame (live.ts's `subscribed` branch, the same shape the
		// subscribe ack above writes); batched inside `events` it is walked as
		// transcript and silently does nothing — and the epoch reset it
		// carries is what keeps a restarted host's events from being dropped
		// as stale. Everything else keeps travelling inside the batch.
		writeBatch := func(evs []hub.Event) error {
			start := 0
			for i, ev := range evs {
				if t, _ := ev["type"].(string); t != "subscribed" {
					continue
				}
				if i > start {
					if err := writeEventsFrame(evs[start:i]); err != nil {
						return err
					}
				}
				if err := writeJSONFrame(ev); err != nil {
					return err
				}
				start = i + 1
			}
			if start < len(evs) {
				return writeEventsFrame(evs[start:])
			}
			return nil
		}

		hello := map[string]any{
			"v":             1,
			"type":          "hello",
			"service":       "hub",
			"hosts":         helloHosts(h, ident),
			"defaultHostId": helloDefaultHost(h, ident),
			"seqs":          helloSeqs(h, ident),
			"role":          ident.Role,
			// This socket's row id in the admin subscriber panel (0 when
			// the registration was already gone). Guests get it too; it
			// is their own id, not anyone else's.
			"subscriberId": subID,
		}
		// Live browser /ws/fe clients, this connection included — the admin
		// top bar shows it beside the host block. Users and guests stay
		// without this figure; their pages do not render the admin panel.
		if ident.isAdmin() {
			hello["feSubscribers"] = h.SubscriberCount()
		}
		if err := writeJSONFrame(hello); err != nil {
			return
		}

		// Writer: batch events to cut frame overhead under chunk storms.
		// Instead of a free-running 25ms ticker (which wakes up to flush
		// nothing when idle), the flush timer is armed only when an
		// event arrives and stopped once the batch is flushed.
		batch := make([]hub.Event, 0, 16)
		const flushInterval = 25 * time.Millisecond
		var (
			flushTimer *time.Timer
			flushCh    <-chan time.Time // nil ⇒ the select case stays disabled
		)
		flush := func() error {
			if len(batch) == 0 {
				return nil
			}
			evs := batch
			batch = make([]hub.Event, 0, 16)
			if flushTimer != nil {
				flushTimer.Stop()
				select {
				case <-flushTimer.C:
				default:
				}
				flushTimer = nil
				flushCh = nil
			}
			return writeBatch(evs)
		}
		defer func() {
			if flushTimer != nil {
				flushTimer.Stop()
			}
		}()

		ping := time.NewTicker(10 * time.Second)
		defer ping.Stop()
		// Snapshot once per connection: tests retune the package vars
		// between connections without racing in-flight handlers.
		livenessInterval, livenessTimeout := feLivenessInterval, feLivenessTimeout
		liveness := time.NewTicker(livenessInterval)
		defer liveness.Stop()

		// A guest token's expiry must terminate an already-established
		// socket. Authentication rejects expired tokens at connect time,
		// but without this timer a page opened while valid would keep
		// receiving events forever.
		var expiryC <-chan time.Time
		var expiryTimer *time.Timer
		if ident.isGuest() && ident.ExpiresAt > 0 {
			if d := time.Until(time.Unix(ident.ExpiresAt, 0)); d <= 0 {
				_ = conn.Close(websocket.StatusPolicyViolation, "guest token expired")
				return
			} else {
				expiryTimer = time.NewTimer(d)
				expiryC = expiryTimer.C
			}
		}
		if expiryTimer != nil {
			defer expiryTimer.Stop()
		}

		ctx := r.Context()
		// readDone closes when the browser socket goes away. Without it a
		// closed tab stays in the subscriber set (and in the count the other
		// pages display) until the next write fails or the liveness ping
		// times out — up to 20s of a stale number.
		readDone := make(chan struct{})
		// Read FE frames in background so the read side does not stall.
		// This reader is also what processes the peer's WS pong for the
		// protocol-level Ping below — without an in-flight Read the pong
		// would never be dispatched. Besides the app-level pings it carries
		// one control frame: {"v":1,"type":"subscribe","host":ID}, which
		// retargets this connection's event filter when the page switches
		// hosts without reconnecting. The ack echoes the host's current seq
		// watermark so the FE can align instead of gap-pulling from 0 (the
		// whole per-host ring buffer).
		go func() {
			defer close(readDone)
			for {
				_, data, err := conn.Read(ctx)
				if err != nil {
					return
				}
				var ctl struct {
					Type    string `json:"type"`
					Host    string `json:"host"`
					Session string `json:"session"`
				}
				if json.Unmarshal(data, &ctl) != nil {
					continue
				}
				if ctl.Type == "viewing" {
					// Admin and user pages may declare which session they
					// display; this opens the host uplink filter (see
					// PROTOCOL.md §6.4). Guests use the subscribe frame and
					// the session whitelist instead.
					if ident.isGuest() {
						continue
					}
					h.SetSubscriberViewing(ch, strings.TrimSpace(ctl.Session))
					continue
				}
				if ctl.Type != "subscribe" {
					continue // pings and anything unrecognized stay a no-op
				}
				target := strings.TrimSpace(ctl.Host)
				session := strings.TrimSpace(ctl.Session)
				if !ident.isAdmin() {
					// A user or guest may only retarget within its scope.
					// An out-of-scope frame is ignored and the previous
					// subscription stays as it was — no ack, no state
					// change (the FE never learns about other hosts).
					if target == "" || !ident.allowsHost(h, target) {
						continue
					}
					if ident.isGuest() && session != "" && !hub.GuestAllowsSession(ident.asGuestToken(), target, session) {
						continue
					}
				}
				if ident.isUser() {
					// A user may have paired a new host since this socket
					// opened; refresh the fan-out whitelist before moving.
					h.SetSubscriberUserHosts(ch, h.HostIDsForUser(ident.UserID))
				}
				if !h.SetSubscriberHost(ch, target) {
					continue
				}
				// Both roles record the session they display: for a guest
				// it is whitelist bookkeeping (an out-of-scope name was
				// already rejected above), for an admin it is what the
				// subscriber panel lists under "viewing". An empty session
				// clears the row — a host switch starts before the page
				// names its next session, and a stale name would point at
				// a transcript on the host it just left.
				// This is roster state, not a viewing declaration: only the
				// explicit `viewing` frame may narrow the host's uplink.
				h.SetSubscriberSession(ch, session)
				// writeJSONFrame takes the same write mutex the event
				// batcher uses, so an ack cannot interleave a frame.
				ack := map[string]any{
					"v": 1, "type": "subscribed",
					"host": target, "seq": h.LastSeq(target),
				}
				if ident.isGuest() && session != "" {
					ack["session"] = session
				}
				_ = writeJSONFrame(ack)
			}
		}()

		for {
			select {
			case <-ctx.Done():
				_ = flush()
				return
			case <-readDone:
				// Browser closed the socket: drop the registration right
				// away (the deferred unsub is idempotent) so the other
				// pages' subscriber count corrects itself immediately.
				_ = flush()
				return
			case <-subKicked:
				// Credential revoked/deleted, or the subscriber was kicked
				// because its host was unpaired: close the socket now.
				_ = flush()
				_ = conn.Close(websocket.StatusPolicyViolation, "credential revoked")
				return
			case <-expiryC:
				_ = flush()
				h.DropGuestSubscribers(ident.TokenID)
				_ = conn.Close(websocket.StatusPolicyViolation, "guest token expired")
				return
			case <-ping.C:
				if err := flush(); err != nil {
					return
				}
				if err := writeJSONFrame(map[string]any{"v": 1, "type": "ping", "ts": time.Now().Unix()}); err != nil {
					return
				}
			case <-liveness.C:
				// Protocol-level liveness (T7): a half-open FE connection
				// used to linger until a data write hit the 15s timeout —
				// and forever on an idle session. Ping waits for the peer's
				// pong (processed by the drain goroutine above); failure
				// frees the 512-event subscriber channel immediately.
				// Concurrent with writeFrame: the library serializes
				// control frames via its internal write mutex.
				pctx, pcancel := context.WithTimeout(ctx, livenessTimeout)
				err := conn.Ping(pctx)
				pcancel()
				if err != nil {
					return
				}
			case <-flushCh:
				if err := flush(); err != nil {
					return
				}
			case ev, ok := <-ch:
				if !ok {
					_ = flush()
					return
				}
				batch = append(batch, ev)
				if len(batch) >= 16 {
					if err := flush(); err != nil {
						return
					}
				} else if flushTimer == nil {
					// Arm the flush: if no further events arrive within
					// flushInterval, send what we have.
					flushTimer = time.NewTimer(flushInterval)
					flushCh = flushTimer.C
				}
			}
		}
	}
}
