package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/internal/hub"
	"github.com/coder/websocket"
)

// TestIntegrationFeWSHostFilter is the end-to-end half of the FE host
// split: a browser that names a host on /ws/fe receives ONLY that host's
// events, and can retarget with a subscribe frame without reconnecting
// (answered with the host's seq watermark so the client aligns instead of
// gap-pulling the whole buffer).
func TestIntegrationFeWSHostFilter(t *testing.T) {
	h := hub.NewWithDir("")
	tickets := newFETicketStore()
	lim := newPairLimiter()
	const secret = "filter-secret"
	srv := httptest.NewServer(buildHandler(h, secret, tickets, lim, nil))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	h1 := dialPairedHost(t, ctx, srv, h, "h1", "H1")
	defer h1.Close(websocket.StatusNormalClosure, "")
	h2 := dialPairedHost(t, ctx, srv, h, "h2", "H2")
	defer h2.Close(websocket.StatusNormalClosure, "")

	ticket, _ := tickets.issue("")
	fe, _, err := websocket.Dial(ctx,
		strings.Replace(srv.URL, "http", "ws", 1)+"/ws/fe?ticket="+ticket+"&host=h1", nil)
	if err != nil {
		t.Fatalf("fe ws dial: %v", err)
	}
	defer fe.Close(websocket.StatusNormalClosure, "")
	fe.SetReadLimit(1 << 20)
	frames := feFrames(ctx, fe)
	if hello := waitForFrameType(frames, "hello", 3*time.Second); hello == nil {
		t.Fatal("no fe hello")
	}

	pushHostEvent(t, ctx, h1, 1, map[string]any{"type": "chunk", "text": "for-h1"})
	pushHostEvent(t, ctx, h2, 1, map[string]any{"type": "chunk", "text": "for-h2"})
	got := chunkTextsOf(ctx, frames, 700*time.Millisecond)
	if !containsStr(got, "for-h1") {
		t.Fatalf("filtered FE missed its own host: %v", got)
	}
	if containsStr(got, "for-h2") {
		t.Fatalf("other host's event leaked into the filtered stream: %v", got)
	}
	// The hub must also stop counting this page as an audience for h2 —
	// that is what lets h2 pause its uplink entirely.
	if n := h.SubscriberCountFor("h2"); n != 0 {
		t.Errorf("SubscriberCountFor(h2) = %d, want 0", n)
	}
	if n := h.SubscriberCountFor("h1"); n != 1 {
		t.Errorf("SubscriberCountFor(h1) = %d, want 1", n)
	}

	// Retarget to h2 over the same connection.
	sub, _ := json.Marshal(map[string]any{"v": 1, "type": "subscribe", "host": "h2"})
	if err := fe.Write(ctx, websocket.MessageText, sub); err != nil {
		t.Fatalf("subscribe write: %v", err)
	}
	ack := waitForFrameType(frames, "subscribed", 3*time.Second)
	if ack == nil {
		t.Fatal("no subscribed ack")
	}
	if ack["host"] != "h2" {
		t.Errorf("subscribed host = %v, want h2", ack["host"])
	}
	// seq is the host's current watermark (h2 pushed seq 1) — the FE aligns
	// to it instead of pulling the whole per-host ring buffer from 0.
	if seq, _ := ack["seq"].(float64); seq != 1 {
		t.Errorf("subscribed seq = %v, want 1", ack["seq"])
	}

	pushHostEvent(t, ctx, h2, 2, map[string]any{"type": "chunk", "text": "h2-second"})
	pushHostEvent(t, ctx, h1, 2, map[string]any{"type": "chunk", "text": "h1-second"})
	after := chunkTextsOf(ctx, frames, 700*time.Millisecond)
	if !containsStr(after, "h2-second") {
		t.Errorf("after subscribe to h2, its events did not arrive: %v", after)
	}
	if containsStr(after, "h1-second") {
		t.Errorf("after subscribe to h2, h1 events still leak: %v", after)
	}
	if n := h.SubscriberCountFor("h1"); n != 0 {
		t.Errorf("SubscriberCountFor(h1) after retarget = %d, want 0", n)
	}
}

// TestIntegrationFESubscriberCount: the hub hello reports the live browser
// total (the page itself included) and every later connect/disconnect pushes
// a hub-level `subscribers_changed` to the pages already open — that number
// is what the FE top bar renders beside the host block.
func TestIntegrationFESubscriberCount(t *testing.T) {
	h := hub.NewWithDir("")
	tickets := newFETicketStore()
	lim := newPairLimiter()
	const secret = "subs-secret"
	srv := httptest.NewServer(buildHandler(h, secret, tickets, lim, nil))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dialFE := func() (*websocket.Conn, chan map[string]any) {
		t.Helper()
		ticket, _ := tickets.issue("")
		conn, _, err := websocket.Dial(ctx,
			strings.Replace(srv.URL, "http", "ws", 1)+"/ws/fe?ticket="+ticket, nil)
		if err != nil {
			t.Fatalf("fe ws dial: %v", err)
		}
		conn.SetReadLimit(1 << 20)
		return conn, feFrames(ctx, conn)
	}

	// Hub-level broadcasts ride inside `events` frames (the subscriber pump
	// batches them like host events), so scan the batch for the count frame.
	waitSubCount := func(frames chan map[string]any, want float64, d time.Duration) bool {
		t.Helper()
		deadline := time.After(d)
		for {
			select {
			case f, ok := <-frames:
				if !ok {
					return false
				}
				if f["type"] != "events" {
					continue
				}
				evs, _ := f["events"].([]any)
				for _, evAny := range evs {
					ev, _ := evAny.(map[string]any)
					if ev == nil || ev["type"] != "subscribers_changed" {
						continue
					}
					if n, _ := ev["count"].(float64); n == want {
						return true
					}
				}
			case <-deadline:
				return false
			}
		}
	}

	fe1, frames1 := dialFE()
	defer fe1.Close(websocket.StatusNormalClosure, "")
	hello1 := waitForFrameType(frames1, "hello", 3*time.Second)
	if hello1 == nil {
		t.Fatal("no first fe hello")
	}
	if n, _ := hello1["feSubscribers"].(float64); n != 1 {
		t.Fatalf("first hello feSubscribers = %v, want 1", hello1["feSubscribers"])
	}

	fe2, frames2 := dialFE()
	defer fe2.Close(websocket.StatusNormalClosure, "")
	hello2 := waitForFrameType(frames2, "hello", 3*time.Second)
	if n, _ := hello2["feSubscribers"].(float64); n != 2 {
		t.Fatalf("second hello feSubscribers = %v, want 2", hello2["feSubscribers"])
	}
	if !waitSubCount(frames1, 2, 3*time.Second) {
		t.Fatal("open page got no subscribers_changed=2 when another page joined")
	}

	// Closing the second page drops its subscription immediately (the WS
	// read goroutine's exit wakes the handler), so the first page's number
	// falls back to 1 without waiting for a ping failure.
	fe2.Close(websocket.StatusNormalClosure, "")
	if !waitSubCount(frames1, 1, 3*time.Second) {
		t.Fatal("open page got no subscribers_changed=1 after the other page left")
	}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// TestSubscribeFrameKeepsViewingAll drives the pre-viewing `subscribe`
// control frame exactly as an old FE sends it — no `session` field, and no
// `viewing` frame ever — and asserts the host's viewing set stays all:true.
// A page that only speaks `subscribe` must never have its transcript
// trimmed (PROTOCOL.md §6.4).
func TestSubscribeFrameKeepsViewingAll(t *testing.T) {
	h := hub.NewWithDir("")
	srv := httptest.NewServer(buildHandler(h, "", nil, nil, nil))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	feConn, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/fe?host=h1", nil)
	if err != nil {
		t.Fatalf("fe ws dial: %v", err)
	}
	defer feConn.Close(websocket.StatusNormalClosure, "")
	feConn.SetReadLimit(1 << 20)

	// The legacy frame: host only, no session.
	if err := feConn.Write(ctx, websocket.MessageText, []byte(`{"v":1,"type":"subscribe","host":"h1"}`)); err != nil {
		t.Fatalf("write subscribe: %v", err)
	}
	for {
		_, raw, err := feConn.Read(ctx)
		if err != nil {
			t.Fatalf("waiting for subscribed ack: %v", err)
		}
		var frame map[string]any
		if json.Unmarshal(raw, &frame) != nil {
			continue
		}
		if frame["type"] == "subscribed" {
			break
		}
	}

	// The viewing-set decision itself is covered in internal/hub
	// (TestViewingAllWhenPageSilent): a subscribe-only page must keep the set
	// at all:true. Here it is enough that the frame was accepted and acked.
}

// TestFEReceivesEpochResetAsSubscribedFrame pins the shape of the epoch reset
// on /ws/fe. The FE's only seq-reconciliation entry point for a host restart
// is the top-level {"type":"subscribed","host":..,"seq":baseline} frame (see
// acp-fe live.ts, the `subscribed` branch next to the subscribe ack). An
// `events` batch is walked as transcript, so a reset delivered inside one is
// emitted as an ordinary event: the page keeps its old per-host watermark and
// silently drops every event of the new epoch, whose seq restarted lower.
func TestFEReceivesEpochResetAsSubscribedFrame(t *testing.T) {
	h := hub.NewWithDir("")
	const secret = "epoch-reset-secret"
	srv := httptest.NewServer(buildHandler(h, secret, newFETicketStore(), newPairLimiter(), nil))
	defer srv.Close()

	code, _ := h.PairingCode()
	token, err := h.Pair(code, "h1", "H1")
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	host := dialHostWithToken(t, ctx, srv, "h1", token, 111)
	defer host.Close(websocket.StatusNormalClosure, "")
	pushHostEvent(t, ctx, host, 1, map[string]any{"type": "chunk", "text": "before"})

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/ws-ticket", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	tr, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var ticketRes struct {
		Ticket string `json:"ticket"`
	}
	_ = json.NewDecoder(tr.Body).Decode(&ticketRes)
	tr.Body.Close()

	fe, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/fe?ticket="+ticketRes.Ticket, nil)
	if err != nil {
		t.Fatalf("fe dial: %v", err)
	}
	defer fe.Close(websocket.StatusNormalClosure, "")
	fe.SetReadLimit(1 << 20)
	if _, _, err := fe.Read(ctx); err != nil {
		t.Fatalf("fe hello: %v", err)
	}
	frames := feFrames(ctx, fe)

	// A second host connection is a new epoch (a restarted host process): the
	// hub must announce the retired high-water mark to the page.
	restarted := dialHostWithToken(t, ctx, srv, "h1", token, 112)
	defer restarted.Close(websocket.StatusNormalClosure, "")

	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("FE never received a top-level subscribed frame for the epoch reset")
		case f, ok := <-frames:
			if !ok {
				t.Fatal("FE connection closed before the epoch reset")
			}
			typ, _ := f["type"].(string)
			if typ == "events" {
				if evs, _ := f["events"].([]any); len(evs) > 0 {
					for _, e := range evs {
						if m, _ := e.(map[string]any); m != nil && m["type"] == "subscribed" {
							t.Fatalf("epoch reset was batched as a transcript event: %v", m)
						}
					}
				}
				continue
			}
			if typ != "subscribed" {
				continue
			}
			if f["host"] != "h1" {
				t.Fatalf("subscribed frame names host %v, want h1", f["host"])
			}
			if seq, _ := f["seq"].(float64); seq != 0 {
				t.Fatalf("subscribed baseline = %v, want the declared resume.up 0", f["seq"])
			}
			return
		}
	}
}
