package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/internal/hub"
	"github.com/coder/websocket"
)

// A chunk frame whose reqId is unknown must be routed to the assembly path,
// ignored and counted — not logged as a legacy unknown respond, and never a
// panic.
func TestHandleHostFrameChunkedRespondUnknownReq(t *testing.T) {
	h := hub.NewWithDir("")
	code, _ := h.PairingCode()
	if _, err := h.Pair(code, "h1", "H1"); err != nil {
		t.Fatal(err)
	}
	frame, _ := json.Marshal(map[string]any{
		"v": 1, "type": "respond", "reqId": "missing", "status": 200,
		"chunk": base64.StdEncoding.EncodeToString([]byte("x")), "encoding": "base64", "more": false,
	})
	handleHostFrame(h, "h1", frame, func([]byte) error { return nil })

	if got := h.Stats().LateRelayChunks; got != 1 {
		t.Fatalf("LateRelayChunks = %d, want 1 (the frame must reach RespondChunk)", got)
	}
}

// End to end over the real WS host handler: a host answers in two chunk
// frames, and the browser's relayed HTTP request receives the reassembled
// body with nothing about the split visible.
func TestChunkedRespondRelayedToBrowser(t *testing.T) {
	h := hub.NewWithDir(t.TempDir())
	const secret = "admin-secret"
	srv := httptest.NewServer(buildHandler(h, secret, newFETicketStore(), newPairLimiter(), nil))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	code, _ := h.PairingCode()
	token, err := h.Pair(code, "h1", "H1")
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	conn, _, err := websocket.Dial(ctx, strings.Replace(srv.URL, "http", "ws", 1)+"/ws/host", &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization":   []string{"Bearer " + token},
			"X-Hub-Deflate":   []string{"1"},
			"X-Hub-State-Ack": []string{"1"},
		},
	})
	if err != nil {
		t.Fatalf("host ws dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	conn.SetReadLimit(1 << 20)
	if _, _, err := conn.Read(ctx); err != nil { // hello
		t.Fatalf("hello: %v", err)
	}

	// 2.25MB of valid JSON, split into two frames the way respondChunked
	// splits at relayChunkSize.
	body := `{"ok":true,"data":"` + strings.Repeat("q", 2<<20+256<<10) + `"}`
	const split = 1 << 20

	go func() {
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var f struct {
				Type  string `json:"type"`
				ReqID string `json:"reqId"`
			}
			if json.Unmarshal(data, &f) != nil || f.Type != "request" {
				continue
			}
			for i, part := range []string{body[:split], body[split:]} {
				frame, _ := json.Marshal(map[string]any{
					"v": 1, "type": "respond", "reqId": f.ReqID, "status": 200,
					"chunk":    base64.StdEncoding.EncodeToString([]byte(part)),
					"encoding": "base64",
					"more":     i == 0,
				})
				if err := conn.Write(ctx, websocket.MessageText, frame); err != nil {
					return
				}
			}
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/sessions?hostId=h1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("relay request: %v", err)
	}
	defer res.Body.Close()
	got, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read relay body: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("relay status = %d, body = %s", res.StatusCode, got)
	}
	if string(got) != body {
		t.Fatalf("relayed body = %d bytes, want the reassembled %d", len(got), len(body))
	}
}
