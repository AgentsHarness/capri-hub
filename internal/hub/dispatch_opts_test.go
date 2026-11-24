package hub

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/AgentsHarness/capri-hub/wire"
)

// TestDispatchOptionsReachTheHost: DispatchOpts stamps the request frame with
// the key/scope it was given, and a plain Dispatch (empty options) leaves both
// fields absent, so older callers keep their exact wire shape.
func TestDispatchOptionsReachTheHost(t *testing.T) {
	h := NewWithDir("")
	testPair(t, h, "h1", "H1")
	fh := dialFakeHost(t, h, "h1", 71)

	cases := []struct {
		name string
		opts DispatchOptions
	}{
		{"with key", DispatchOptions{IdemKey: "6f1e0c1e-7f5a-4c2b-9d3e-2a1b0c9d8e7f", IdemScope: "user:u1"}},
		{"empty", DispatchOptions{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			type result struct {
				status int
				err    error
			}
			done := make(chan result, 1)
			go func() {
				resp, err := h.DispatchOpts(context.Background(), "h1", "POST", "/api/prompt",
					json.RawMessage(`{"sessionId":"s1"}`), tc.opts)
				done <- result{status: resp.Status, err: err}
			}()

			req := fh.recvType(wire.TypeRequest, 2*time.Second)
			if req.IdemKey != tc.opts.IdemKey || req.IdemScope != tc.opts.IdemScope {
				t.Fatalf("request idempotency = %q/%q, want %q/%q",
					req.IdemKey, req.IdemScope, tc.opts.IdemKey, tc.opts.IdemScope)
			}

			answer := wire.Frame{V: wire.ProtocolVersion, Type: wire.TypeRespond, ReqID: req.ReqID, ChunkSeq: 1, Ack: req.Seq}
			answer.SetRespondStatus(200)
			answer.Body = json.RawMessage(`{"ok":true}`)
			fh.send(answer)

			select {
			case r := <-done:
				if r.err != nil || r.status != 200 {
					t.Fatalf("dispatch = status %d, err %v", r.status, r.err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("dispatch did not resolve")
			}
		})
	}
}

// TestDispatchOptsRejectsInvalidEnvelope: a key/scope the frame validator
// would refuse is answered 400 before any host lookup, not as a 503 from the
// encoder.
func TestDispatchOptsRejectsInvalidEnvelope(t *testing.T) {
	h := NewWithDir("")
	longKey := strings.Repeat("k", wire.IdemKeyMaxLen+1)
	longScope := strings.Repeat("s", wire.IdemScopeMaxLen+1)
	cases := []struct {
		name string
		opts DispatchOptions
	}{
		{"scope without key", DispatchOptions{IdemScope: "root"}},
		{"key too long", DispatchOptions{IdemKey: longKey}},
		{"key not printable", DispatchOptions{IdemKey: "a\tb"}},
		{"scope too long", DispatchOptions{IdemKey: "k", IdemScope: longScope}},
		{"scope not printable", DispatchOptions{IdemKey: "k", IdemScope: "a\tb"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.DispatchOpts(context.Background(), "h1", "POST", "/api/prompt", nil, tc.opts)
			var re *RelayError
			if !errors.As(err, &re) || re.Status != 400 {
				t.Fatalf("err = %v, want a 400 RelayError", err)
			}
		})
	}
}
