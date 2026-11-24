package wire

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func roundTrip(t *testing.T, f Frame) Frame {
	t.Helper()
	b, err := Encode(f)
	if err != nil {
		t.Fatalf("encode %+v: %v", f, err)
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	if !reflect.DeepEqual(got, f) {
		t.Fatalf("round trip\n got %+v\nwant %+v\nwire %s", got, f, b)
	}
	return got
}

func hbFrame(t *testing.T) Frame {
	t.Helper()
	f, err := NewHeartbeat(100, HeartbeatStatus{Ready: true, PendingCount: 2, Port: 8765})
	if err != nil {
		t.Fatalf("NewHeartbeat: %v", err)
	}
	return f
}

func TestFrameRoundTrip(t *testing.T) {
	zero, err := NewHeartbeat(0, HeartbeatStatus{Ready: true})
	if err != nil {
		t.Fatalf("NewHeartbeat: %v", err)
	}

	respond := Frame{V: ProtocolVersion, Type: TypeRespond, Ack: 100, ReqID: "7", ChunkSeq: 1, Body: json.RawMessage(`{"ok":true}`)}
	respond.SetRespondStatus(200)

	chunked := Frame{V: ProtocolVersion, Type: TypeRespond, Ack: 100, ReqID: "7", ChunkSeq: 2, Chunk: "aGk=", Encoding: "base64", More: true}
	chunked.SetRespondStatus(200)

	probe, err := NewHeartbeatProbe(100, 42, HeartbeatStatus{Ready: true}, false)
	if err != nil {
		t.Fatalf("NewHeartbeatProbe: %v", err)
	}
	probeAck, err := NewHeartbeatProbe(100, 42, HeartbeatStatus{Ready: true}, true)
	if err != nil {
		t.Fatalf("NewHeartbeatProbe: %v", err)
	}
	acking := hbFrame(t)
	acking.RelayAcks = []RelayAck{
		{ReqID: "7", Chunk: 3},
		{ReqID: "8", Done: true},
		{ReqID: "9", Abort: true},
	}

	cases := map[string]Frame{
		"hello": NewHello(Hello{
			Epoch:  7,
			Token:  "tok",
			Resume: &Resume{Up: 41, Down: 17},
			Caps:   &Caps{Deflate: true, TransportUnits: true, RelayAck: true},
		}),
		"hello_ack": NewHelloAck(HelloAck{
			Epoch:    7,
			HubBoot:  9,
			AckUp:    41,
			AckDown:  17,
			Audience: &Audience{Gen: 33, Watchers: 2, Sessions: []string{"s1"}},
			Liveness: &DefaultLiveness,
			Limits:   &DefaultLimits,
			Caps:     &Caps{Deflate: true},
			RelayAcks: []RelayAck{
				{ReqID: "7", Chunk: 2},
				{ReqID: "8", Done: true},
			},
		}),
		"events": {V: ProtocolVersion, Type: TypeEvents, Seq: 100, Ack: 17, Events: []json.RawMessage{
			json.RawMessage(`{"type":"chunk","seq":100}`),
			json.RawMessage(`{"type":"chunk","seq":101}`),
		}},
		"audience":     NewAudience(Audience{Gen: 34, Watchers: 2, Sessions: []string{"s1", "s2"}}),
		"request":      {V: ProtocolVersion, Type: TypeRequest, Seq: 13, Ack: 100, ReqID: "7", Method: "POST", Path: "/api/x", Body: json.RawMessage(`{"a":1}`)},
		"respond":      respond,
		"chunked":      chunked,
		"hb":           hbFrame(t),
		"hb zero":      zero,
		"probe":        probe,
		"probeAck":     probeAck,
		"hb relayAcks": acking,
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			got := roundTrip(t, f)
			if got.Type != f.Type {
				t.Fatalf("type %q", got.Type)
			}
		})
	}
}

func TestFrameTypedViews(t *testing.T) {
	h := Hello{Epoch: 7, Token: "t", Resume: &Resume{Up: 1, Down: 2}}
	f := NewHello(h)
	back, err := f.Hello()
	if err != nil || !reflect.DeepEqual(back, h) {
		t.Fatalf("hello view %+v err %v", back, err)
	}
	if _, err := hbFrame(t).Hello(); err == nil {
		t.Fatal("hello view of an hb frame succeeded")
	}

	ack := HelloAck{Epoch: 9, AckUp: 3, AckDown: 4, Audience: &Audience{Gen: 1}, Liveness: &DefaultLiveness, Limits: &DefaultLimits,
		RelayAcks: []RelayAck{{ReqID: "7", Chunk: 5}}}
	fa := NewHelloAck(ack)
	backAck, err := fa.HelloAck()
	if err != nil || !reflect.DeepEqual(backAck, ack) {
		t.Fatalf("hello_ack view %+v err %v", backAck, err)
	}
	if len(backAck.RelayAcks) != 1 || backAck.RelayAcks[0].Chunk != 5 {
		t.Fatalf("hello_ack relayAcks %+v", backAck.RelayAcks)
	}

	st, err := hbFrame(t).Heartbeat()
	if err != nil || !st.Ready || st.Port != 8765 {
		t.Fatalf("heartbeat view %+v err %v", st, err)
	}

	r := Frame{V: ProtocolVersion, Type: TypeRespond, ReqID: "1", ChunkSeq: 1}
	if r.RespondStatus() != 0 {
		t.Fatalf("status of a bare respond is %d", r.RespondStatus())
	}
	r.SetRespondStatus(503)
	if r.RespondStatus() != 503 {
		t.Fatalf("status %d", r.RespondStatus())
	}
}

func TestDecodeRejects(t *testing.T) {
	cases := []struct {
		name string
		wire string
		want error
	}{
		{"wrong version", `{"v":1,"type":"hb","status":{}}`, ErrProtocol},
		{"missing version", `{"type":"hb","status":{}}`, ErrProtocol},
		{"unknown type", `{"v":3,"type":"ping"}`, ErrProtocol},
		{"seq on hb", `{"v":3,"type":"hb","seq":5,"status":{}}`, ErrProtocol},
		{"seq on hello", `{"v":3,"type":"hello","seq":1,"epoch":7,"resume":{"up":0,"down":0}}`, ErrProtocol},
		{"seq on hello_ack", `{"v":3,"type":"hello_ack","seq":1}`, ErrProtocol},
		{"missing seq on events", `{"v":3,"type":"events","events":[{"seq":4}]}`, ErrProtocol},
		{"seq on audience", `{"v":3,"type":"audience","seq":12,"gen":4}`, ErrProtocol},
		{"missing seq on request", `{"v":3,"type":"request","reqId":"7","method":"GET","path":"/x"}`, ErrProtocol},
		{"events first seq mismatch", `{"v":3,"type":"events","seq":4,"events":[{"seq":5}]}`, ErrUnreadable},
		{"events hole", `{"v":3,"type":"events","seq":4,"events":[{"seq":4},{"seq":6}]}`, ErrUnreadable},
		{"events not an object", `{"v":3,"type":"events","seq":4,"events":[7]}`, ErrUnreadable},
		{"empty events", `{"v":3,"type":"events","seq":4,"events":[]}`, ErrProtocol},
		{"hello without epoch", `{"v":3,"type":"hello","resume":{"up":0,"down":0}}`, ErrProtocol},
		{"hello without resume", `{"v":3,"type":"hello","epoch":7}`, ErrProtocol},
		{"hello_ack without hubBoot", `{"v":3,"type":"hello_ack","epoch":7,"audience":{"gen":1},"liveness":{"keepalive":5,"idle":20},"limits":{"maxFrame":8388608,"maxRelayBody":29360128}}`, ErrProtocol},
		{"hello_ack without limits", `{"v":3,"type":"hello_ack","epoch":7,"hubBoot":9,"audience":{"gen":1},"liveness":{"keepalive":5,"idle":20}}`, ErrProtocol},
		{"hello_ack bad liveness", `{"v":3,"type":"hello_ack","epoch":7,"hubBoot":9,"audience":{"gen":1},"liveness":{"keepalive":5,"idle":6},"limits":{"maxFrame":8388608,"maxRelayBody":29360128}}`, ErrProtocol},
		{"audience gen 0", `{"v":3,"type":"audience"}`, ErrProtocol},
		{"audience all with sessions", `{"v":3,"type":"audience","gen":4,"all":true,"sessions":["s1"]}`, ErrProtocol},
		{"request without path", `{"v":3,"type":"request","seq":13,"reqId":"7","method":"POST"}`, ErrProtocol},
		{"respond without reqId", `{"v":3,"type":"respond","chunkSeq":1,"body":{}}`, ErrProtocol},
		{"respond without chunkSeq", `{"v":3,"type":"respond","reqId":"7","body":{}}`, ErrProtocol},
		{"chunkSeq on events", `{"v":3,"type":"events","seq":4,"chunkSeq":1,"events":[{"seq":4}]}`, ErrProtocol},
		{"probe on events", `{"v":3,"type":"events","seq":4,"probe":1,"events":[{"seq":4}]}`, ErrProtocol},
		{"probeAck on hello", `{"v":3,"type":"hello","epoch":7,"resume":{"up":0,"down":0},"probeAck":1}`, ErrProtocol},
		{"relayAcks on events", `{"v":3,"type":"events","seq":4,"relayAcks":[{"reqId":"7"}],"events":[{"seq":4}]}`, ErrProtocol},
		{"relayAck without reqId", `{"v":3,"type":"hb","status":{},"relayAcks":[{"chunk":2}]}`, ErrProtocol},
		{"relayAck done and abort", `{"v":3,"type":"hb","status":{},"relayAcks":[{"reqId":"7","done":true,"abort":true}]}`, ErrProtocol},
		{"hb without status", `{"v":3,"type":"hb"}`, ErrProtocol},
		{"hb status not an object", `{"v":3,"type":"hb","status":3}`, ErrUnreadable},
		{"not json", `{`, ErrUnreadable},
		{"trailing data", `{"v":3,"type":"hb","status":{}} {}`, ErrUnreadable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Decode([]byte(c.wire)); !errors.Is(err, c.want) {
				t.Fatalf("Decode(%s) err = %v, want %v", c.wire, err, c.want)
			}
		})
	}
}

func TestDecodeAcceptsMinimal(t *testing.T) {
	f, err := Decode([]byte(`{"v":3,"type":"hb","ack":3,"status":{"ready":true}}`))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if f.Ack != 3 || f.Seq != 0 {
		t.Fatalf("frame %+v", f)
	}
	f, err = Decode([]byte(`{"v":3,"type":"audience","gen":34,"all":true}`))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !f.All || f.Seq != 0 || f.AudienceState().Gen != 34 {
		t.Fatalf("frame %+v", f)
	}

	f, err = Decode([]byte(`{"v":3,"type":"hb","ack":3,"status":{"ready":true},"probe":11,"probeAck":10}`))
	if err != nil {
		t.Fatalf("Decode probe: %v", err)
	}
	if f.Probe != 11 || f.ProbeAck != 10 {
		t.Fatalf("probe fields %+v", f)
	}

	f, err = Decode([]byte(`{"v":3,"type":"respond","ack":9,"reqId":"7","chunkSeq":4,"chunk":"aGk=","encoding":"base64","more":true}`))
	if err != nil {
		t.Fatalf("Decode respond: %v", err)
	}
	if f.ChunkSeq != 4 || f.Seq != 0 {
		t.Fatalf("respond %+v", f)
	}
}

func TestHeartbeatProbe(t *testing.T) {
	f, err := NewHeartbeatProbe(7, 0, HeartbeatStatus{Ready: true}, false)
	if err != nil || f.Probe != 0 || f.ProbeAck != 0 {
		t.Fatalf("zero nonce: %+v err %v", f, err)
	}
	f, err = NewHeartbeatProbe(7, 9, HeartbeatStatus{Ready: true}, false)
	if err != nil || f.Probe != 9 || f.ProbeAck != 0 {
		t.Fatalf("probe: %+v err %v", f, err)
	}
	f, err = NewHeartbeatProbe(7, 9, HeartbeatStatus{Ready: true}, true)
	if err != nil || f.Probe != 0 || f.ProbeAck != 9 {
		t.Fatalf("probeAck: %+v err %v", f, err)
	}
}

func TestEncodeRejects(t *testing.T) {
	if _, err := Encode(Frame{V: 1, Type: TypeHeartbeat}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("encode v1 err %v", err)
	}
	if _, err := Encode(Frame{V: ProtocolVersion, Type: TypeEvents, Seq: 1}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("encode empty events err %v", err)
	}
}

func TestValidateEvents(t *testing.T) {
	ok := Frame{V: ProtocolVersion, Type: TypeEvents, Seq: 7, Events: []json.RawMessage{
		json.RawMessage(`{"seq":7}`),
		json.RawMessage(`{"seq":8}`),
		json.RawMessage(`{"seq":9}`),
	}}
	if err := ValidateEvents(ok); err != nil {
		t.Fatalf("ValidateEvents: %v", err)
	}
	hole := Frame{V: ProtocolVersion, Type: TypeEvents, Seq: 7, Events: []json.RawMessage{
		json.RawMessage(`{"seq":7}`),
		json.RawMessage(`{"seq":9}`),
	}}
	if err := ValidateEvents(hole); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("hole err %v", err)
	}
}

func TestTrimmedEvent(t *testing.T) {
	got := string(TrimmedEvent("s1", 7))
	want := `{"type":"trimmed","sessionId":"s1","seq":7}`
	if got != want {
		t.Fatalf("TrimmedEvent = %s, want %s", got, want)
	}
	if !json.Valid(TrimmedEvent(`a"b`, 1)) {
		t.Fatal("TrimmedEvent is not valid JSON for a quoted session id")
	}
}

// TestFrameIdempotencyFieldsRoundTrip: a request carries the relay-layer
// idempotency envelope across encode/decode, with and without a scope.
func TestFrameIdempotencyFieldsRoundTrip(t *testing.T) {
	cases := map[string]Frame{
		"key and scope": {
			V: ProtocolVersion, Type: TypeRequest, Seq: 13, Ack: 100,
			ReqID: "7", Method: "POST", Path: "/api/prompt", Body: json.RawMessage(`{"prompt":"hi"}`),
			IdemKey: "6f1e0c1e-7f5a-4c2b-9d3e-2a1b0c9d8e7f", IdemScope: "user:u1",
		},
		"key only": {
			V: ProtocolVersion, Type: TypeRequest, Seq: 14, Ack: 100,
			ReqID: "8", Method: "POST", Path: "/api/sessions",
			IdemKey: strings.Repeat("k", IdemKeyMaxLen),
		},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			got := roundTrip(t, f)
			if got.IdemKey != f.IdemKey || got.IdemScope != f.IdemScope {
				t.Fatalf("idempotency = %q/%q, want %q/%q", got.IdemKey, got.IdemScope, f.IdemKey, f.IdemScope)
			}
		})
	}
}

// TestFrameRejectsIdempotencyOnNonRequest: the envelope is request-only, so
// any other frame type carrying it is a protocol violation.
func TestFrameRejectsIdempotencyOnNonRequest(t *testing.T) {
	bad := []string{
		`{"v":3,"type":"hb","status":{},"idemKey":"k"}`,
		`{"v":3,"type":"hello","epoch":7,"resume":{"up":0,"down":0},"idemKey":"k"}`,
		`{"v":3,"type":"events","seq":4,"events":[{"seq":4}],"idemScope":"root"}`,
		`{"v":3,"type":"respond","reqId":"7","chunkSeq":1,"idemKey":"k"}`,
		`{"v":3,"type":"audience","gen":4,"idemKey":"k"}`,
	}
	for _, w := range bad {
		if _, err := Decode([]byte(w)); !errors.Is(err, ErrProtocol) {
			t.Fatalf("Decode(%s) err = %v, want ErrProtocol", w, err)
		}
	}
}

// TestFrameRejectsInvalidIdempotencyKey: bounds and charset are enforced on
// both Decode and Encode, and a scope cannot ride without a key.
func TestFrameRejectsInvalidIdempotencyKey(t *testing.T) {
	longKey := strings.Repeat("k", IdemKeyMaxLen+1)
	longScope := strings.Repeat("s", IdemScopeMaxLen+1)
	ok := []string{
		`{"v":3,"type":"request","seq":13,"reqId":"7","method":"POST","path":"/x","idemKey":"` +
			strings.Repeat("k", IdemKeyMaxLen) + `","idemScope":"` + strings.Repeat("s", IdemScopeMaxLen) + `"}`,
		`{"v":3,"type":"request","seq":13,"reqId":"7","method":"POST","path":"/x","idemKey":"has space"}`,
	}
	for _, w := range ok {
		if _, err := Decode([]byte(w)); err != nil {
			t.Fatalf("Decode(%s): %v", w, err)
		}
	}

	bad := []string{
		`{"v":3,"type":"request","seq":13,"reqId":"7","method":"POST","path":"/x","idemKey":"` + longKey + `"}`,
		`{"v":3,"type":"request","seq":13,"reqId":"7","method":"POST","path":"/x","idemKey":"` + longKey + `","idemScope":"root"}`,
		`{"v":3,"type":"request","seq":13,"reqId":"7","method":"POST","path":"/x","idemScope":"root"}`,
		`{"v":3,"type":"request","seq":13,"reqId":"7","method":"POST","path":"/x","idemKey":"k","idemScope":"` + longScope + `"}`,
		`{"v":3,"type":"request","seq":13,"reqId":"7","method":"POST","path":"/x","idemKey":"a\tb"}`,
		`{"v":3,"type":"request","seq":13,"reqId":"7","method":"POST","path":"/x","idemKey":"cl\u00e9"}`,
		`{"v":3,"type":"request","seq":13,"reqId":"7","method":"POST","path":"/x","idemKey":"k","idemScope":"a\tb"}`,
	}
	for _, w := range bad {
		if _, err := Decode([]byte(w)); !errors.Is(err, ErrProtocol) {
			t.Fatalf("Decode(%s) err = %v, want ErrProtocol", w, err)
		}
	}

	// Encode shares the same validation.
	if _, err := Encode(Frame{V: ProtocolVersion, Type: TypeRequest, Seq: 13, ReqID: "7", Method: "POST", Path: "/x", IdemKey: longKey}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("Encode with an oversized key err = %v, want ErrProtocol", err)
	}
	if _, err := Encode(Frame{V: ProtocolVersion, Type: TypeRequest, Seq: 13, ReqID: "7", Method: "POST", Path: "/x", IdemScope: "root"}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("Encode with a scope but no key err = %v, want ErrProtocol", err)
	}
}

// TestEpochAndHubBootAreHandshakeOnly pins PROTOCOL-V2 §2: the session's epoch
// is named in hello / hello_ack and the hub's incarnation only in hello_ack,
// so no later frame can become a second source for either fact.
func TestEpochAndHubBootAreHandshakeOnly(t *testing.T) {
	ok := []string{
		`{"v":3,"type":"hello","epoch":7,"resume":{"up":0,"down":0}}`,
		`{"v":3,"type":"hello_ack","epoch":7,"hubBoot":9,"audience":{"gen":1},"liveness":{"keepalive":5,"idle":20},"limits":{"maxFrame":8388608,"maxRelayBody":29360128}}`,
	}
	for _, w := range ok {
		if _, err := Decode([]byte(w)); err != nil {
			t.Fatalf("Decode(%s): %v", w, err)
		}
	}
	bad := []string{
		`{"v":3,"type":"hb","epoch":7,"status":{}}`,
		`{"v":3,"type":"events","seq":1,"epoch":7,"events":[{"seq":1}]}`,
		`{"v":3,"type":"audience","gen":2,"epoch":7}`,
		`{"v":3,"type":"request","seq":1,"reqId":"7","method":"GET","path":"/x","epoch":7}`,
		`{"v":3,"type":"respond","reqId":"7","chunkSeq":1,"epoch":7}`,
		`{"v":3,"type":"hb","hubBoot":9,"status":{}}`,
		`{"v":3,"type":"hello","epoch":7,"hubBoot":9,"resume":{"up":0,"down":0}}`,
		`{"v":3,"type":"events","seq":1,"hubBoot":9,"events":[{"seq":1}]}`,
	}
	for _, w := range bad {
		if _, err := Decode([]byte(w)); !errors.Is(err, ErrProtocol) {
			t.Fatalf("Decode(%s) err = %v, want ErrProtocol", w, err)
		}
	}
}
