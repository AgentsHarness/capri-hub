package hub

import (
	"encoding/json"
	"testing"
)

// TestEncodeViewingViewWireShape pins the exact standalone frame the host
// decodes: a top-level "type":"viewing" plus flat all/sessions (and gen on
// the gen-stamped form). The frame is edge-triggered, so a shape the host
// does not switch on is silently dropped and the filter only refreshes on
// the next 25s ping.
func TestEncodeViewingViewWireShape(t *testing.T) {
	if got, want := encodeViewingView(ViewingView{Sessions: []string{"s1", "s2"}}),
		`{"v":1,"type":"viewing","all":false,"sessions":["s1","s2"]}`; got != want {
		t.Fatalf("encodeViewingView = %s, want %s", got, want)
	}
	if got, want := encodeViewingViewGen(ViewingView{Sessions: []string{"s1", "s2"}}, 7),
		`{"v":1,"type":"viewing","all":false,"sessions":["s1","s2"],"gen":7}`; got != want {
		t.Fatalf("encodeViewingViewGen = %s, want %s", got, want)
	}
	if got, want := encodeViewingViewGen(ViewingView{All: true}, 9),
		`{"v":1,"type":"viewing","all":true,"gen":9}`; got != want {
		t.Fatalf("encodeViewingViewGen(all) = %s, want %s", got, want)
	}
	// The dedupe key is gen-free and canonical: two encodes of the same set
	// must match, and no gen leaks into the key.
	if a, b := encodeViewingView(ViewingView{All: true}), encodeViewingView(ViewingView{All: true}); a != b {
		t.Fatalf("dedupe key is not canonical: %q vs %q", a, b)
	}
	var key map[string]json.RawMessage
	if err := json.Unmarshal([]byte(encodeViewingView(ViewingView{All: true})), &key); err != nil {
		t.Fatalf("dedupe key is not JSON: %v", err)
	}
	if _, ok := key["gen"]; ok {
		t.Fatal("dedupe key must not carry gen")
	}

	// Exact top-level key set of the gen-stamped frame: shape drift here must
	// fail loudly rather than degrade to an ignored frame.
	var frame map[string]json.RawMessage
	if err := json.Unmarshal([]byte(encodeViewingViewGen(ViewingView{Sessions: []string{"s1"}}, 3)), &frame); err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	for _, k := range []string{"v", "type", "all", "sessions", "gen"} {
		if _, ok := frame[k]; !ok {
			t.Errorf("frame is missing top-level %q: %v", k, frame)
		}
	}
	if len(frame) != 5 {
		t.Errorf("frame top-level keys = %v, want exactly v/type/all/sessions/gen", frame)
	}
}
