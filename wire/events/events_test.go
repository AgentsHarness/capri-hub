package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestKindsNonEmpty(t *testing.T) {
	if len(loaded.Kinds) == 0 {
		t.Fatal("events.json has no kinds")
	}
	if loaded.Version < 1 {
		t.Fatalf("version = %d, want >= 1", loaded.Version)
	}
}

func TestRenderValues(t *testing.T) {
	valid := func(r RenderMode) bool {
		return r == RenderTyped || r == RenderGeneric || r == RenderIgnored
	}
	if !valid(loaded.Default.Render) {
		t.Errorf("default render = %q", loaded.Default.Render)
	}
	for name, tr := range loaded.Kinds {
		if !valid(tr.Render) {
			t.Errorf("%s render = %q", name, tr.Render)
		}
	}
}

func TestDefaultTraits(t *testing.T) {
	want := Traits{
		Droppable:     false,
		Trimmable:     true,
		Terminal:      false,
		SessionScoped: false,
		Render:        RenderGeneric,
	}
	if loaded.Default != want {
		t.Fatalf("default = %+v, want %+v", loaded.Default, want)
	}
	if got := Trait("a_type_that_does_not_exist"); got != want {
		t.Fatalf("unknown type traits = %+v, want the default", got)
	}
	if Known("a_type_that_does_not_exist") {
		t.Fatal("unknown type reported as known")
	}
	if !Trimmable("a_type_that_does_not_exist") {
		t.Fatal("unknown types must default to trimmable")
	}
}

func TestNoDuplicateKeys(t *testing.T) {
	dups, err := duplicateObjectKeys(bytes.NewReader(source))
	if err != nil {
		t.Fatal(err)
	}
	if len(dups) != 0 {
		t.Fatalf("duplicate JSON keys: %v", dups)
	}
}

func TestDuplicateKeyScanner(t *testing.T) {
	dups, err := duplicateObjectKeys(strings.NewReader(`{"kinds":{"a":{"x":1,"x":2},"b":{}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(dups) != 1 || dups[0] != "x" {
		t.Fatalf("duplicate keys = %v, want [x]", dups)
	}
}

// TestRequiredWireTypes pins the types the host and frontend already classify;
// a rename in events.json must not silently fall back to the default.
func TestRequiredWireTypes(t *testing.T) {
	want := map[string]struct {
		droppable bool
		trimmable bool
		render    RenderMode
	}{
		"chunk":                   {true, true, RenderTyped},
		"thought":                 {true, true, RenderTyped},
		"user_chunk":              {true, true, RenderTyped},
		"user_message":            {false, true, RenderTyped},
		"text":                    {false, true, RenderTyped},
		"image":                   {false, true, RenderTyped},
		"tool_call":               {false, true, RenderTyped},
		"tool_call_update":        {false, true, RenderTyped},
		"plan":                    {false, true, RenderTyped},
		"session_notification":    {false, true, RenderGeneric},
		"ext_notification":        {false, true, RenderGeneric},
		"turn_completed":          {false, false, RenderTyped},
		"usage":                   {false, false, RenderTyped},
		"gen_rate":                {true, false, RenderTyped},
		"log":                     {true, false, RenderIgnored},
		"session_updates_chunk":   {true, false, RenderIgnored},
		"fs_notify":               {false, false, RenderIgnored},
		"fs_index":                {false, false, RenderIgnored},
		"fs_index_delta":          {false, false, RenderIgnored},
		"search_content_status":   {true, false, RenderIgnored},
		"search_fuzzy_status":     {true, false, RenderTyped},
		"pty_notification":        {false, false, RenderIgnored},
		"leader_reconnected":      {false, false, RenderIgnored},
		"leader_version_mismatch": {false, false, RenderIgnored},
		"git_worktree_status":     {false, false, RenderIgnored},
		"config_changed":          {false, false, RenderIgnored},
		"settings_update":         {false, false, RenderIgnored},
		"trimmed":                 {false, false, RenderIgnored},
	}
	for typ, w := range want {
		tr, ok := loaded.Kinds[typ]
		if !ok {
			t.Errorf("%s missing from events.json", typ)
			continue
		}
		if tr.Droppable != w.droppable || tr.Trimmable != w.trimmable || tr.Render != w.render {
			t.Errorf("%s = %+v, want droppable=%v trimmable=%v render=%v",
				typ, tr, w.droppable, w.trimmable, w.render)
		}
	}
}

func TestTerminalTypes(t *testing.T) {
	for _, typ := range []string{"turn_completed", "tool_call_update", "done", "cancelled", "error"} {
		if !Terminal(typ) {
			t.Errorf("%s must be terminal", typ)
		}
	}
	for _, typ := range []string{"chunk", "plan", "trimmed"} {
		if Terminal(typ) {
			t.Errorf("%s must not be terminal", typ)
		}
	}
}

// duplicateObjectKeys reports every key repeated within the same JSON object.
// encoding/json keeps the last value silently, so the table's shape alone
// cannot prove a key was not shadowed.
func duplicateObjectKeys(r io.Reader) ([]string, error) {
	type frame struct {
		object    bool
		expectKey bool
		keys      map[string]bool
	}
	var stack []*frame
	var dups []string
	dec := json.NewDecoder(r)
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return dups, nil
		}
		if err != nil {
			return nil, err
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{':
				stack = append(stack, &frame{object: true, expectKey: true, keys: map[string]bool{}})
			case '[':
				stack = append(stack, &frame{})
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				if len(stack) > 0 && stack[len(stack)-1].object {
					stack[len(stack)-1].expectKey = true // container value completed
				}
			}
		case string:
			if len(stack) == 0 {
				continue
			}
			top := stack[len(stack)-1]
			if !top.object {
				continue
			}
			if !top.expectKey {
				top.expectKey = true // scalar value completed
				continue
			}
			if top.keys[v] {
				dups = append(dups, v)
			}
			top.keys[v] = true
			top.expectKey = false
		default:
			// Number, bool, or null: a completed scalar value.
			if len(stack) > 0 && stack[len(stack)-1].object {
				stack[len(stack)-1].expectKey = true
			}
		}
	}
}
