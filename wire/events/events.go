// Package events is the shared table of Capri wire event types.
//
// events.json is the source of truth for the traits the host (and eventually
// the hub) needs to tell transcript from control: what may be dropped under
// outbox pressure, what may be replaced with a trimmed placeholder when nobody
// watches a session, what is terminal, what carries a session id, and how the
// frontend treats the event. Add a new wire type there, not to a per-repo
// string list.
//
// The frontend mirror is generated from the same file by gen/. This package is
// compiled into both binaries; it performs no I/O at runtime.
package events

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// RenderMode says how the frontend treats a wire type.
type RenderMode string

const (
	// RenderTyped events have a dedicated frontend handler.
	RenderTyped RenderMode = "typed"
	// RenderGeneric events go through the generic notification path, or are a
	// forward-compat carrier for kinds the host has not modeled.
	RenderGeneric RenderMode = "generic"
	// RenderIgnored events are known and intentionally not rendered.
	RenderIgnored RenderMode = "ignored"
)

// Traits is the classification of one wire event type.
type Traits struct {
	// Droppable events may be replaced by a trimmed placeholder under outbox
	// pressure; a slow subscriber's queue may also drop them.
	Droppable bool `json:"droppable"`
	// Trimmable events may be replaced by a trimmed placeholder when no
	// browser session is watching the session they belong to.
	Trimmable bool `json:"trimmable"`
	// Terminal events carry turn evidence or a terminal state.
	Terminal bool `json:"terminal"`
	// SessionScoped events carry a sessionId used for audience/guest filtering.
	SessionScoped bool `json:"sessionScoped"`
	// Render is the frontend treatment.
	Render RenderMode `json:"render"`
}

type table struct {
	Version int               `json:"version"`
	Default Traits            `json:"default"`
	Kinds   map[string]Traits `json:"kinds"`
}

//go:embed events.json
var source []byte

var loaded = mustLoad(source)

func mustLoad(raw []byte) table {
	var t table
	if err := json.Unmarshal(raw, &t); err != nil {
		panic(fmt.Sprintf("events: malformed events.json: %v", err))
	}
	if len(t.Kinds) == 0 {
		panic("events: events.json has no kinds")
	}
	validate := func(name string, tr Traits) {
		switch tr.Render {
		case RenderTyped, RenderGeneric, RenderIgnored:
		default:
			panic(fmt.Sprintf("events: %s has invalid render %q", name, tr.Render))
		}
	}
	validate("default", t.Default)
	for name, tr := range t.Kinds {
		validate(name, tr)
	}
	return t
}

// Trait returns the traits for typ, or the table's default for an unlisted
// wire type.
func Trait(typ string) Traits {
	if tr, ok := loaded.Kinds[typ]; ok {
		return tr
	}
	return loaded.Default
}

// Known reports whether typ is explicitly listed in the table.
func Known(typ string) bool {
	_, ok := loaded.Kinds[typ]
	return ok
}

// Droppable reports whether events of typ may be replaced under outbox
// pressure.
func Droppable(typ string) bool { return Trait(typ).Droppable }

// Trimmable reports whether events of typ may be replaced when nobody watches
// their session.
func Trimmable(typ string) bool { return Trait(typ).Trimmable }

// Terminal reports whether events of typ carry turn evidence or a terminal
// state.
func Terminal(typ string) bool { return Trait(typ).Terminal }

// SessionScoped reports whether events of typ carry a session id.
func SessionScoped(typ string) bool { return Trait(typ).SessionScoped }

// Render returns the frontend treatment for typ.
func Render(typ string) RenderMode { return Trait(typ).Render }
