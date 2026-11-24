// Command gen renders acp-hub/wire/events/events.json into the frontend's
// TypeScript mirror. Run it from the events directory:
//
//	go run ./gen -out ../../../acp-fe/src/api/types/events.generated.ts
//
// The output is sorted by wire type so regeneration produces no noise.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

type trait struct {
	Droppable     bool   `json:"droppable"`
	Trimmable     bool   `json:"trimmable"`
	Terminal      bool   `json:"terminal"`
	SessionScoped bool   `json:"sessionScoped"`
	Render        string `json:"render"`
}

type table struct {
	Version int              `json:"version"`
	Kinds   map[string]trait `json:"kinds"`
}

func main() {
	in := flag.String("in", "events.json", "path to events.json")
	out := flag.String("out", "../../../acp-fe/src/api/types/events.generated.ts", "output TypeScript file")
	flag.Parse()

	raw, err := os.ReadFile(*in)
	if err != nil {
		fatal(err)
	}
	var t table
	if err := json.Unmarshal(raw, &t); err != nil {
		fatal(fmt.Errorf("%s: %w", *in, err))
	}
	if len(t.Kinds) == 0 {
		fatal(fmt.Errorf("%s: no kinds", *in))
	}

	names := make([]string, 0, len(t.Kinds))
	for name, tr := range t.Kinds {
		switch tr.Render {
		case "typed", "generic", "ignored":
		default:
			fatal(fmt.Errorf("%s: invalid render %q", name, tr.Render))
		}
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString(`/**
 * 由 acp-hub/wire/events/gen 从 events.json 生成，禁止手改。
 * 重新生成：cd acp-hub/wire/events && go run ./gen
 */

export type HostEventRender = 'typed' | 'generic' | 'ignored'

export type HostEventTrait = {
  readonly droppable: boolean
  readonly trimmable: boolean
  readonly terminal: boolean
  readonly sessionScoped: boolean
  readonly render: HostEventRender
}

export const HOST_EVENT_TRAITS: Readonly<Record<string, HostEventTrait>> = {
`)
	for _, name := range names {
		tr := t.Kinds[name]
		fmt.Fprintf(&b, "  '%s': { droppable: %t, trimmable: %t, terminal: %t, sessionScoped: %t, render: '%s' },\n",
			name, tr.Droppable, tr.Trimmable, tr.Terminal, tr.SessionScoped, tr.Render)
	}
	b.WriteString("}\n\n")
	b.WriteString("/** render: \"ignored\" 的事件：FE 已知且有意不渲染。 */\n")
	b.WriteString("export const SILENT_HOST_TYPES: ReadonlySet<string> = new Set([\n")
	for _, name := range names {
		if t.Kinds[name].Render == "ignored" {
			fmt.Fprintf(&b, "  '%s',\n", name)
		}
	}
	b.WriteString("])\n")

	if err := os.WriteFile(*out, []byte(b.String()), 0o644); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gen:", err)
	os.Exit(1)
}
