package hub

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestSetLogLevel(t *testing.T) {
	prev := verbose
	t.Cleanup(func() { verbose = prev })

	cases := []struct {
		raw     string
		want    string
		verbose bool
	}{
		{"", LogLevelInfo, false},
		{"info", LogLevelInfo, false},
		{"debug", LogLevelDebug, true},
		{"DEBUG", LogLevelDebug, true},
		{"  debug  ", LogLevelDebug, true},
		{"trace", LogLevelDebug, true},
		// A typo must not mute the always-on lines, so it degrades to info.
		{"debu", LogLevelInfo, false},
		{"warn", LogLevelInfo, false},
	}
	for _, tc := range cases {
		if got := SetLogLevel(tc.raw); got != tc.want {
			t.Errorf("SetLogLevel(%q) = %q, want %q", tc.raw, got, tc.want)
		}
		if Verbose() != tc.verbose {
			t.Errorf("SetLogLevel(%q): Verbose() = %v, want %v", tc.raw, Verbose(), tc.verbose)
		}
	}
}

func TestVerbosefGating(t *testing.T) {
	prev := verbose
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	t.Cleanup(func() {
		verbose = prev
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	log.SetOutput(&buf)
	log.SetFlags(0)

	SetLogLevel(LogLevelInfo)
	Verbosef("[capri-hub] host x event seq regressed: got %d", 1)
	if buf.Len() != 0 {
		t.Fatalf("info level must not emit per-event detail, got %q", buf.String())
	}

	SetLogLevel(LogLevelDebug)
	Verbosef("[capri-hub] host x event seq regressed: got %d", 1)
	if !strings.Contains(buf.String(), "seq regressed") {
		t.Fatalf("debug level must emit per-event detail, got %q", buf.String())
	}
}
