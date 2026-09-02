package hub

import (
	"log"
	"strings"
)

// Log verbosity. Only two tiers exist: everything that matters for operating
// the hub (pairing, connect/disconnect, real errors) always logs, while the
// lines that fire once *per event* are gated behind debug. A host that
// restarts mid-session can otherwise emit one such line for every event it
// pushes, which is enough to fill a journald ring in hours.
const (
	LogLevelInfo  = "info"
	LogLevelDebug = "debug"
)

var verbose bool

// SetLogLevel maps the CAPRI_LOG_LEVEL environment variable onto process-wide
// verbosity and returns the effective level. "debug" (and the legacy "trace")
// enable per-event detail; anything else, including an unset or misspelled
// value, stays at info so a typo cannot mute real errors or surprise operators.
func SetLogLevel(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case LogLevelDebug, "trace":
		verbose = true
		return LogLevelDebug
	default:
		verbose = false
		return LogLevelInfo
	}
}

// Verbose reports whether per-event detail logging is enabled.
func Verbose() bool { return verbose }

// Verbosef logs a per-event diagnostic only when debug level is active.
func Verbosef(format string, args ...any) {
	if verbose {
		log.Printf(format, args...)
	}
}
