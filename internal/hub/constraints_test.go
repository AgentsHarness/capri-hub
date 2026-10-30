package hub

import (
	"testing"
	"time"
)

// hostReplayCap mirrors capri-host internal/hub/client.go's replayCap: the
// host replays at most this many events after a reconnect. It lives in the
// other repository, so the inequality below is the only machine check that
// the two buffers still fit together — change EITHER side and re-check both.
const hostReplayCap = 1000

// hostDefaultSessionIdleTimeout mirrors capri-host's
// defaultSessionIdleTimeout, the DOWNLINK watchdog that applies before the
// hub has advertised its own numbers. It is a floor, not an exact match:
// hello.idleTimeout is derived from the hub's sweep (see hostIdleTimeout in
// cmd/capri-hub) and the host adopts what it receives.
const hostDefaultSessionIdleTimeout = 20 * time.Second

// hostProbeHeartbeat mirrors capri-host's probeHeartbeatInterval: the
// host_status cadence against a hub that advertises hello.probe. That beat
// is the slowest periodic uplink frame a healthy but quiet host sends.
const hostProbeHeartbeat = 15 * time.Second

// TestEventBufCapCoversHostReplayRing locks the cross-repo invariant argued
// in eventBufCap's doc comment: the hub's gap-pull buffer must be at least
// as large as the host's replay ring, or the oldest replayed events are
// compacted away and the FE's ordered-delivery buffer waits forever on a
// predecessor that exists on neither side.
func TestEventBufCapCoversHostReplayRing(t *testing.T) {
	if eventBufCap < hostReplayCap {
		t.Fatalf("eventBufCap = %d, must be >= the host replay ring (%d): "+
			"a smaller hub buffer silently drops the oldest replayed events",
			eventBufCap, hostReplayCap)
	}
	if evBufHighWater <= eventBufCap {
		t.Fatalf("evBufHighWater = %d must exceed eventBufCap = %d", evBufHighWater, eventBufCap)
	}
}

// TestLivenessScaleBeatsHostHeartbeat pins the cross-repo inequality that
// decides whether a quiet host flaps: the sweep must outlast the slowest
// periodic uplink frame the host sends, with room for one lost beat. When
// the sweep is shorter than hostProbeHeartbeat, every idle period produces
// an offline flip that only the next beat undoes — a healthy host that
// keeps "disconnecting" in the browser.
func TestLivenessScaleBeatsHostHeartbeat(t *testing.T) {
	// Two beats: one to arrive, one in case the first was lost.
	if min := 2 * hostProbeHeartbeat; HostSilenceTimeout < min {
		t.Fatalf("HostSilenceTimeout = %s must cover two host heartbeats (%s), "+
			"or an idle host is swept offline between beats",
			HostSilenceTimeout, min)
	}
}

// TestLivenessScaleMatchesHostDefault pins the other cross-repo inequality:
// hello.idleTimeout (hub.HostSilenceTimeout + 2 sweep intervals, see
// hostIdleTimeout in cmd/capri-hub) must outlast the point where the
// registry flips. If the host gave up first, browsers would see a host that
// is reconnecting while still listed online.
func TestLivenessScaleMatchesHostDefault(t *testing.T) {
	advertised := HostSilenceTimeout + 2*LivenessCheckInterval
	if advertised <= HostSilenceTimeout+LivenessCheckInterval {
		t.Fatalf("advertised idleTimeout %s must exceed the sweep's worst case %s",
			advertised, HostSilenceTimeout+LivenessCheckInterval)
	}
	// The host's own fallback must never be shorter than what we advertise,
	// or a host that ignores hello.idleTimeout would drop the session before
	// the registry converges.
	if advertised > hostDefaultSessionIdleTimeout*4 {
		t.Fatalf("advertised idleTimeout %s has grown far past the host default %s; "+
			"re-check both sides together", advertised, hostDefaultSessionIdleTimeout)
	}
}
