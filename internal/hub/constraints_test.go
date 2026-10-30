package hub

import (
	"testing"

	"github.com/AgentsHarness/capri-hub/wire"
)

// hostReplayCap mirrors capri-host internal/hub/client.go's replayCap: the
// host replays at most this many events after a reconnect. It lives in the
// other repository, so the inequality below is the only machine check that
// the two buffers still fit together — change EITHER side and re-check both.
const hostReplayCap = 1000

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

// TestLivenessScaleIsSelfConsistent pins the one liveness invariant the
// session relies on: a single lost heartbeat must never close a healthy
// session, so the idle budget is at least two keepalive intervals.
func TestLivenessScaleIsSelfConsistent(t *testing.T) {
	if err := wire.ValidateLiveness(SessionLiveness); err != nil {
		t.Fatalf("advertised liveness %+v is invalid: %v", SessionLiveness, err)
	}
	if SessionLiveness.Idle < 2*SessionLiveness.Keepalive {
		t.Fatalf("idle %ds is below two keepalive intervals (%ds)",
			SessionLiveness.Idle, SessionLiveness.Keepalive)
	}
}
