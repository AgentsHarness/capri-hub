package wire

import (
	"fmt"
	"time"
)

// ResumeWindow is how many out-of-order frames a Receiver parks before it gives
// up with ErrOverflow.
const ResumeWindow = 1500

// Probe and heartbeat cadence, shared so host and hub act on the same clock.
const (
	ProbeAfter    = 7 * time.Second // no frame for this long -> send probe
	ProbeTimeout  = 3 * time.Second // no response -> close liveness
	BusyKeepalive = 1 * time.Second // hb cadence while a turn is active
)

// Defaults. Liveness and Limits are advertised by the hub in hello_ack; these
// are what a fresh peer assumes and what the hub itself uses. Treat them as
// read-only.
var (
	DefaultLiveness = Liveness{Keepalive: 5, Idle: 20}
	DefaultLimits   = Limits{MaxFrame: 8 << 20, MaxRelayBody: 28 << 20, ResumeWindow: ResumeWindow}
)

// ValidateLiveness rejects a time scale that would make a single lost heartbeat
// fatal or an idle session look alive forever.
func ValidateLiveness(l Liveness) error {
	switch {
	case l.Keepalive < 1 || l.Keepalive > 60:
		return fmt.Errorf("%w: liveness keepalive %ds outside 1..60", ErrProtocol, l.Keepalive)
	case l.Idle < 2*l.Keepalive:
		return fmt.Errorf("%w: liveness idle %ds below 2*keepalive (%ds)", ErrProtocol, l.Idle, 2*l.Keepalive)
	case l.Idle > 300:
		return fmt.Errorf("%w: liveness idle %ds above 300", ErrProtocol, l.Idle)
	}
	return nil
}

// ValidateLimits rejects limits that are missing or beyond what the
// implementation can buffer.
func ValidateLimits(l Limits) error {
	switch {
	case l.MaxFrame < 1<<10 || l.MaxFrame > 64<<20:
		return fmt.Errorf("%w: limits maxFrame %d outside 1KiB..64MiB", ErrProtocol, l.MaxFrame)
	case l.MaxRelayBody < 1<<10 || l.MaxRelayBody > 256<<20:
		return fmt.Errorf("%w: limits maxRelayBody %d outside 1KiB..256MiB", ErrProtocol, l.MaxRelayBody)
	case l.ResumeWindow < 1 || l.ResumeWindow > 1<<20:
		return fmt.Errorf("%w: limits resumeWindow %d outside 1..1048576", ErrProtocol, l.ResumeWindow)
	}
	return nil
}
