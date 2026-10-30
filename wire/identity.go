package wire

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strconv"
)

// NewEpoch returns a fresh session epoch. Zero means "no session", so a zero
// draw is retried; two calls never collide in practice.
func NewEpoch() (uint64, error) {
	var b [8]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, fmt.Errorf("wire: epoch: %w", err)
		}
		if e := binary.LittleEndian.Uint64(b[:]); e != 0 {
			return e, nil
		}
	}
}

// CloseReason says why a session ended. The host switches its reconnect policy
// on this enum, never on a string: superseded redials at once, auth re-pairs,
// everything else backs off.
type CloseReason uint8

// The zero value is deliberately not a reason: every close path names itself.
const (
	CloseNormal CloseReason = iota + 1
	CloseShutdown
	CloseSuperseded
	CloseAuth
	CloseProtocol
	CloseLiveness
	CloseOverflow
	CloseUnreadable
)

// closeTable is the single mapping for both transports. WS carries
// (code, reason); QUIC has only an application error code. The two must always
// describe the same verdict, and the QUIC codes are wire contract — never
// renumber them.
var closeTable = [...]struct {
	name     string
	wsCode   int
	wsReason string
	quic     uint64
}{
	CloseNormal:     {name: "normal", wsCode: 1000, wsReason: "normal", quic: 0},
	CloseShutdown:   {name: "shutdown", wsCode: 1000, wsReason: "shutdown", quic: 8},
	CloseSuperseded: {name: "superseded", wsCode: 1000, wsReason: "superseded", quic: 2},
	CloseAuth:       {name: "auth", wsCode: 1008, wsReason: "auth", quic: 3},
	CloseProtocol:   {name: "protocol", wsCode: 1002, wsReason: "protocol version", quic: 4},
	CloseLiveness:   {name: "liveness", wsCode: 1008, wsReason: "liveness", quic: 5},
	CloseOverflow:   {name: "overflow", wsCode: 1011, wsReason: "overflow", quic: 10},
	CloseUnreadable: {name: "unreadable", wsCode: 1011, wsReason: "unreadable", quic: 9},
}

// invalidClose is what an unset reason maps to: an internal error, which makes
// the peer reconnect with backoff instead of re-pairing.
const invalidClose = 1011

// Valid reports whether r is one of the eight protocol reasons.
func (r CloseReason) Valid() bool { return r >= CloseNormal && r <= CloseUnreadable }

// String is the stable lowercase name of the reason.
func (r CloseReason) String() string {
	if !r.Valid() {
		return "closeReason(" + strconv.Itoa(int(r)) + ")"
	}
	return closeTable[r].name
}

// WS returns the WebSocket close pair for r.
func (r CloseReason) WS() (code int, reason string) {
	if !r.Valid() {
		return invalidClose, "invalid reason"
	}
	return closeTable[r].wsCode, closeTable[r].wsReason
}

// QUICCode returns the QUIC application error code for r.
func (r CloseReason) QUICCode() uint64 {
	if !r.Valid() {
		return 1
	}
	return closeTable[r].quic
}

// CloseReasonFromWS maps a peer's close back to the enum. An unknown pair was
// an ordinary drop, so callers fall back to backoff.
func CloseReasonFromWS(code int, reason string) (CloseReason, bool) {
	for i := CloseNormal; i <= CloseUnreadable; i++ {
		if closeTable[i].wsCode == code && closeTable[i].wsReason == reason {
			return i, true
		}
	}
	return 0, false
}

// CloseReasonFromQUIC maps a peer's application error code back to the enum.
func CloseReasonFromQUIC(code uint64) (CloseReason, bool) {
	for i := CloseNormal; i <= CloseUnreadable; i++ {
		if closeTable[i].quic == code {
			return i, true
		}
	}
	return 0, false
}
