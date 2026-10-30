// Package wire is the capri host↔hub v2 session protocol: the frame model,
// the sender and receiver state machines, liveness/limit defaults and the one
// close-reason table both transports share.
//
// It is deliberately transport-agnostic and side-effect free — no websocket,
// QUIC, net or os imports — so capri-host and capri-hub cannot drift apart on
// the protocol.
package wire

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ProtocolVersion is the only envelope version this module speaks.
const ProtocolVersion = 2

// Frame types.
const (
	TypeHello     = "hello"
	TypeHelloAck  = "hello_ack"
	TypeEvents    = "events"
	TypeAudience  = "audience"
	TypeRequest   = "request"
	TypeRespond   = "respond"
	TypeHeartbeat = "hb"
)

// Decode errors. A caller maps ErrProtocol to close(protocol) and ErrUnreadable
// to close(unreadable): the first means the peer speaks a different protocol,
// the second that a frame arrived mangled and the sender must replay from its
// log rather than have its watermark jump.
var (
	ErrProtocol   = errors.New("wire: protocol violation")
	ErrUnreadable = errors.New("wire: unreadable frame")
)

// Reliable reports whether frames of this type consume this direction's seq
// space. respond is relay-plane and carries no session seq.
func Reliable(frameType string) bool {
	switch frameType {
	case TypeEvents, TypeAudience, TypeRequest:
		return true
	}
	return false
}

func knownType(frameType string) bool {
	switch frameType {
	case TypeHello, TypeHelloAck, TypeEvents, TypeAudience, TypeRequest, TypeRespond, TypeHeartbeat:
		return true
	}
	return false
}

// Frame is the v2 envelope. Every frame type is this one struct: fields are
// omitted when zero, so a hello, an events batch and a heartbeat all encode
// from the same shape.
//
// seq belongs to reliable frames only; respond carries its delivery proof at
// the relay layer instead. ack is this direction's watermark for the opposite
// direction and may be 0 only while nothing has been received.
type Frame struct {
	V    int    `json:"v"`
	Type string `json:"type"`
	Seq  uint64 `json:"seq,omitempty"`
	Ack  uint64 `json:"ack,omitempty"`

	// hello / hello_ack
	Epoch    uint64    `json:"epoch,omitempty"`
	HubBoot  uint64    `json:"hubBoot,omitempty"`
	Token    string    `json:"token,omitempty"`
	Resume   *Resume   `json:"resume,omitempty"`
	Caps     *Caps     `json:"caps,omitempty"`
	AckUp    uint64    `json:"ackUp,omitempty"`
	AckDown  uint64    `json:"ackDown,omitempty"`
	Audience *Audience `json:"audience,omitempty"`
	Liveness *Liveness `json:"liveness,omitempty"`
	Limits   *Limits   `json:"limits,omitempty"`

	// events
	Events []json.RawMessage `json:"events,omitempty"`

	// audience (absolute state, flat on the wire)
	Gen      uint64   `json:"gen,omitempty"`
	Watchers int      `json:"watchers,omitempty"`
	All      bool     `json:"all,omitempty"`
	Sessions []string `json:"sessions,omitempty"`

	// request / respond (relay plane)
	ReqID    string          `json:"reqId,omitempty"`
	Method   string          `json:"method,omitempty"`
	Path     string          `json:"path,omitempty"`
	Body     json.RawMessage `json:"body,omitempty"`
	Chunk    string          `json:"chunk,omitempty"`
	Encoding string          `json:"encoding,omitempty"`
	More     bool            `json:"more,omitempty"`

	// Status is the one envelope key whose shape depends on the frame type: a
	// HeartbeatStatus object on hb, the HTTP status code on respond. It stays
	// raw here; use Heartbeat/RespondStatus and their setters to reach the
	// typed view.
	Status json.RawMessage `json:"status,omitempty"`
}

// Hello is the host's opening frame. epoch identifies the sequence space, so a
// reconnect with the same epoch resumes and a new one resets both directions.
type Hello struct {
	Epoch  uint64  `json:"epoch"`
	Token  string  `json:"token,omitempty"`
	Resume *Resume `json:"resume,omitempty"`
	Caps   *Caps   `json:"caps,omitempty"`
}

// Resume states what the host already holds: up is the highest hub→host seq it
// applied, down the highest host→hub seq it believes the hub applied.
type Resume struct {
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

// Caps is the capability offer/echo. Deflate is only usable after the hub
// echoes it in hello_ack.
type Caps struct {
	Deflate bool `json:"deflate,omitempty"`
}

// HelloAck is the hub's answer. AckUp and AckDown are authoritative: the host
// adopts them instead of its own records.
//
// HubBoot identifies the hub process that minted this ack. A hub restart
// resets its own request-id counter, so a reqId is only meaningful inside one
// hubBoot: relay state keyed by reqId must also carry it.
type HelloAck struct {
	Epoch    uint64    `json:"epoch"`
	HubBoot  uint64    `json:"hubBoot"`
	AckUp    uint64    `json:"ackUp,omitempty"`
	AckDown  uint64    `json:"ackDown,omitempty"`
	Audience *Audience `json:"audience,omitempty"`
	Liveness *Liveness `json:"liveness,omitempty"`
	Limits   *Limits   `json:"limits,omitempty"`
	Caps     *Caps     `json:"caps,omitempty"`
}

// Audience is the absolute viewer state for one host. Gen orders snapshots
// across sessions and is never reset by an epoch change; equal gen is a
// duplicate that is applied once and still acked. All means the audience
// cannot be narrowed, so Sessions must be empty.
//
// A zero Watchers is omitted on the wire, which decodes back to zero — the
// same "nobody is watching, pause upload" meaning.
type Audience struct {
	Gen      uint64   `json:"gen,omitempty"`
	Watchers int      `json:"watchers,omitempty"`
	All      bool     `json:"all,omitempty"`
	Sessions []string `json:"sessions,omitempty"`
}

// Validate checks the absolute-state invariants a receiver may not guess at.
func (a Audience) Validate() error {
	switch {
	case a.Gen == 0:
		return fmt.Errorf("%w: audience gen 0", ErrProtocol)
	case a.Watchers < 0:
		return fmt.Errorf("%w: audience watchers %d", ErrProtocol, a.Watchers)
	case a.All && len(a.Sessions) > 0:
		return fmt.Errorf("%w: audience all=true carries %d sessions", ErrProtocol, len(a.Sessions))
	}
	for i, s := range a.Sessions {
		if s == "" {
			return fmt.Errorf("%w: audience session %d is empty", ErrProtocol, i)
		}
		if i > 0 && a.Sessions[i-1] >= s {
			return fmt.Errorf("%w: audience sessions not sorted or not deduped at %d", ErrProtocol, i)
		}
	}
	return nil
}

// Liveness is the hub's advertised time scale, in seconds. Idle must be at
// least 2*keepalive so a single lost heartbeat never kills a healthy session.
type Liveness struct {
	Keepalive int `json:"keepalive,omitempty"`
	Idle      int `json:"idle,omitempty"`
}

// Limits replaces the constants both sides used to duplicate.
type Limits struct {
	MaxFrame     int `json:"maxFrame,omitempty"`
	MaxRelayBody int `json:"maxRelayBody,omitempty"`
	ResumeWindow int `json:"resumeWindow,omitempty"`
}

// HeartbeatStatus is the hb snapshot. A lost hb is corrected by the next one;
// nothing here is acknowledged.
type HeartbeatStatus struct {
	Ready        bool `json:"ready,omitempty"`
	Busy         bool `json:"busy,omitempty"`
	Booting      bool `json:"booting,omitempty"`
	PendingCount int  `json:"pendingCount,omitempty"`
	Port         int  `json:"port,omitempty"`
}

// Encode marshals f after validating it. It never assigns a seq: that is the
// Sender's job, and renumbering at encode time would break retransmission.
func Encode(f Frame) ([]byte, error) {
	if err := f.validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("wire: encode: %w", err)
	}
	return b, nil
}

// Decode parses and validates one frame. Validation is strict — unknown
// versions and types, a seq on an unreliable frame, a missing mandatory
// payload or a non-contiguous events batch all fail here, because none of them
// can be repaired by skipping the frame.
func Decode(b []byte) (Frame, error) {
	var f Frame
	if err := json.Unmarshal(b, &f); err != nil {
		return Frame{}, fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	if err := f.validate(); err != nil {
		return Frame{}, err
	}
	return f, nil
}

func (f Frame) validate() error {
	if f.V != ProtocolVersion {
		return fmt.Errorf("%w: version %d, want %d", ErrProtocol, f.V, ProtocolVersion)
	}
	if !knownType(f.Type) {
		return fmt.Errorf("%w: unknown frame type %q", ErrProtocol, f.Type)
	}
	if Reliable(f.Type) {
		if f.Seq == 0 {
			return fmt.Errorf("%w: %s without seq", ErrProtocol, f.Type)
		}
	} else if f.Seq != 0 {
		return fmt.Errorf("%w: %s carries seq %d", ErrProtocol, f.Type, f.Seq)
	}
	// The session's epoch and the hub's incarnation are named once, in the
	// handshake. Carrying them on any other frame would create a second,
	// possibly conflicting, source for the same fact.
	if f.Type != TypeHello && f.Type != TypeHelloAck && f.Epoch != 0 {
		return fmt.Errorf("%w: %s carries epoch %d", ErrProtocol, f.Type, f.Epoch)
	}
	if f.Type != TypeHelloAck && f.HubBoot != 0 {
		return fmt.Errorf("%w: %s carries hubBoot %d", ErrProtocol, f.Type, f.HubBoot)
	}

	switch f.Type {
	case TypeHello:
		if f.Epoch == 0 {
			return fmt.Errorf("%w: hello without epoch", ErrProtocol)
		}
		if f.Resume == nil {
			return fmt.Errorf("%w: hello without resume", ErrProtocol)
		}
	case TypeHelloAck:
		if f.Epoch == 0 {
			return fmt.Errorf("%w: hello_ack without epoch", ErrProtocol)
		}
		if f.HubBoot == 0 {
			return fmt.Errorf("%w: hello_ack without hubBoot", ErrProtocol)
		}
		if f.Audience == nil || f.Liveness == nil || f.Limits == nil {
			return fmt.Errorf("%w: hello_ack without audience, liveness or limits", ErrProtocol)
		}
		if err := f.Audience.Validate(); err != nil {
			return err
		}
		if err := ValidateLiveness(*f.Liveness); err != nil {
			return err
		}
		if err := ValidateLimits(*f.Limits); err != nil {
			return err
		}
	case TypeEvents:
		return ValidateEvents(f)
	case TypeAudience:
		return f.AudienceState().Validate()
	case TypeRequest:
		if f.ReqID == "" || f.Method == "" || f.Path == "" {
			return fmt.Errorf("%w: request without reqId, method or path", ErrProtocol)
		}
	case TypeRespond:
		if f.ReqID == "" {
			return fmt.Errorf("%w: respond without reqId", ErrProtocol)
		}
	case TypeHeartbeat:
		if len(f.Status) == 0 {
			return fmt.Errorf("%w: hb without status", ErrProtocol)
		}
		if _, err := f.Heartbeat(); err != nil {
			return err
		}
	}
	return nil
}

// ValidateEvents checks that the batch is one contiguous run starting at
// frame.seq. A sender that would open a hole must split the batch instead; a
// receiver that sees a hole closes with unreadable rather than letting the
// watermark jump over it.
func ValidateEvents(f Frame) error {
	if len(f.Events) == 0 {
		return fmt.Errorf("%w: events frame without events", ErrProtocol)
	}
	seq := f.Seq
	for i, raw := range f.Events {
		var ev struct {
			Seq uint64 `json:"seq"`
		}
		if err := json.Unmarshal(raw, &ev); err != nil {
			return fmt.Errorf("%w: event %d: %v", ErrUnreadable, i, err)
		}
		if ev.Seq != seq {
			return fmt.Errorf("%w: event %d has seq %d, want %d", ErrUnreadable, i, ev.Seq, seq)
		}
		seq++
	}
	return nil
}

// TrimmedEvent renders the canonical placeholder that replaces a discarded
// payload: the seq is kept, so the run stays gapless.
func TrimmedEvent(sessionID string, seq uint64) []byte {
	b, err := json.Marshal(struct {
		Type      string `json:"type"`
		SessionID string `json:"sessionId"`
		Seq       uint64 `json:"seq"`
	}{"trimmed", sessionID, seq})
	if err != nil {
		// Three primitives cannot fail to marshal.
		return nil
	}
	return b
}

// Hello returns the typed hello payload carried by f.
func (f Frame) Hello() (Hello, error) {
	if f.Type != TypeHello {
		return Hello{}, fmt.Errorf("wire: frame type %q is not hello", f.Type)
	}
	return Hello{Epoch: f.Epoch, Token: f.Token, Resume: f.Resume, Caps: f.Caps}, nil
}

// HelloAck returns the typed hello_ack payload carried by f.
func (f Frame) HelloAck() (HelloAck, error) {
	if f.Type != TypeHelloAck {
		return HelloAck{}, fmt.Errorf("wire: frame type %q is not hello_ack", f.Type)
	}
	return HelloAck{
		Epoch:    f.Epoch,
		HubBoot:  f.HubBoot,
		AckUp:    f.AckUp,
		AckDown:  f.AckDown,
		Audience: f.Audience,
		Liveness: f.Liveness,
		Limits:   f.Limits,
		Caps:     f.Caps,
	}, nil
}

// AudienceState returns the absolute audience carried by an audience frame.
func (f Frame) AudienceState() Audience {
	return Audience{Gen: f.Gen, Watchers: f.Watchers, All: f.All, Sessions: f.Sessions}
}

// SetAudienceState writes a into an audience frame's flat envelope fields.
func (f *Frame) SetAudienceState(a Audience) {
	f.Gen, f.Watchers, f.All, f.Sessions = a.Gen, a.Watchers, a.All, a.Sessions
}

// Heartbeat returns the snapshot carried by an hb frame.
func (f Frame) Heartbeat() (HeartbeatStatus, error) {
	var st HeartbeatStatus
	if len(f.Status) == 0 {
		return st, fmt.Errorf("%w: hb without status", ErrProtocol)
	}
	if err := json.Unmarshal(f.Status, &st); err != nil {
		return st, fmt.Errorf("%w: hb status: %v", ErrUnreadable, err)
	}
	return st, nil
}

// SetHeartbeat stores st as an hb frame's status.
func (f *Frame) SetHeartbeat(st HeartbeatStatus) error {
	b, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("wire: hb status: %w", err)
	}
	f.Status = b
	return nil
}

// RespondStatus returns a respond frame's HTTP status code, 0 when absent.
func (f Frame) RespondStatus() int {
	var code int
	if len(f.Status) == 0 || json.Unmarshal(f.Status, &code) != nil {
		return 0
	}
	return code
}

// SetRespondStatus stores a respond frame's HTTP status code.
func (f *Frame) SetRespondStatus(code int) {
	b, err := json.Marshal(code)
	if err != nil {
		return
	}
	f.Status = b
}

// NewHello builds a hello frame.
func NewHello(h Hello) Frame {
	return Frame{V: ProtocolVersion, Type: TypeHello, Epoch: h.Epoch, Token: h.Token, Resume: h.Resume, Caps: h.Caps}
}

// NewHelloAck builds a hello_ack frame.
func NewHelloAck(a HelloAck) Frame {
	return Frame{
		V:        ProtocolVersion,
		Type:     TypeHelloAck,
		Epoch:    a.Epoch,
		HubBoot:  a.HubBoot,
		AckUp:    a.AckUp,
		AckDown:  a.AckDown,
		Audience: a.Audience,
		Liveness: a.Liveness,
		Limits:   a.Limits,
		Caps:     a.Caps,
	}
}

// NewAudience builds an audience frame.
func NewAudience(seq, ack uint64, a Audience) Frame {
	f := Frame{V: ProtocolVersion, Type: TypeAudience, Seq: seq, Ack: ack}
	f.SetAudienceState(a)
	return f
}

// NewHeartbeat builds an hb frame.
func NewHeartbeat(ack uint64, st HeartbeatStatus) (Frame, error) {
	f := Frame{V: ProtocolVersion, Type: TypeHeartbeat, Ack: ack}
	if err := f.SetHeartbeat(st); err != nil {
		return Frame{}, err
	}
	return f, nil
}
