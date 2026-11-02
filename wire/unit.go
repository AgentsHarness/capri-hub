package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// UnitSize is the transport-unit payload target. A frame larger than this is
// split so a control frame can be written between two units instead of waiting
// for the whole frame.
const UnitSize = 32 << 10

// Unit flags.
const (
	UnitCompressed uint8 = 1 << 0
	UnitFragment   uint8 = 1 << 1
)

const unitHeaderSize = 13

// ErrUnit reports a malformed transport unit or an invalid unit sequence.
var ErrUnit = errors.New("wire: malformed transport unit")

// Unit is one transport-unit record: a 13-byte header followed by a slice of
// one frame's payload.
type Unit struct {
	Flags   uint8
	FrameID uint32
	Total   uint32
	Offset  uint32
	Data    []byte
}

// EncodeUnit writes u in the unit wire format. It does not validate u; a
// malformed unit only fails when a receiver decodes it.
func EncodeUnit(u Unit) []byte {
	b := make([]byte, unitHeaderSize+len(u.Data))
	b[0] = u.Flags
	binary.BigEndian.PutUint32(b[1:5], u.FrameID)
	binary.BigEndian.PutUint32(b[5:9], u.Total)
	binary.BigEndian.PutUint32(b[9:13], u.Offset)
	copy(b[unitHeaderSize:], u.Data)
	return b
}

// DecodeUnit parses one unit. A complete unit has Offset 0 and Total equal to
// the data length; a fragment has the fragment flag, Total above zero and ends
// at or before Total. Data aliases b, so a caller that reuses its read buffer
// must copy.
func DecodeUnit(b []byte) (Unit, error) {
	if len(b) < unitHeaderSize {
		return Unit{}, fmt.Errorf("%w: %d bytes, want at least %d", ErrUnit, len(b), unitHeaderSize)
	}
	u := Unit{
		Flags:   b[0],
		FrameID: binary.BigEndian.Uint32(b[1:5]),
		Total:   binary.BigEndian.Uint32(b[5:9]),
		Offset:  binary.BigEndian.Uint32(b[9:13]),
		Data:    b[unitHeaderSize:],
	}
	if u.Flags&^(UnitCompressed|UnitFragment) != 0 {
		return Unit{}, fmt.Errorf("%w: unknown flags %#x", ErrUnit, u.Flags)
	}
	if uint64(u.Offset)+uint64(len(u.Data)) > uint64(u.Total) {
		return Unit{}, fmt.Errorf("%w: offset %d plus %d data bytes exceed total %d", ErrUnit, u.Offset, len(u.Data), u.Total)
	}
	if u.Flags&UnitFragment != 0 {
		if u.Total == 0 {
			return Unit{}, fmt.Errorf("%w: fragment with total 0", ErrUnit)
		}
		return u, nil
	}
	if u.Offset != 0 || uint64(len(u.Data)) != uint64(u.Total) {
		return Unit{}, fmt.Errorf("%w: complete unit at offset %d with %d data bytes and total %d", ErrUnit, u.Offset, len(u.Data), u.Total)
	}
	return u, nil
}

// SplitFrame encodes payload as one complete unit or as a run of fragments of
// at most unitSize payload bytes. A frame that fits in one unit is never
// fragmented, so it can travel while another frame's fragments are open.
func SplitFrame(payload []byte, compressed bool, frameID uint32, unitSize int) ([][]byte, error) {
	if uint64(len(payload)) > math.MaxUint32 {
		return nil, fmt.Errorf("%w: frame of %d bytes does not fit a uint32 total", ErrUnit, len(payload))
	}
	if unitSize <= 0 {
		unitSize = UnitSize
	}
	flags := uint8(0)
	if compressed {
		flags |= UnitCompressed
	}
	total := uint32(len(payload))
	if len(payload) <= unitSize {
		return [][]byte{EncodeUnit(Unit{Flags: flags, FrameID: frameID, Total: total, Data: payload})}, nil
	}
	units := make([][]byte, 0, 1+(len(payload)-1)/unitSize)
	for off := 0; off < len(payload); off += unitSize {
		end := len(payload)
		if remaining := len(payload) - off; unitSize < remaining {
			end = off + unitSize
		}
		units = append(units, EncodeUnit(Unit{
			Flags:   flags | UnitFragment,
			FrameID: frameID,
			Total:   total,
			Offset:  uint32(off),
			Data:    payload[off:end],
		}))
	}
	return units, nil
}

// Reassembler turns units back into frames. One fragmented frame may be open
// at a time; complete units pass through and leave the open frame alone, which
// is how an hb interleaves with a large frame.
type Reassembler struct {
	open       bool
	frameID    uint32
	total      uint32
	compressed bool
	buf        []byte
}

// Accept consumes one raw unit. complete reports that frame is a whole frame:
// either a complete unit that arrived on its own, or the last fragment of the
// open frame, which resets the reassembler. While a frame is still assembling,
// complete is false and compressed reports the open frame's flag. maxFrame
// above zero rejects any frame whose total exceeds it. Errors wrap ErrUnit.
func (r *Reassembler) Accept(raw []byte, maxFrame int) (frame []byte, compressed bool, complete bool, err error) {
	u, err := DecodeUnit(raw)
	if err != nil {
		return nil, false, false, err
	}
	if maxFrame > 0 && uint64(u.Total) > uint64(maxFrame) {
		return nil, false, false, fmt.Errorf("%w: frame total %d exceeds maxFrame %d", ErrUnit, u.Total, maxFrame)
	}
	fragCompressed := u.Flags&UnitCompressed != 0

	if u.Flags&UnitFragment == 0 {
		if r.open && u.FrameID == r.frameID {
			return nil, false, false, fmt.Errorf("%w: frame %d completes while its fragments are open", ErrUnit, u.FrameID)
		}
		out := make([]byte, len(u.Data))
		copy(out, u.Data)
		return out, fragCompressed, true, nil
	}

	if !r.open {
		if u.Offset != 0 {
			return nil, false, false, fmt.Errorf("%w: frame %d opens at offset %d", ErrUnit, u.FrameID, u.Offset)
		}
		r.open = true
		r.frameID = u.FrameID
		r.total = u.Total
		r.compressed = fragCompressed
		r.buf = append([]byte(nil), u.Data...)
	} else {
		switch {
		case u.FrameID != r.frameID:
			return nil, false, false, fmt.Errorf("%w: fragment for frame %d while %d is open", ErrUnit, u.FrameID, r.frameID)
		case fragCompressed != r.compressed:
			return nil, false, false, fmt.Errorf("%w: frame %d fragment changes the compressed flag", ErrUnit, u.FrameID)
		case uint64(u.Offset) != uint64(len(r.buf)):
			return nil, false, false, fmt.Errorf("%w: frame %d fragment at offset %d, want %d", ErrUnit, u.FrameID, u.Offset, len(r.buf))
		}
		r.buf = append(r.buf, u.Data...)
	}
	if uint64(len(r.buf)) < uint64(r.total) {
		return nil, r.compressed, false, nil
	}
	if uint64(len(r.buf)) > uint64(r.total) {
		return nil, false, false, fmt.Errorf("%w: frame %d assembled %d bytes, total %d", ErrUnit, r.frameID, len(r.buf), r.total)
	}
	out, comp := r.buf, r.compressed
	r.Reset()
	return out, comp, true, nil
}

// Reset drops an open fragmented frame and its partial payload.
func (r *Reassembler) Reset() {
	r.open = false
	r.frameID = 0
	r.total = 0
	r.compressed = false
	r.buf = nil
}
