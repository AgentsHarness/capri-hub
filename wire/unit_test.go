package wire

import (
	"bytes"
	"errors"
	"testing"
)

func TestUnitRoundTrip(t *testing.T) {
	cases := []Unit{
		{FrameID: 1},
		{Flags: UnitCompressed, FrameID: 2, Total: 4, Data: []byte("data")},
		{Flags: UnitFragment, FrameID: 3, Total: 10, Offset: 4, Data: []byte("aaaaaa")},
		{Flags: UnitFragment, FrameID: 8, Total: 3, Data: []byte("abc")},
		{Flags: UnitCompressed | UnitFragment, FrameID: 4, Total: 300, Data: bytes.Repeat([]byte("x"), 200)},
	}
	for _, want := range cases {
		got, err := DecodeUnit(EncodeUnit(want))
		if err != nil {
			t.Fatalf("%+v: %v", want, err)
		}
		if got.Flags != want.Flags || got.FrameID != want.FrameID || got.Total != want.Total || got.Offset != want.Offset ||
			!bytes.Equal(got.Data, want.Data) {
			t.Fatalf("round trip\n got %+v\nwant %+v", got, want)
		}
	}
}

func TestDecodeUnitRejects(t *testing.T) {
	cases := map[string][]byte{
		"empty":              nil,
		"short header":       make([]byte, unitHeaderSize-1),
		"unknown flags":      EncodeUnit(Unit{Flags: 1 << 2, FrameID: 1}),
		"past total":         EncodeUnit(Unit{Flags: UnitFragment, FrameID: 1, Total: 5, Offset: 3, Data: []byte("abc")}),
		"fragment total 0":   EncodeUnit(Unit{Flags: UnitFragment, FrameID: 1}),
		"complete at offset": EncodeUnit(Unit{FrameID: 1, Total: 5, Offset: 1, Data: []byte("abcd")}),
		"complete short":     EncodeUnit(Unit{FrameID: 1, Total: 6, Data: []byte("abcde")}),
		"complete long":      EncodeUnit(Unit{FrameID: 1, Total: 4, Data: []byte("abcde")}),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeUnit(raw); !errors.Is(err, ErrUnit) {
				t.Fatalf("DecodeUnit err = %v, want ErrUnit", err)
			}
		})
	}
}

func TestSplitFrameSingleUnit(t *testing.T) {
	for _, size := range []int{0, 1, UnitSize} {
		payload := bytes.Repeat([]byte{0x7a}, size)
		units, err := SplitFrame(payload, false, 7, 0)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if len(units) != 1 {
			t.Fatalf("size %d split into %d units", size, len(units))
		}
		u, err := DecodeUnit(units[0])
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if u.Flags&UnitFragment != 0 || u.Offset != 0 || u.Total != uint32(size) || u.FrameID != 7 {
			t.Fatalf("size %d: %+v", size, u)
		}
		if !bytes.Equal(u.Data, payload) {
			t.Fatalf("size %d: payload mismatch", size)
		}
	}
}

func TestSplitFrameFragments(t *testing.T) {
	payload := bytes.Repeat([]byte("abcdefgh"), 40)
	units, err := SplitFrame(payload, true, 11, 7)
	if err != nil {
		t.Fatalf("SplitFrame: %v", err)
	}
	if want := (len(payload) + 6) / 7; len(units) != want {
		t.Fatalf("%d units, want %d", len(units), want)
	}
	var joined []byte
	for i, raw := range units {
		u, err := DecodeUnit(raw)
		if err != nil {
			t.Fatalf("unit %d: %v", i, err)
		}
		if u.Flags&UnitFragment == 0 || u.Flags&UnitCompressed == 0 {
			t.Fatalf("unit %d flags %#x", i, u.Flags)
		}
		if u.FrameID != 11 || u.Total != uint32(len(payload)) || u.Offset != uint32(i*7) {
			t.Fatalf("unit %d header %+v", i, u)
		}
		joined = append(joined, u.Data...)
	}
	if !bytes.Equal(joined, payload) {
		t.Fatal("fragments do not join back to the payload")
	}
}

func TestSplitReassemble(t *testing.T) {
	for _, size := range []int{0, 1, UnitSize - 1, UnitSize, UnitSize + 1, 3*UnitSize + 17} {
		for _, unitSize := range []int{0, 64} {
			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(i*31 + 7)
			}
			units, err := SplitFrame(payload, true, 5, unitSize)
			if err != nil {
				t.Fatalf("size %d: %v", size, err)
			}
			var r Reassembler
			for i, raw := range units {
				frame, compressed, complete, err := r.Accept(raw, len(payload))
				if err != nil {
					t.Fatalf("size %d unit %d: %v", size, i, err)
				}
				if i < len(units)-1 {
					if complete || frame != nil {
						t.Fatalf("size %d unit %d: complete %v frame %d bytes", size, i, complete, len(frame))
					}
					continue
				}
				if !complete {
					t.Fatalf("size %d: final unit did not complete", size)
				}
				if !compressed {
					t.Fatalf("size %d: compressed flag lost", size)
				}
				if !bytes.Equal(frame, payload) {
					t.Fatalf("size %d: reassembled %d bytes, want %d", size, len(frame), len(payload))
				}
			}
		}
	}
}

func TestReassemblerInterleavesCompleteUnit(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 10)
	units, err := SplitFrame(payload, false, 1, 4)
	if err != nil {
		t.Fatalf("SplitFrame: %v", err)
	}
	control, err := SplitFrame([]byte(`{"v":2,"type":"hb"}`), false, 99, 0)
	if err != nil {
		t.Fatalf("SplitFrame control: %v", err)
	}

	var r Reassembler
	if frame, _, complete, err := r.Accept(units[0], 0); err != nil || complete || frame != nil {
		t.Fatalf("first fragment: frame %v complete %v err %v", frame, complete, err)
	}
	frame, _, complete, err := r.Accept(control[0], 0)
	if err != nil || !complete || string(frame) != `{"v":2,"type":"hb"}` {
		t.Fatalf("interleaved complete: %q complete %v err %v", frame, complete, err)
	}
	if frame, _, complete, err := r.Accept(units[1], 0); err != nil || complete || frame != nil {
		t.Fatalf("second fragment: frame %v complete %v err %v", frame, complete, err)
	}
	if _, _, complete, err := r.Accept(control[0], 0); err != nil || !complete {
		t.Fatalf("second interleaved complete: complete %v err %v", complete, err)
	}
	frame, _, complete, err = r.Accept(units[2], 0)
	if err != nil || !complete || !bytes.Equal(frame, payload) {
		t.Fatalf("final fragment: %q complete %v err %v", frame, complete, err)
	}
}

func TestReassemblerRejects(t *testing.T) {
	payload := bytes.Repeat([]byte("y"), 12)
	units, err := SplitFrame(payload, false, 1, 4)
	if err != nil {
		t.Fatalf("SplitFrame: %v", err)
	}
	other, err := SplitFrame(payload, false, 2, 4)
	if err != nil {
		t.Fatalf("SplitFrame: %v", err)
	}

	cases := []struct {
		name  string
		first [][]byte
		raw   []byte
	}{
		{"out of order open", nil, units[1]},
		{"different frameID", units[:1], other[0]},
		{"offset mismatch", units[:1], units[2]},
		{"complete for open frameID", units[:1], EncodeUnit(Unit{FrameID: 1, Total: 0})},
		{"changed compressed flag", units[:1], EncodeUnit(Unit{Flags: UnitCompressed | UnitFragment, FrameID: 1, Total: uint32(len(payload)), Offset: 4, Data: []byte("yyyy")})},
		{"malformed header", units[:1], make([]byte, unitHeaderSize-1)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var r Reassembler
			for _, raw := range c.first {
				if _, _, _, err := r.Accept(raw, 0); err != nil {
					t.Fatalf("setup: %v", err)
				}
			}
			if _, _, _, err := r.Accept(c.raw, 0); !errors.Is(err, ErrUnit) {
				t.Fatalf("err = %v, want ErrUnit", err)
			}
		})
	}
}

func TestReassemblerMaxFrame(t *testing.T) {
	payload := bytes.Repeat([]byte("z"), 100)
	units, err := SplitFrame(payload, false, 1, 16)
	if err != nil {
		t.Fatalf("SplitFrame: %v", err)
	}
	var r Reassembler
	if _, _, _, err := r.Accept(units[0], 50); !errors.Is(err, ErrUnit) {
		t.Fatalf("fragment over maxFrame: %v", err)
	}
	complete, err := SplitFrame(payload, false, 2, 0)
	if err != nil {
		t.Fatalf("SplitFrame: %v", err)
	}
	if _, _, _, err := r.Accept(complete[0], 50); !errors.Is(err, ErrUnit) {
		t.Fatalf("complete over maxFrame: %v", err)
	}
	if _, _, got, err := r.Accept(complete[0], len(payload)); err != nil || !got {
		t.Fatalf("exact maxFrame: complete %v err %v", got, err)
	}
}

func TestReassemblerReset(t *testing.T) {
	payload := bytes.Repeat([]byte("q"), 8)
	units, err := SplitFrame(payload, false, 1, 4)
	if err != nil {
		t.Fatalf("SplitFrame: %v", err)
	}
	var r Reassembler
	if _, _, _, err := r.Accept(units[0], 0); err != nil {
		t.Fatalf("first fragment: %v", err)
	}
	r.Reset()
	if _, _, _, err := r.Accept(units[1], 0); !errors.Is(err, ErrUnit) {
		t.Fatalf("fragment after reset: %v", err)
	}
	if _, _, _, err := r.Accept(units[0], 0); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	frame, _, complete, err := r.Accept(units[1], 0)
	if err != nil || !complete || !bytes.Equal(frame, payload) {
		t.Fatalf("reassembled %q complete %v err %v", frame, complete, err)
	}
}
