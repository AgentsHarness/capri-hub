package wire

import (
	"errors"
	"testing"
)

// TestAudienceCarriesNoSeq: audience is absolute latest-wins state, so it
// stays out of the reliable seq space and is rejected if it takes a seq.
func TestAudienceCarriesNoSeq(t *testing.T) {
	if Reliable(TypeAudience) {
		t.Fatal("audience is treated as a reliable frame")
	}
	f := NewAudience(Audience{Gen: 2, Watchers: 1})
	if f.Seq != 0 || f.Ack != 0 {
		t.Fatalf("audience carries seq %d ack %d", f.Seq, f.Ack)
	}
	if _, err := Encode(f); err != nil {
		t.Fatalf("encode: %v", err)
	}
	f.Seq = 1
	if _, err := Encode(f); !errors.Is(err, ErrProtocol) {
		t.Fatalf("audience with a seq was accepted: %v", err)
	}
}

func TestAudienceValidate(t *testing.T) {
	ok := []Audience{
		{Gen: 1},
		{Gen: 33, Watchers: 2, Sessions: []string{"s1", "s2"}},
		{Gen: 34, All: true},
	}
	for i, a := range ok {
		if err := a.Validate(); err != nil {
			t.Fatalf("case %d %+v: %v", i, a, err)
		}
	}

	bad := []Audience{
		{},                     // gen 0
		{Watchers: 1},          // gen 0
		{Gen: 1, Watchers: -1}, // negative watchers
		{Gen: 1, All: true, Sessions: []string{"s"}}, // narrowed while all
		{Gen: 1, Sessions: []string{"s2", "s1"}},     // unsorted
		{Gen: 1, Sessions: []string{"s1", "s1"}},     // duplicate
		{Gen: 1, Sessions: []string{""}},             // empty id
	}
	for i, a := range bad {
		if err := a.Validate(); !errors.Is(err, ErrProtocol) {
			t.Fatalf("case %d %+v: err %v", i, a, err)
		}
	}
}
