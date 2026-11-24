package wire

import (
	"errors"
	"testing"
)

func TestDefaults(t *testing.T) {
	if err := ValidateLiveness(DefaultLiveness); err != nil {
		t.Fatalf("DefaultLiveness: %v", err)
	}
	if err := ValidateLimits(DefaultLimits); err != nil {
		t.Fatalf("DefaultLimits: %v", err)
	}
	if DefaultLiveness.Idle < 2*DefaultLiveness.Keepalive {
		t.Fatalf("default idle %d is below 2*keepalive %d", DefaultLiveness.Idle, DefaultLiveness.Keepalive)
	}
}

func TestValidateLiveness(t *testing.T) {
	ok := []Liveness{
		{Keepalive: 1, Idle: 2},
		{Keepalive: 5, Idle: 20},
		{Keepalive: 60, Idle: 300},
	}
	for _, l := range ok {
		if err := ValidateLiveness(l); err != nil {
			t.Fatalf("%+v: %v", l, err)
		}
	}
	bad := []Liveness{
		{},                         // keepalive 0
		{Keepalive: 0, Idle: 20},   // keepalive 0
		{Keepalive: 61, Idle: 300}, // keepalive above 60
		{Keepalive: 5, Idle: 9},    // idle below 2*keepalive
		{Keepalive: 5, Idle: 301},  // idle above 300
	}
	for _, l := range bad {
		if err := ValidateLiveness(l); !errors.Is(err, ErrProtocol) {
			t.Fatalf("%+v: err %v", l, err)
		}
	}
}

func TestValidateLimits(t *testing.T) {
	ok := []Limits{
		{MaxFrame: 1 << 10, MaxRelayBody: 1 << 10},
		DefaultLimits,
		{MaxFrame: 64 << 20, MaxRelayBody: 256 << 20},
	}
	for _, l := range ok {
		if err := ValidateLimits(l); err != nil {
			t.Fatalf("%+v: %v", l, err)
		}
	}
	bad := []Limits{
		{}, // all zero
		{MaxFrame: 1, MaxRelayBody: 1 << 20},
		{MaxFrame: 1024, MaxRelayBody: 1},
		{MaxFrame: 65 << 20, MaxRelayBody: 1 << 20},
		{MaxFrame: 1024, MaxRelayBody: 257 << 20},
	}
	for _, l := range bad {
		if err := ValidateLimits(l); !errors.Is(err, ErrProtocol) {
			t.Fatalf("%+v: err %v", l, err)
		}
	}
}
