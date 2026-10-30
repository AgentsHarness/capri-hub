package wire

import "testing"

func TestNewEpoch(t *testing.T) {
	a, err := NewEpoch()
	if err != nil {
		t.Fatalf("NewEpoch: %v", err)
	}
	if a == 0 {
		t.Fatal("NewEpoch returned 0")
	}
	b, err := NewEpoch()
	if err != nil {
		t.Fatalf("NewEpoch: %v", err)
	}
	if a == b {
		t.Fatalf("two epochs collided at %d", a)
	}
	for i := 0; i < 1000; i++ {
		e, err := NewEpoch()
		if err != nil {
			t.Fatalf("NewEpoch: %v", err)
		}
		if e == 0 {
			t.Fatal("NewEpoch returned 0")
		}
	}
}
