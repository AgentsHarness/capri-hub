package wire

import (
	"fmt"
	"testing"
)

func TestCloseReasonTable(t *testing.T) {
	all := []CloseReason{
		CloseNormal, CloseShutdown, CloseSuperseded, CloseAuth,
		CloseProtocol, CloseLiveness, CloseOverflow, CloseUnreadable,
	}
	if len(all) != 8 {
		t.Fatalf("table has %d reasons", len(all))
	}

	wsPairs := make(map[string]CloseReason, len(all))
	codeOwners := make(map[uint64]CloseReason, len(all))
	for _, r := range all {
		if !r.Valid() {
			t.Fatalf("%d is not valid", r)
		}
		name := r.String()
		if name == "" || name == "closeReason(" {
			t.Fatalf("reason %d has no name", r)
		}
		code, reason := r.WS()
		if reason == "" {
			t.Fatalf("%s has an empty WS reason", name)
		}
		key := fmt.Sprintf("%d|%s", code, reason)
		if prev, dup := wsPairs[key]; dup {
			t.Fatalf("%s and %s share the WS pair (%d, %q)", prev, name, code, reason)
		}
		wsPairs[key] = r

		q := r.QUICCode()
		if prev, dup := codeOwners[q]; dup {
			t.Fatalf("%s and %s share QUIC code %d", prev, name, q)
		}
		codeOwners[q] = r

		if got, ok := CloseReasonFromWS(code, reason); !ok || got != r {
			t.Fatalf("WS round trip of %s gave %v %v", name, got, ok)
		}
		if got, ok := CloseReasonFromQUIC(q); !ok || got != r {
			t.Fatalf("QUIC round trip of %s gave %v %v", name, got, ok)
		}
	}

	if got, ok := CloseReasonFromQUIC(0); !ok || got != CloseNormal {
		t.Fatalf("QUIC 0 is not normal: %v %v", got, ok)
	}
	if _, ok := CloseReasonFromWS(1002, "nope"); ok {
		t.Fatal("unknown WS reason resolved")
	}
}

func TestCloseReasonInvalid(t *testing.T) {
	var zero CloseReason
	if zero.Valid() {
		t.Fatal("zero value is valid")
	}
	if zero.String() != "closeReason(0)" {
		t.Fatalf("zero String = %q", zero.String())
	}
	if code, reason := zero.WS(); code != 1011 || reason == "" {
		t.Fatalf("zero WS = (%d, %q)", code, reason)
	}
	if code := CloseReason(200); code.Valid() {
		t.Fatal("out-of-range reason is valid")
	}
}
