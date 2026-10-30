package main

import (
	"bytes"
	"compress/flate"
	"strings"
	"testing"
)

func deflateBytes(t *testing.T, in []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	if _, err := zw.Write(in); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}
	return buf.Bytes()
}

// An uplink frame whose decompressed form exceeds the cap must be an error:
// the WS/QUIC read limits only bound the compressed bytes, so without this
// check a tiny deflate stream could expand to gigabytes inside the hub.
func TestInflateUplinkRejectsOversizedOutput(t *testing.T) {
	prev := maxInflatedFrame
	maxInflatedFrame = 1024
	t.Cleanup(func() { maxInflatedFrame = prev })

	bomb := deflateBytes(t, bytes.Repeat([]byte("a"), 2048))
	if _, err := inflateUplink(bomb); err == nil {
		t.Fatal("inflateUplink accepted a 2KB payload under a 1KB cap")
	}

	small := []byte(strings.Repeat("b", 100))
	if got, err := inflateUplink(deflateBytes(t, small)); err != nil {
		t.Fatalf("inflateUplink(100B): %v", err)
	} else if !bytes.Equal(got, small) {
		t.Fatalf("inflateUplink returned %d bytes, want the original 100", len(got))
	}
}

// The default cap must sit above the host's 28MB relay-response ceiling, or
// a legal large respond would be rejected (and end the session) as
// undecodable.
func TestInflateUplinkDefaultCapAboveRelayCeiling(t *testing.T) {
	const relayResponseCeiling = 28 << 20
	if maxInflatedFrame <= relayResponseCeiling {
		t.Fatalf("maxInflatedFrame = %d, must exceed the %d-byte relay ceiling", maxInflatedFrame, relayResponseCeiling)
	}
}
