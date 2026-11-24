package main

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
	"sync"
	"time"
)

// ── host→hub uplink flate compression ─────────────────────────────────
//
// Hub side: frames arrive either as bare JSON (WS text message / QUIC length
// prefix without the flag bit) or as one raw-deflate stream of the JSON
// payload (WS binary message / QUIC length prefix with the top bit set).
// Payloads below the host's compression floor are never compressed, but the
// hub accepts any flagged frame regardless of size.

// uplinkCompressedFlag is bit 31 of the QUIC 4-byte length prefix, marking the
// frame body as a raw-deflate stream.
const uplinkCompressedFlag = 1 << 31

// parseUplinkLen splits a QUIC uplink length prefix into the true frame length
// and the compressed flag (top bit).
func parseUplinkLen(n uint32) (length uint32, compressed bool) {
	return n &^ uplinkCompressedFlag, n&uplinkCompressedFlag != 0
}

// maxInflatedFrame caps the DECOMPRESSED size of one uplink frame. Both
// transports bound the compressed bytes only, and a deflate stream expands far
// beyond its input — a small frame could otherwise balloon to gigabytes inside
// the hub. It stays above the 28MB relay-response ceiling so a big but valid
// response is not mistaken for a bad frame.
var maxInflatedFrame = 32 << 20

// inflateUplink decompresses one raw-deflate uplink payload back into the
// original JSON frame bytes.
func inflateUplink(b []byte) ([]byte, error) {
	zr := flate.NewReader(bytes.NewReader(b))
	defer zr.Close()
	// One byte past the cap distinguishes "exactly at the cap" from over it.
	out, err := io.ReadAll(io.LimitReader(zr, int64(maxInflatedFrame)+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxInflatedFrame {
		return nil, fmt.Errorf("inflated uplink frame exceeds %d bytes", maxInflatedFrame)
	}
	return out, nil
}

// maxFESubscribers caps concurrent browser /ws/fe connections: each one
// costs a 512-event channel plus two goroutines, and with FE_TOKEN unset
// the endpoint is open to anyone. Excess connections get WS close 1013
// (Try Again Later).
const maxFESubscribers = 256

// minCompressSize: event frames below this size skip flate compression —
// the flate header + sync marker overhead is not worth it, and browsers
// get to skip a decompression step.
const minCompressSize = 256

// FE WS liveness cadence (T7): protocol-level Ping every interval, pong
// must arrive within the timeout or the subscriber is reclaimed. Vars
// (not consts) so tests can tighten them.
var (
	feLivenessInterval = 20 * time.Second
	feLivenessTimeout  = 10 * time.Second
)

// Pooled flate writers/buffers for the compressed /ws/fe path: under
// chunk storms writeEventsFrame runs per frame, and a fresh
// flate.Writer + bytes.Buffer per frame would hammer the GC.
// flate.Writer.Reset re-targets a writer after Close, so pooled writers
// are fully reusable.
var (
	flateWriterPool = sync.Pool{
		New: func() any {
			fw, _ := flate.NewWriter(io.Discard, flate.BestSpeed)
			return fw
		},
	}
	flateBufPool = sync.Pool{
		New: func() any { return new(bytes.Buffer) },
	}
)
