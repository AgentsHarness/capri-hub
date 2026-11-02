package main

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/quic-go/quic-go"

	"github.com/AgentsHarness/capri-hub/wire"
)

// The uplink decoders accept two framings per transport — bare JSON and a raw
// deflate stream — and must reject a corrupt stream as unreadable so the
// session closes with that verdict and the host replays from the hub's
// watermark.

func TestParseUplinkLen(t *testing.T) {
	n, compressed := parseUplinkLen(7)
	if n != 7 || compressed {
		t.Fatalf("bare prefix = %d/%v", n, compressed)
	}
	n, compressed = parseUplinkLen(uplinkCompressedFlag | 7)
	if n != 7 || !compressed {
		t.Fatalf("flagged prefix = %d/%v", n, compressed)
	}
}

// writeQUICFrame writes one length-prefixed frame, optionally deflated.
func writeQUICFrame(t *testing.T, s *quic.Stream, payload []byte, compress bool) {
	t.Helper()
	body := payload
	if compress {
		body = deflateBytes(t, payload)
	}
	var prefix [4]byte
	v := uint32(len(body))
	if compress {
		v |= uplinkCompressedFlag
	}
	prefix[0], prefix[1], prefix[2], prefix[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
	if _, err := s.Write(prefix[:]); err != nil {
		t.Fatalf("prefix: %v", err)
	}
	if _, err := s.Write(body); err != nil {
		t.Fatalf("body: %v", err)
	}
}

// writeControlUnit writes payload as a complete transport unit on a control
// stream (a length-prefixed unit, compressed inside the unit when requested).
func writeControlUnit(s *quic.Stream, payload []byte, compressed bool, frameID uint32) error {
	if compressed {
		var err error
		if payload, err = deflateRaw(payload); err != nil {
			return err
		}
	}
	units, err := wire.SplitFrame(payload, compressed, frameID, 0)
	if err != nil {
		return err
	}
	for _, unit := range units {
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], uint32(len(unit)))
		if _, err := s.Write(prefix[:]); err != nil {
			return err
		}
		if _, err := s.Write(unit); err != nil {
			return err
		}
	}
	return nil
}

// writeRawControlUnit writes one already-encoded unit.
func writeRawControlUnit(s *quic.Stream, unit []byte) error {
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(unit)))
	if _, err := s.Write(prefix[:]); err != nil {
		return err
	}
	_, err := s.Write(unit)
	return err
}

// readControlUnit reads one length-prefixed unit and returns its complete
// frame payload. A fragment or an invalid unit is an error.
func readControlUnit(s *quic.Stream) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(s, prefix[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n > hostFrameLimit {
		return nil, fmt.Errorf("unit too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(s, buf); err != nil {
		return nil, err
	}
	u, err := wire.DecodeUnit(buf)
	if err != nil {
		return nil, err
	}
	if u.Flags&wire.UnitFragment != 0 || u.Flags&wire.UnitCompressed != 0 {
		return nil, fmt.Errorf("expected one uncompressed complete unit, got flags %#x", u.Flags)
	}
	return u.Data, nil
}

// deflateRaw is deflateBytes without a testing.T.
func deflateRaw(in []byte) ([]byte, error) {
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := fw.Write(in); err != nil {
		return nil, err
	}
	if err := fw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func TestQUICControlFrameDecoding(t *testing.T) {
	tlsConf, err := quicTLSConfig(true)
	if err != nil {
		t.Fatalf("tls: %v", err)
	}
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConf, &quic.Config{})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	bare := []byte(`{"v":2,"type":"hb","ack":3,"status":{}}`)
	big := []byte(`{"v":2,"type":"hb","ack":4,"status":{"ready":true,"busy":true,"port":8765,"padding":"` +
		strings.Repeat("z", 2048) + `"}}`)

	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			serverDone <- err
			return
		}
		// The server opens the stream: a bidirectional stream is only
		// announced to the peer once it carries data, so the reader must be
		// the side that waits.
		stream, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			serverDone <- err
			return
		}
		writeQUICFrame(t, stream, bare, false)
		writeQUICFrame(t, stream, big, true)
		// A flagged prefix followed by bytes that are not a deflate stream.
		var prefix [4]byte
		v := uint32(5) | uplinkCompressedFlag
		prefix[0], prefix[1], prefix[2], prefix[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
		if _, err := stream.Write(prefix[:]); err != nil {
			serverDone <- err
			return
		}
		if _, err := stream.Write([]byte{0xff, 0xff, 0xff, 0xff, 0xff}); err != nil {
			serverDone <- err
			return
		}
		serverDone <- stream.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addr := ln.Addr().(*net.UDPAddr)
	conn, err := quic.DialAddr(ctx, addr.String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"capri-hub"},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept stream: %v", err)
	}

	got, err := readQUICFrame(stream, 0)
	if err != nil {
		t.Fatalf("bare frame: %v", err)
	}
	if string(got) != string(bare) {
		t.Fatalf("bare frame = %s", got)
	}

	got, err = readQUICFrame(stream, 0)
	if err != nil {
		t.Fatalf("deflated frame: %v", err)
	}
	if string(got) != string(big) {
		t.Fatalf("deflated frame decoded %d bytes, want %d", len(got), len(big))
	}

	if _, err := readQUICFrame(stream, 0); !errors.Is(err, wire.ErrUnreadable) {
		t.Fatalf("corrupt deflate stream error = %v, want ErrUnreadable", err)
	}
	if err := <-serverDone; err != nil {
		t.Logf("server stream close: %v", err)
	}
}

// TestWSUnitReassembly: a binary message is a transport unit; fragments of
// one frame may be interleaved with a text control frame, and a complete
// compressed unit is inflated after the deflate echo.
func TestWSUnitReassembly(t *testing.T) {
	payload := []byte(`{"v":2,"type":"events","seq":1,"events":[{"type":"chunk","seq":1,"text":"` +
		strings.Repeat("x", 4096) + `"}]}`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")
		ctx := context.Background()
		hb := []byte(`{"v":2,"type":"hb","status":{}}`)
		if err := conn.Write(ctx, websocket.MessageText, hb); err != nil {
			return
		}
		units, err := wire.SplitFrame(payload, false, 7, 256)
		if err != nil {
			return
		}
		for i, unit := range units {
			if i == len(units)/2 {
				if err := conn.Write(ctx, websocket.MessageText, hb); err != nil {
					return
				}
			}
			if err := conn.Write(ctx, websocket.MessageBinary, unit); err != nil {
				return
			}
		}
		compressed, err := deflateRaw(payload)
		if err != nil {
			return
		}
		compressedUnits, err := wire.SplitFrame(compressed, true, 8, 0)
		if err != nil {
			return
		}
		if err := conn.Write(ctx, websocket.MessageBinary, compressedUnits[0]); err != nil {
			return
		}
		_, _, _ = conn.Read(ctx)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	tr := newWSTransport(conn)
	tr.SetDeflate(true)

	if got, err := tr.Recv(); err != nil || string(got) != string(hbBytes()) {
		t.Fatalf("first hb = %s, %v", got, err)
	}
	if got, err := tr.Recv(); err != nil || string(got) != string(hbBytes()) {
		t.Fatalf("interleaved hb = %s, %v", got, err)
	}
	if got, err := tr.Recv(); err != nil || string(got) != string(payload) {
		t.Fatalf("reassembled frame = %d bytes, %v; want %d", len(got), err, len(payload))
	}
	if got, err := tr.Recv(); err != nil || string(got) != string(payload) {
		t.Fatalf("inflated frame = %d bytes, %v; want %d", len(got), err, len(payload))
	}
	if tr.LastActivity().IsZero() {
		t.Fatal("LastActivity was not updated by reads")
	}
}

func hbBytes() []byte { return []byte(`{"v":2,"type":"hb","status":{}}`) }

// TestWSUnitDecodeFailures: binary garbage is unreadable, and a compressed
// unit before the deflate echo is a protocol violation, not a frame to skip.
func TestWSUnitDecodeFailures(t *testing.T) {
	serve := func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")
		ctx := context.Background()
		if err := conn.Write(ctx, websocket.MessageText, hbBytes()); err != nil {
			return
		}
		if err := conn.Write(ctx, websocket.MessageBinary, []byte("not-a-unit")); err != nil {
			return
		}
		if err := conn.Write(ctx, websocket.MessageBinary, compressedEventsUnit(t)); err != nil {
			return
		}
		_, _, _ = conn.Read(ctx)
	}
	srv := httptest.NewServer(http.HandlerFunc(serve))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	tr := newWSTransport(conn)
	if _, err := tr.Recv(); err != nil {
		t.Fatalf("text hb: %v", err)
	}
	if _, err := tr.Recv(); !errors.Is(err, wire.ErrUnreadable) {
		t.Fatalf("binary garbage = %v, want ErrUnreadable", err)
	}

	conn2, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", nil)
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer conn2.Close(websocket.StatusNormalClosure, "")
	tr2 := newWSTransport(conn2)
	if _, err := tr2.Recv(); err != nil {
		t.Fatalf("text hb 2: %v", err)
	}
	if _, err := tr2.Recv(); !errors.Is(err, wire.ErrUnreadable) {
		t.Fatalf("compressed unit without negotiation = %v, want ErrUnreadable", err)
	}
}

// compressedEventsUnit returns one complete compressed unit carrying a frame.
func compressedEventsUnit(t *testing.T) []byte {
	t.Helper()
	body, err := deflateRaw([]byte(`{"v":2,"type":"events","seq":1,"events":[{"type":"chunk","seq":1}]}`))
	if err != nil {
		t.Fatalf("deflate: %v", err)
	}
	units, err := wire.SplitFrame(body, true, 3, 0)
	if err != nil || len(units) != 1 {
		t.Fatalf("split compressed frame: %v (%d units)", err, len(units))
	}
	return units[0]
}

// TestQUICControlUnitReassembly: the control stream carries units, so a
// fragmented frame can be interleaved with an hb and a compressed unit is
// inflated at the end.
func TestQUICControlUnitReassembly(t *testing.T) {
	tlsConf, err := quicTLSConfig(true)
	if err != nil {
		t.Fatalf("tls: %v", err)
	}
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConf, &quic.Config{})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	payload := []byte(`{"v":2,"type":"events","seq":1,"events":[{"type":"chunk","seq":1,"text":"` +
		strings.Repeat("y", 4096) + `"}]}`)

	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			serverDone <- err
			return
		}
		stream, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			serverDone <- err
			return
		}
		if err := writeControlUnit(stream, hbBytes(), false, 10); err != nil {
			serverDone <- err
			return
		}
		units, err := wire.SplitFrame(payload, false, 11, 256)
		if err != nil {
			serverDone <- err
			return
		}
		for i, unit := range units {
			if i == len(units)/2 {
				if err := writeControlUnit(stream, hbBytes(), false, 12); err != nil {
					serverDone <- err
					return
				}
			}
			if err := writeRawControlUnit(stream, unit); err != nil {
				serverDone <- err
				return
			}
		}
		if err := writeControlUnit(stream, payload, true, 13); err != nil {
			serverDone <- err
			return
		}
		serverDone <- stream.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"capri-hub"},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept stream: %v", err)
	}
	tr := newQUICTransport(conn, stream)
	defer tr.Close(wire.CloseNormal)
	tr.SetDeflate(true)
	tr.SetMaxFrame(32 << 20)

	if got, err := tr.Recv(); err != nil || string(got) != string(hbBytes()) {
		t.Fatalf("first hb = %s, %v", got, err)
	}
	if got, err := tr.Recv(); err != nil || string(got) != string(hbBytes()) {
		t.Fatalf("interleaved hb = %s, %v", got, err)
	}
	if got, err := tr.Recv(); err != nil || string(got) != string(payload) {
		t.Fatalf("reassembled frame = %d bytes, %v; want %d", len(got), err, len(payload))
	}
	if got, err := tr.Recv(); err != nil || string(got) != string(payload) {
		t.Fatalf("inflated frame = %d bytes, %v; want %d", len(got), err, len(payload))
	}
	if tr.LastActivity().IsZero() {
		t.Fatal("LastActivity was not updated by control reads")
	}
	if err := <-serverDone; err != nil {
		t.Logf("server stream close: %v", err)
	}
}

// TestQUICControlFrameIDsAvoidFragments: control units and the writer's
// fragments share the control stream; their frameID namespaces must not
// overlap or an interleaved hb would look like a complete unit inside the open
// fragment and be rejected as unreadable.
func TestQUICControlFrameIDsAvoidFragments(t *testing.T) {
	tr := &quicTransport{}
	for i := 0; i < 8; i++ {
		if id := tr.nextFrameID(); id < 1<<31 {
			t.Fatalf("control frame id %d overlaps the writer's fragment ids", id)
		}
	}
}
