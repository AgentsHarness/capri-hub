package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/quic-go/quic-go"

	"github.com/AgentsHarness/capri-wire"
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

func TestWSBinaryFrameDecoding(t *testing.T) {
	// The hub side of /ws/host: a text message is plain JSON, a binary message
	// is a raw deflate stream once the capability was negotiated.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")
		ctx := context.Background()
		if err := conn.Write(ctx, websocket.MessageText, []byte(`{"v":2,"type":"hb","status":{}}`)); err != nil {
			return
		}
		if err := conn.Write(ctx, websocket.MessageBinary, []byte("not-deflate")); err != nil {
			return
		}
		// Keep the socket open long enough for the client to read both.
		_, _, _ = conn.Read(ctx)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	tr := newWSTransport(conn)

	// Before the deflate echo a binary message is a peer speaking another
	// protocol.
	if _, err := tr.Recv(); err != nil {
		t.Fatalf("text frame: %v", err)
	}
	if _, err := tr.Recv(); !errors.Is(err, wire.ErrUnreadable) {
		t.Fatalf("binary frame without negotiation = %v, want ErrUnreadable", err)
	}

	// With deflate negotiated, a corrupt stream is unreadable too.
	tr.SetDeflate(true)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	conn2, _, err := websocket.Dial(ctx2, "ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", nil)
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer conn2.Close(websocket.StatusNormalClosure, "")
	tr2 := newWSTransport(conn2)
	tr2.SetDeflate(true)
	if _, err := tr2.Recv(); err != nil {
		t.Fatalf("text frame 2: %v", err)
	}
	if _, err := tr2.Recv(); !errors.Is(err, wire.ErrUnreadable) {
		t.Fatalf("corrupt deflate frame = %v, want ErrUnreadable", err)
	}
}
