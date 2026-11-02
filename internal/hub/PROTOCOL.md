# PROTOCOL — hub-side transport notes

The host ↔ hub session protocol is specified once in
`wire/PROTOCOL-V2.md` and implemented by
`github.com/AgentsHarness/capri-hub/wire` (frame model, sender/receiver, close
reasons). That document is the single source of truth; this file only records
what the hub's transports do with a frame and in what order.

Reliability model and fault matrix: see `wire/PROTOCOL-V2.md` and the protocol
lecture page `docs/session-v2-protocol-lecture.html`.

## 1. Frame envelope

Every frame is one JSON object, `{"v":2,"type":...,"seq":N,"ack":M}`.

- The first frame on a fresh transport is always `hello`; the hub answers
  `hello_ack` and owns down-seq assignment, the up watermark,
  retransmission and the idle timer from then on.
- Reliable types carry a seq (`events`, `audience`, `request`). Unreliable
  ones must not (`hello`, `hello_ack`, `hb`, `respond`).
- `ack` is the sender's watermark over the opposite direction and rides
  every frame that can carry it.
- `audience` is absolute state: the hub keeps at most one unacknowledged
  audience frame and may replace its payload under the same seq. A receiver
  applies a newer `gen` even when the frame's seq is already delivered.
- No capability headers exist. `hello` and `hello_ack` are the only frames
  that name an epoch; the hub also names its process in `hello_ack.hubBoot`.

## 2. Handshake order

1. The transport is accepted (WS upgrade or QUIC control stream).
2. `hello` is read within `HandshakeTimeout`, decoded and validated.
   `hello.token` must resolve to the host the transport authenticated as.
3. Deflate is armed if `hello.caps.deflate` offered it.
4. The session attaches: same epoch → resume, new epoch → reset and
   `subscribed{seq:baseline}` on the host's fan-out queue.
5. `hello_ack` is written (watermarks, audience snapshot, liveness, limits,
   hubBoot, deflate echo).
6. Retired sessions of the same host are closed `superseded`; their late
   frames are refused.

A missing mandatory field, a wrong version or a frame of the wrong type at
any step closes with `protocol` (a frame that cannot be decoded closes with
`unreadable`).

## 3. WebSocket (`GET /ws/host`)

- One text message = one plain JSON frame.
- One binary message = one raw-DEFLATE stream of a JSON frame, allowed only
  after the hello_ack echo.
- Transport keepalive (WS ping) runs at `liveness.keepalive`; it is not a
  protocol signal.

## 4. QUIC (UDP :8788, ALPN `capri-hub`)

- One bidirectional control stream carries `hello`, `hello_ack`, `events`,
  `audience`, `request` and `hb`.
- Each frame on it is a 4-byte big-endian length followed by the body; bit
  31 of the length marks a raw-DEFLATE body.
- Request streams carry the host's `respond` frames only. The hub never
  writes on them, and EOF on a request stream does not end the session.
- QUIC application keepalive is a dial-time option, not tunable from
  `hello_ack`.

## 5. Compression

Raw DEFLATE (RFC 1951, no zlib header) of the JSON frame, negotiated by
`hello.caps.deflate` / `hello_ack.caps.deflate`. Bodies below 256 bytes or
where compression does not pay stay bare. The hub caps the decompressed size
at 32 MiB; a frame it cannot inflate ends the session with `unreadable`
rather than being skipped, because skipping would let a later seq move the
watermark past a hole.

## 6. Close mapping

No JSON close frame. `wire.CloseReason` is the only vocabulary:

`normal`, `shutdown`, `superseded`, `auth`, `protocol`, `liveness`,
`overflow`, `unreadable`.

The shared table maps each to a `(code, reason)` pair for WS and to an
application error code for QUIC. The hub never matches on a string.
