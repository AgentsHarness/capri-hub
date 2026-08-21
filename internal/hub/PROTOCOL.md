# PROTOCOL

Wire-format notes for the capri-hub ↔ capri-host transport. The FE-facing
(`/ws/fe`) formats are unchanged. This document specifies the host→hub
**uplink flate compression** (`"deflate"`): the host side MUST follow it
byte-for-byte.

## 1. Negotiation

Compression is per-connection, hub-confirmed, and off by default. Either
side that has not confirmed keeps everything as bare JSON (backward
compatible — old hub + new host and vice versa all work).

### 1.1 QUIC transport (UDP :8788, ALPN `capri-hub`)

1. Host opens one bidirectional stream and sends the auth frame:

   ```
   4 bytes  big-endian length of the JSON below (no flag bit)
   JSON     {"v":1,"type":"auth","token":"<host-token>","deflate":true}
   ```

   `"deflate":true` = host offers flate compression. Omit the field (or
   `false`) to stay on bare JSON.

2. Hub authenticates, then replies hello:

   ```
   4 bytes  big-endian length (no flag bit — hub→host is never compressed)
   JSON     {"v":1,"type":"hello","service":"hub","subscribers":N,"seq":S,
             ... ,"deflate":true}
   ```

   `"deflate":true` appears **only** when the hub accepted the offer. It is
   the host's only enable signal: compressed uplink frames are permitted
   strictly after this hello.

### 1.2 WebSocket transport (`GET /ws/host`)

The hub sends its hello immediately after the upgrade — before it can read
any uplink frame — so the host must signal the offer in the HTTP handshake:

```
GET /ws/host HTTP/1.1
Authorization: Bearer <host-token>
X-Hub-Deflate: 1
```

(`?deflate=1` on the URL is accepted as an alternative.) The hub's hello
frame echoes `"deflate":true` when accepted, same as QUIC. There is no
in-frame negotiation on WS: an uplink JSON frame carrying `"deflate":true`
is ignored as a signal.

## 2. Compressed uplink frames

Applies to **any** host→hub frame type after confirmation — in practice
`events` and `respond` frames. `ping`/`pong`/`host_status` control frames
are tiny and stay bare JSON (allowed either way; the hub accepts both).

The compressed unit is the **frame body** — the JSON payload — exactly the
bytes that would otherwise be sent as a bare frame. Compression is
**flate (raw DEFLATE, RFC 1951)** — no zlib/gzip header, no dictionary —
identical to the hub→FE `/ws/fe?c=1` stream, Go `compress/flate` /
browser `DecompressionStream('deflate-raw')`.

Per-frame: one independent, complete deflate stream (`flate.NewWriter` …
`Write` … `Close`). No shared compressor state across frames.

### 2.1 Threshold

A payload smaller than **256 bytes** is sent uncompressed (the flate
header + final-block overhead is not worth it — matches the hub's
`minCompressSize` for the FE stream). The hub accepts a flagged/binary
frame of any size, so the threshold is advisory for the host.

### 2.2 WebSocket wire format

The WS message *type* carries the flag:

| WS message type | Body                        |
|-----------------|-----------------------------|
| Text (0x1)      | bare JSON frame bytes       |
| Binary (0x2)    | one raw-deflate stream of the JSON frame bytes |

Example compressed `events` frame body after inflation:

```json
{"v":1,"type":"events","seqStart":100,"events":[{"type":"chunk","text":"…","seq":100}]}
```

### 2.3 QUIC wire format

Every QUIC uplink frame is `4-byte big-endian length prefix || body`.
Bit 31 of the prefix is the compression flag:

```
byte 0        byte 1        byte 2        byte 3
[C][length <<  ...  31-bit big-endian body length  ...]
 ^ bit 31 (MSB of byte 0): 1 = body is a raw-deflate stream
                            0 = body is bare JSON
length = prefix & 0x7FFFFFFF   (max 33554431 = 32MB-1)
```

- `C = 0`: `body` is the bare JSON frame (`length` = JSON byte count).
- `C = 1`: `body` is the raw-deflate stream (`length` = **compressed**
  byte count).

The hub→host downlink never sets the flag bit; hosts may ignore it.

## 3. Backward compatibility

- Host omits `deflate` / `X-Hub-Deflate` ⇒ everything bare JSON, exactly
  as before this extension.
- Hub does not echo `"deflate":true` (old hub, or offer refused) ⇒ the
  host MUST send every frame as bare JSON (WS text / QUIC `C = 0`). The
  hub drops binary WS frames and QUIC `C = 1` frames it cannot map to a
  negotiated connection.
