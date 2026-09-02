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

## 4. QUIC stream planes (multi-stream sessions)

One QUIC connection = one host session, spread over several bidirectional
streams. Frames are self-describing JSON routed by `type`; no frame is
stream-specific except the auth handshake.

- **Control stream** — the FIRST stream the host opens (and the hub
  accepts) on the connection:
  - host → hub: first frame MUST be `auth`; then `events`, `host_status`,
    `seq_reset`, `pong`.
  - hub → host: `hello` (deflate echo), `subscribers`, `ping`, and ALL
    relayed `request` frames. The hub never writes on any other stream.
    The `ping` piggy-backs `"seq"`: the per-host data-plane watermark
    (same meaning as `hello.seq`), refreshed every ping — hosts use it as
    a delivery ACK to anchor drop-repairs. Old hubs omit the field; hosts
    treat a missing `seq` as "no new ack".
  - closing the control stream (or its read timeout) ends the whole
    session and the connection.

- **Request streams** — every additional stream the host opens after
  auth. Pure uplink:
  - carry `respond` frames (one stream per in-flight request, or a
    single shared request stream on older hosts);
  - the host MAY send one no-op `pong` as the first frame to materialize
    the stream (`OpenStream` transmits nothing until first write — an
    unaccepted, unwritten stream is invisible to the hub);
  - EOF/reset on a request stream is the NORMAL end of that request and
    MUST NOT tear down the session; each request stream also has its own
    idle deadline (hub-side `hostReadTimeout`).

Wire format (length prefix, bit 31 deflate flag) is identical on every
stream; the deflate flag is session-scoped (negotiated via the auth
frame / hello echo) and applies to frames on all streams.

## 5. Hub → browser relay compression (`/api/*`, gzip)

Distinct from §1–§2 (host↔hub flate) and from the `/ws/fe` event stream: the
`/api/*` relay answers ordinary HTTP requests and historically wrote the host's
JSON verbatim. A session-history page is multi-megabyte raw (one agentic turn
carries tens of MB of tool output), so this last hop dominates session-switch
latency — measured: 2.18 MB of JSON took 5–15 s on a few-Mbps link, where the
same page gzips to ~66 KB / ~1.6 s.

`handleRelay` compresses the relay response when BOTH hold:

- the request names `gzip` explicitly in `Accept-Encoding` (a bare `*` does
  not count — non-browser clients send it while being perfectly happy with
  identity), and it is not refused with `gzip;q=0`;
- the body is at least `minCompressSize` (256 B, same floor as the FE WS
  stream).

When it fires, the response carries `Content-Encoding: gzip`, an exact
`Content-Length` of the compressed bytes, and `Vary: Accept-Encoding` —
appended to any `Vary: Origin` the CORS layer already set, so a shared cache
sees both axes. If the
compressed form is not smaller, or the gzip step fails, the body goes out
uncompressed with no `Content-Encoding` — `Accept-Encoding` never becomes a
correctness requirement. Error paths answered through `writeJSON` (413, 503
no-host, relay errors) stay plain JSON.

The layer is payload-transparent: the host's `detail=lite|meta` history
projection and this gzip are independent, and the hub never parses a relay
body.
