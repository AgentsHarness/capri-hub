# PROTOCOL

Wire-format notes for the capri-hub ↔ capri-host transport. This document
specifies the host→hub **uplink flate compression** (`"deflate"`): the host
side MUST follow it byte-for-byte. §6 covers the browser-facing host split
(`/ws/fe`), which also changes what the host-facing `subscribers` count
means.

## 1. Handshake

host, hub and FE ship together and the wire protocol keeps **no** backward
compatibility: a peer that does not carry every mandatory hello field is an
older build, and the session is refused instead of silently degrading.
`deflate`, `stateAck`, `seq`, `subscribers`, `pingInterval` and
`idleTimeout` are all mandatory.

Compression is per-connection and hub-confirmed: until the hello echo the
host writes bare JSON.

### 1.1 QUIC transport (UDP :8788, ALPN `capri-hub`)

1. Host opens one bidirectional stream and sends the auth frame:

   ```
   4 bytes  big-endian length of the JSON below (no flag bit)
   JSON     {"v":1,"type":"auth","token":"<host-token>","deflate":true}
   ```

   `"deflate":true` = the host speaks the compressed uplink format.
   `"stateAck":true` = the host confirms absolute-state frames. Both are
   mandatory; a missing `stateAck` is answered with an `auth_error` frame.

2. Hub authenticates, then replies hello:

   ```
   4 bytes  big-endian length (no flag bit — hub→host is never compressed)
   JSON     {"v":1,"type":"hello","service":"hub","subscribers":N,"seq":S,
             ... ,"deflate":true}
   ```

   `"deflate":true` echoes the host's announcement: compressed uplink
   frames are permitted strictly after this hello.

   `"probe":true` is a one-way capability broadcast: this transport has a
   socket probe, so the host stretches `host_status` from the 5s beat to
   15s to save idle uplink traffic. The probe does **not** refresh
   `LastSeen`: a control pong never reaches the frame handler, so the
   registry's 30s sweep does not see it. `host_status` is the application
   beat on both transports, and 15s is still two beats inside the sweep.

   **This field is transport-scoped.** It is advertised only on the
   WebSocket transport. QUIC has no control ping, so its hello omits
   `"probe"` and the host keeps the 5s beat. The host keys its cadence
   off this field.

   `"pingInterval"` and `"idleTimeout"` (integer seconds) state this hub's
   liveness time scale — the MQTT *Server Keep Alive* idea: the peer that
   judges silence tells the other one what it is judging, instead of both
   ends hard-coding an assumption that drifts apart. Today
   `pingInterval` = 5 (`hostPingInterval`) and `idleTimeout` = 36
   (`hub.HostSilenceTimeout` 30 + two `LivenessCheckInterval`s of 3s).

   - `pingInterval` — how often this hub sends a `ping` frame. The host
     counts frames, so this bounds the downlink silence it can rely on.
     The ping is sent on every tick even when the payload is trimmed for a
     `stateAck` connection.
   - `idleTimeout` — the downlink budget the host should run. It is
     deliberately larger than the sweep's `HostSilenceTimeout`: the sweep
     only acts on its ticker, so a host going silent just after a tick is
     buried one interval later, plus one interval of ordering margin against
     the host's own check granularity. The host adopts this number from
     hello. Its local 20s default applies only until hello arrives, and
     when the advertised value is out of range.

   The host uses `idleTimeout` as its own downlink watchdog budget, so both
   ends fail at the same time scale. Accepted range is
   `pingInterval` 1..60, `idleTimeout` 5..300; anything outside is ignored
   and the host keeps its local defaults (`defaultSessionIdleTimeout` =
   20s), so a typo in a hub config can never become a reconnect loop.

### 1.2 WebSocket transport (`GET /ws/host`)

The hub sends its hello immediately after the upgrade — before it can read
any uplink frame — so the host signals its capabilities in the HTTP
handshake:
```
GET /ws/host HTTP/1.1
Authorization: Bearer <host-token>
X-Hub-Deflate: 1
X-Hub-State-Ack: 1
```

Both headers are mandatory: a handshake missing either is closed with
`(1002, "protocol version")`. The hub's hello frame echoes
`"deflate":true`, same as QUIC. There is no in-frame negotiation on WS: an
uplink JSON frame carrying `"deflate":true` is ignored as a signal.

### 1.3 WebSocket close reasons

The hub closes a host socket with a fixed `(code, reason)` pair that states
**why**, and acp-host switches its reconnect policy on the `reason` — the
code alone is ambiguous. This is wire contract: the strings are short
literals, never interpolated error text, and a new meaning gets a new
reason rather than an extended one.

| code | reason | meaning / host action |
|------|--------|-----------------------|
| 1000 | `shutdown` | hub going down; reconnect with backoff |
| 1000 | `superseded` | a newer connection took this `hostId`; redial at once, **do not re-pair** |
| 1000 | `peer closed` | the host's own end went away; nothing to interpret |
| 1001 | `ping write failed` | downlink write broke; reconnect with backoff |
| 1001 | `uplink idle timeout` | no uplink within `hostReadTimeout`; reconnect with backoff |
| 1001 | `hello write failed` | the hello could not be written; reconnect with backoff |
| 1008 | `liveness probe timeout` | pongs stopped (`hostProbeFailures`); reconnect with backoff |
| 1008 | `auth` | the token is no longer valid/unpaired; re-pair, then reconnect |
| 1002 | `protocol version` | the handshake lacked a mandatory capability header; upgrade the peer |
| 1011 | `internal error` | hub-side failure; reconnect with backoff |
| 1011 | `uplink unreadable` | a frame could not be decoded (bad deflate stream, `seqStart` mismatch); reconnect with backoff so the host replays from the hub's watermark |

A close with an unrecognized or empty reason is an "ordinary drop": back
off and redial, never re-pair. Reading the code's rendered status name (e.g.
`StatusPolicyViolation`) as an auth signal is explicitly wrong — every 1008
in the table would match it. A `(1002, "protocol version")` close means the
handshake lacked a mandatory capability header and the peer must be
upgraded.

QUIC has no close-reason channel, so the hub carries the same verdicts in
the application error code of `CloseWithError`. The codes are wire contract
and mirror the reason strings above:

| code | meaning | host action |
|------|---------|-------------|
| 0 | routine close | ordinary drop |
| 1 | `internal error` | reconnect with backoff |
| 2 | `superseded` | redial at once, **do not re-pair** |
| 3 | `auth` | re-pair, then reconnect |
| 4 | `protocol version` | upgrade the peer |
| 5 | `liveness probe timeout` | reconnect with backoff |
| 6 | `uplink idle timeout` | reconnect with backoff |
| 7 | `ping write failed` | reconnect with backoff |
| 8 | `shutdown` | reconnect with backoff |
| 9 | `uplink unreadable` | reconnect with backoff; the host replays from the hub's watermark |

An unrecognized code is an ordinary drop. The reason text travels along for
logs only; a host switches on the code.

### 1.4 QUIC auth failure (`auth_error`)

QUIC has no close-reason channel, so an authentication failure is expressed
as a final downlink frame before the connection is closed:

```json
{"v":1,"type":"auth_error","error":"missing auth"}
```

The hub writes it when the first frame is not a valid `auth` frame, or when
its token no longer resolves to a paired host. `error` is display text for
logs only — a host must switch on `type`, never on the message.

A host that receives `auth_error` must treat the session as an
authentication failure and re-pair (fetch a new pairing code / token), not
as an ordinary drop with backoff: redialing the same revoked token can
never succeed. This is the QUIC analogue of the WS `1008 / auth` close
reason in §1.3. The hub also writes it with `"protocol version"` when the
auth frame lacks `stateAck`.

### 1.5 Liveness time scales

Every clock that can end a session or mark a host offline, fastest first.
Values are the **2026-10-30 code** (`cmd/capri-hub/main.go` for the hub's WS
and QUIC host handlers, `internal/hub/hub.go` for the registry sweep, host
`internal/hub/client.go` for the downlink watchdog and QUIC keepalive).

| Clock | Owner | Value | Kills the link? |
|---|---|---|---|
| QUIC keepalive | host (and hub listener) | 15s (host refreshes its NAT binding; the hub's `quic.Config` uses 10s) | No — NAT keepalive only |
| WS control ping | hub | 2s tick; sent only after 6s with no peer frame; pong budget 3s; 2 consecutive failures | Yes — ~16s worst case, **only on an idle link** |
| JSON data `ping` | hub | 5s, carries `seq` (the delivery watermark) | No — it feeds the host's downlink watchdog |
| `host_status` | host | 5s without `hello.probe` (QUIC); 15s when the WS hub advertises `probe` | No — registry `LastSeen` only |
| Registry sweep | hub | 3s tick; `HostSilenceTimeout` 30s without any uplink | Marks the host offline (does not close the socket) |
| Downlink watchdog | host | 20s local default; `hello.idleTimeout` (36s from the current hub) | Yes — host gives up and reconnects |
| Uplink read timeout | hub | 45s without a frame on the host stream | Yes — session closed |

Kill order (each judge must be slower than the one before it):

```
WS probe ~16s  <  sweep 33s  <  host watchdog 36s  <  hub read timeout 45s
```

A probe timeout (~16s) is the only clock that fires before the registry
sweep, so a half-open WS socket is dropped while browsers still show the
host as online for at most a few more seconds. QUIC has no probe: there the
first judge is the registry sweep (33s), then the host's advertised 36s
watchdog. The JSON ping keeps the host's watchdog fed but never judges the
link by itself, and `host_status` only proves the host's application side
is still sending.

These numbers are duplicated as constants; changing one requires updating
this table (and the timing notes in `docs/TRANSPORT-RELIABILITY.md`, §8.1)
in the same change.

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

**A frame that cannot be decoded ends the session.** This applies to both
transports and to both checks — a bad deflate stream and a `seqStart` that
disagrees with the first event's `seq`. Skipping the frame instead would
leave its sequence numbers spent with no record of them, so the next frame's
higher number would move the delivery watermark (`hello.seq` / `ping.seq`)
past the hole, and the host would then delete its replay copies on that ack.
Ending the session keeps the watermark honest and lets the host replay from
it: the replay ring still holds the events, because nothing acked them.

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

### 2.4 Chunked relay responses (`respond`)

A relay answer whose body is at most **1MB** (`relayChunkSize = 1 MiB`) keeps
the original single-frame shape:

```json
{"v":1,"type":"respond","reqId":"7","status":200,"body":{"ok":true}}
```

A larger body is split into several `respond` frames. Each carries a base64
slice instead of `body` — a frame never has both keys:

```json
{"v":1,"type":"respond","reqId":"7","status":200,"chunk":"<base64>","encoding":"base64","more":true}
```

- `chunk` is the raw body bytes of that slice, **standard base64 (padded)**.
  Slices are 1MB except the last one.
- `more:true` means another chunk follows. The last frame has `more:false`.
- `reqId` and `status` repeat on every frame; the hub keeps the status of the
  first chunk and resolves the browser request only on `more:false`.
- Over QUIC the per-request stream stays open across chunks and is closed
  after the `more:false` frame (`reqFrame.final`). Over WebSocket all frames
  share the connection, which is the point of the split: the write lock is
  released between chunks, so events, ping and `host_status` are not stuck
  behind one multi-MB write.
- The assembled body is still capped at **28MB** (`maxChunkedRelayBody`,
  matching the host's `maxRelayResponseBytes`). Over the cap the hub fails
  that one request with `502 {"ok":false,"error":...}`, removes it from the
  pending table and logs — other requests on the same host keep running.
- An `encoding` other than `base64` (including a missing one on a frame that
  carries `chunk`) is a protocol error for that request: same 502 path, no
  session failure.
- A chunk for an unknown `reqId` — normally the browser gave up and the
  pending entry was dropped — is ignored and counted (`lateRelayChunks` in
  `/api/stats`).

The hub reassembles the exact original bytes before answering the relayed
HTTP request, so the browser, `/ws/fe` and gzip path see one unchanged body:
chunking exists only between host and hub, and the FE needs no change.

## 3. Version policy

There is no compatibility mode. A host that omits `deflate` /
`X-Hub-Deflate` sends bare JSON until its hello (which is refused as an
older build); a hub that does not echo the flags fails the host's session
at the first hello. Absolute state (`subscribers` / `viewing`) has exactly
one repair path — confirmed delivery — and the ping never carries it.

### 3.1 Confirmed state delivery (`state_ack`)

`subscribers` and `viewing` are edge-triggered absolute state: losing one
leaves the host acting on a stale answer (paused while a browser waits, or
uploading a transcript nobody displays). Confirmed delivery is the only
repair path: the hub retransmits an unconfirmed frame, and the ping never
re-asserts this state.

The **hello** is one of those carriers, not a separate path. It writes
`subscribers` with a fresh `subsGen` and nests `viewing` under its own key
with a fresh `viewing.gen`, and both are registered as unconfirmed before the
transport is attached. A hello whose state never reached the host is
therefore resent by the same timer as any edge frame, with the identical
generation — which is what the host's generation gate needs to discard the
duplicate if the original did land. Without this, a lost hello left the host
paused until the next browser connect/disconnect, hours later.

1. Announced in the handshake — because the hub writes `hello` before it
   reads any uplink frame:

   ```
   WS:   X-Hub-State-Ack: 1
   QUIC: {"v":1,"type":"auth","token":"…","stateAck":true}
   ```

   Mandatory, together with the deflate announcement: a WS host without
   the header is closed with `(1002, "protocol version")`, a QUIC host
   without the field receives `auth_error` with `"protocol version"`.

2. Every `subscribers` / `viewing` frame the host *applies* is confirmed:

   ```
   host → hub: {"v":1,"type":"state_ack","kind":"subscribers","gen":9}
               {"v":1,"type":"state_ack","kind":"viewing","gen":4}
   ```

   `kind` is `subscribers` or `viewing`; `gen` is the frame's own stamp.
   A duplicate of the newest gen is applied once and STILL acked — the hub
   stops retransmitting only when the ack arrives, so silence would look
   like a lost frame.

3. The hub keeps one outstanding entry per (host, kind) — the newest gen —
   and retransmits its payload verbatim on `StateAckRetryInterval` (1s)
   until an ack with `gen >= the entry's gen` arrives. The delay doubles per
   retransmit up to 30s. Note where that backoff starts from: every NEW state
   resets the entry to 1s, so a lost `viewing` for a freshly switched session
   is repaired within a second; only a generation that keeps failing to be
   confirmed backs off, which is the case the cap exists for. Acks can arrive
   out of order (edge frame racing its retransmit), so a stale ack MUST NOT
   clear a newer entry. Retransmits are serial per generation (`inflight`).
   There is no give-up: a host that stops confirming is a broken host, and
   its own transport timeouts end the session.

4. The ping carries no `subscribers` / `subsGen` / `viewing` (it keeps
   `seq`, the unrelated data-plane ack). Its `seq` is the **delivery**
   watermark: the highest N for which 1..N all arrived (§4.1).

### 3.2 Data-plane watermark (`seq`)

`hello.seq`, `ping.seq` and the FE's `subscribed.seq` carry the same
per-host number, and it means "every event up to N arrived", never "N is the
highest I have seen". The hub keeps that distinction explicitly: a number
above the watermark parks until the numbers below it show up, and the
watermark then walks over the whole run. The host deletes its replay copies
and anchors its repairs at this number, so a value that stepped over a hole
would erase the very events the hole needs.

Two consequences worth stating:

- The first event of a session defines the baseline (there is no history yet,
  and the host can only replay what its ring still holds). After that, a hole
  holds the watermark until it is filled or the session ends.
- If the out-of-order set overflows (`maxGappedSeq`), the hub stops trying to
  prove continuity and gives up on the missing range: everything below the
  lowest parked number is declared lost and the watermark jumps past it. That
  is the same trade the FE's `PENDING_SEQ_CAP` makes, and it is deliberately
  preferred over freezing — a frozen watermark would stop the host from ever
  compacting its replay ring, so the session would end and reconnect to the
  same frozen number for good. A host healthy enough to stay under
  `replayHardCap` never reaches this.

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
    a delivery ACK to anchor drop-repairs.
  - closing the control stream (or its read timeout) ends the whole
    session and the connection.

- **Request streams** — every additional stream the host opens after
  auth. Pure uplink:
  - carry `respond` frames (one stream per in-flight request, with a shared
    request stream as the fallback when the peer's stream limit is hit);
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

## 6. Per-host fan-out (`/ws/fe`) and what `subscribers` now counts

Event sequence numbers are **per host** (§4's `hello.seq` / `ping.seq` are
per-host watermarks too), so a browser that displays one host has no use for
another host's stream — and mixing them is actively wrong, not just wasteful.
`/ws/fe` therefore scopes each connection:

### 6.1 Browser → hub

```
GET /ws/fe?ticket=…&host=<hostId>&c=1          (filter from the first frame)
{"v":1,"type":"subscribe","host":"<hostId>"}   (retarget, no reconnect)
```

* `host` absent or empty ⇒ **every host**. The FE omits it until a host is
  selected (first paint), so this window must keep broadcasting everything.
* `subscribe` is the only browser→hub frame the hub acts on; anything else
  (app-level pings, junk, non-JSON) stays a read-side no-op. Re-sending the
  current host is cheap: the count dedupe below suppresses the notify.

### 6.2 Hub → browser

```
{"v":1,"type":"subscribed","host":"<hostId>","seq":S}
```

`seq` is that host's current hub-side watermark — the FE **aligns** to it
(and, when it already saw events, gap-pulls only the real hole). Without it
a host switch leaves the client at watermark 0, whose first event triggers
`GET /api/events?host=…&after=0` — the whole per-host ring buffer (up to
1500 events) fetched and then discarded.

The browser `hello` carries `feSubscribers`: the number of live `/ws/fe`
clients on the hub, this connection included (admin only — guest hellos
omit it, and hub-level frames never reach guests). Every connect/disconnect
then pushes a hub-level frame to the pages already open:

```
{"v":1,"type":"subscribers_changed","count":N}
```

It has no `hostId` (the figure is hub-wide, not per-host), so the per-host
filter never swallows it; the page that just joined is skipped because its
hello already carries the same number. The FE top bar renders this count
beside the host block; a guest hello carries neither, so the badge stays
hidden for guests.

The same `hello` carries `subscriberId`: this socket's row id in
`GET /api/subscribers` (admin only, along with the count). The FE uses it to
mark "this page" in the detail panel — two tabs on one machine share an
address and a User-Agent, so the id is the only stable discriminator. The
endpoint answers who is watching, not just how many:

```json
{"ok":true,"count":2,"subscribers":[
  {"id":7,"ip":"203.0.113.9","userAgent":"Mozilla/5.0 …","role":"admin",
   "hostId":"h1","sessionId":"s-42","connectedAt":1760000000000},
  {"id":8,"ip":"198.51.100.4","userAgent":"Mozilla/5.0 …","role":"guest",
   "guestId":"g_ab12cd","guestLabel":"小王","hostId":"h1",
   "sessionId":"s-9","connectedAt":1760000300000}
]}
```

`ip` is the client address without the port; when the peer is loopback (the
deployed hub listens on 127.0.0.1 behind nginx) the proxy's `X-Real-IP` /
first `X-Forwarded-For` hop is used instead — headers from non-loopback
peers are ignored, so the display cannot be spoofed by a direct dial. Guest
rows carry the guests.json record id and label, never the token. `hostId`
and `sessionId` are the page's current subscription and the transcript it
declares it is reading; the admin page reports the session with a
`{"v":1,"type":"viewing","host":ID,"session":S}` control frame (or the
`session` field of a `subscribe` frame) — bookkeeping only, no reply, and
it never widens what any subscriber receives.

Fan-out rule per subscriber: an event tagged `hostId` reaches it when the
subscriber's filter is empty or equal; hub-level frames (`hosts_changed`,
`prefs_changed`, `subscribers_changed`, `hello`) carry no `hostId` and
always fan out. The `resync` slow-consumer frame carries the `hostId` of the
event that tripped it; an untagged resync would let one host's drop storm
jump another host's FE watermark to the wrong sequence and silently drop
everything below it. Hub-level resyncs (which have no host) stay untagged.

When a `resync` is emitted: after `resyncDropThreshold` (32) droppable events
are lost to one slow subscriber, or immediately when a single **critical**
event is lost (the FE's turn terminals — `done` / `turn_completed` /
`cancelled` / `prompt_complete` / session `error` — plus `client_request`,
`client_request_resolved` and a terminal `tool_call_update`). A terminal event
is usually the last of its turn, so the FE would never see a higher `seq` to
reveal the hole: escalating at once is what turns a silent stall into a
rebuild. The frame is queued ahead of that subscriber's backlog and never
blocks the fan-out path, so a wedged browser cannot slow the host uplink or
its peers.

### 6.3 Effect on the host-facing `subscribers` count

`hello.subscribers` and the `subscribers` control frame carry the number of
browsers that **receive that host's** events — its
own filtered subscribers plus every watch-all subscriber — instead of the
raw browser total. Nothing about the frame shape changes (a host still
pauses its uplink at `count == 0` and replays from its own ring on 0→1),
but with a filtered FE an unwatched host stops uploading entirely. Wire a
hub to a host and a browser watching a different host and the host log
stays silent; switch and the `0→1` resume line appears.

Per-host counts are deduped per host (`hostID → last count sent`), so one
page switching hosts writes two frames (leave → 0, join → 1) and nothing
else, and `gen` keeps ordering safe exactly as before.

### 6.4 Session-scoped uplink filter (`viewing`)

Per-host fan-out still streams every session of that host. With several
sessions resident and running at once (a background agent, a monitor, a
subagent), a page displaying one transcript was paying for every other
session's chunks and tool output.

The hub therefore tells each host which sessions its pages actually
display.

Edge-triggered frames are standalone and carry their own `type`; the
host dispatches on it and reads `all` / `sessions` at the top level:

```
hub → host, on change (standalone frame):
{"v":1,"type":"viewing","all":false,"sessions":["<sid>", …],"gen":7}
{"v":1,"type":"viewing","all":true,"gen":7}
```

The same value is nested under a `viewing` key in `hello`. Those two are the
only carriers: the ping never carries it (§3.1 item 4), and `stateAck` is
mandatory for every peer, so there is no un-negotiated fallback.

```
hub → host, on change (standalone):  {"v":1,"type":"viewing","all":false,…,"gen":7}
hub → host, in the handshake:        {"v":1,"type":"hello",…,"viewing":{…,"gen":8}}
```

`gen` is a hub-monotonic ordering stamp: a host discards a `viewing` value
whose `gen` is not newer than the last one it applied, so a slow write
cannot deliver an older set after a newer one. Viewing sets carry their own
counter, independent of the subscriber-count `gen` / `subsGen`: the two
absolute-state families never interleave, and each is compared only within
itself.

* `sessions` is the union over every subscriber that receives that host's
  events, plus the subagent children of those sessions (one level, the
  same rule the guest whitelist uses).
* The set is bounded: a session id longer than 128 bytes is ignored, and
  once more than 64 distinct sessions would be listed the set widens to
  `all:true` instead. Both limits push toward filtering less, never more —
  the host must not trim a transcript the hub could not describe.
* `all:true` means the audience cannot be narrowed — at least one such
  page has not declared a session yet (its socket is new, its first
  `viewing` frame is still in flight). The host then filters nothing, so a
  half-loaded page never loses transcript.
* Both forms are **absolute**: a host replaces its set wholesale. A lost
  frame is repaired by the retransmit timer (§3.1).

Host behaviour (`capri-host` `internal/hub/client.go`): events belonging
to a session outside the set are replaced **in place** by a placeholder
before they enter the replay ring —

```
{"type":"trimmed","sessionId":"<sid>","seq":N}
```

— and nothing else. Keeping the event (rather than dropping it) is what
makes this safe: seq counters are per host and continuous, and the FE's
ordered-delivery engine treats any hole as a lost event, gap-pulling and
ultimately rebuilding the transcript ("直播中断"). The placeholder keeps
the sequence gapless while removing the payload, so the hub's stale-seq
gate, its gap-pull ring and the FE sequencer need no change.

The same rule applies one layer earlier, inside the host's own event bus: a
droppable event (`chunk`, `thought`, …) that a slow subscriber cannot receive
is delivered as this same placeholder instead of vanishing. The number was
already assigned in `publish` and shared by every subscriber and by the hub
uplink, so dropping it would open a hole no one downstream could explain —
and, with the cumulative watermark of §3.2, hold that watermark until the
session died. `trimmed` is therefore the single shape of "the body is gone,
the sequence is not", whether the cause is an unwatched session or a slow
reader.

Only bulk transcript types are trimmed: `chunk`, `thought`, `user_chunk`,
`user_message`, `text`, `image`, `tool_call`, `tool_call_update`, `plan`,
and the generic `session_notification` / `ext_notification` carriers. This
list is the contract the host must implement — it is authoritative, so a
host whose trim set differs is wrong, not this document.
Everything else keeps flowing for unwatched sessions: turn terminals
(`done` / `turn_completed` / `cancelled` / `error`), the reverse requests
(`client_request` / `client_request_resolved`), and the small control
rails (usage, busy, queue, recap, roster, subagent lifecycle) — that is
what lets a page switch into a session and find it already consistent.
The transcript itself is rebuilt from host history over HTTP on switch,
which is the same source the FE already uses for an unloaded session.

The filter saves upstream bandwidth on the host→hub leg and downstream on
hub→browser. It does not change who may read what: the hub still fans out
by host, and the FE still drops foreign-session events.
