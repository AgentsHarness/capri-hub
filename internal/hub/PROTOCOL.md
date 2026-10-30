# PROTOCOL

The host ↔ hub session protocol is **v2**, specified once in
`capri-wire/PROTOCOL-V2.md` and implemented by the shared
`github.com/AgentsHarness/capri-wire` package (frame model, sender/receiver,
liveness and limit defaults, close-reason table). That document is
authoritative for the frame envelope, the handshake, ack semantics and the
close reasons; this file only records the hub-side transport and
browser-facing details that are not in the shared spec.

## 1. Hub-side session

`internal/hub/session.go` owns one session loop per attached host:

* The first frame on either transport is `hello`; the hub answers
  `hello_ack` and from then on owns seq assignment (down), the ack
  watermark (up), retransmission and the idle timer.
* A reconnect with the same `(hostId, epoch)` resumes the existing
  receiver/sender state. A new epoch resets both sequence spaces and the
  gap-pull buffer, and sends `/ws/fe` subscribers
  `{"v":1,"type":"subscribed","host":<id>,"seq":0}` before any event of
  the new epoch.
* The session seq space is the **event** seq space: an `events` frame whose
  body is a contiguous run of N events advances the delivery watermark by N,
  so the next frame continues from the last event's seq.
* Browser-relayed `request` frames are appended to the down log and are
  retransmitted until the host's cumulative ack covers them. A request
  whose frame stays unacked for `requestAckTimeout` (6s) is failed; the
  relay ceiling (`RelayTimeout`, 45m) covers a host that acked but never
  answered.

## 2. Transports

### 2.1 WebSocket (`GET /ws/host`)

The bearer token authenticates the upgrade; `hello.token` must resolve to
the same host. One text message is one plain JSON frame; a binary message
is one raw-deflate stream of a JSON frame, allowed only after
`hello.caps.deflate` was echoed in `hello_ack`. There are no capability
headers.

### 2.2 QUIC (UDP :8788, ALPN `capri-hub`)

The host opens one bidirectional control stream. Its first frame is
`hello`; there is no separate `auth` frame. Additional request streams
carry the host's `respond` frames only — the hub never writes on them, and
EOF on a request stream does not end the session. On the control stream
each frame is a 4-byte big-endian length followed by the body; bit 31 of
the length marks a raw-deflate body.

### 2.3 Compressed uplink frames

Same shape on both transports: raw DEFLATE (no zlib header) of the JSON
frame, negotiated by `hello.caps.deflate` / `hello_ack.caps.deflate`. The
hub caps the decompressed size at 32 MiB (one 28 MB relay response plus
envelope). A frame the hub cannot inflate ends the session with
`unreadable`; it is never skipped, because skipping would let a later seq
move the watermark past a hole.

### 2.4 Chunked relay responses (`respond`)

Bodies above the host's relay chunk size arrive as several `respond`
frames carrying base64 `chunk` + `encoding` + `more`; the hub assembles
them into one `RelayResponse`, so neither the browser nor the FE sees the
split. `respond` is relay-plane: it carries no session seq (`seq` is 0)
but does carry `ack`, which is what proves delivery of the `request`
frame it answers.

## 3. Close reasons

No JSON close frame exists. The transport carries the shared
`wire.CloseReason` enum: `normal`, `shutdown`, `superseded`, `auth`,
`protocol`, `liveness`, `overflow`, `unreadable`. WS maps each to a fixed
`(code, reason)` pair; QUIC maps each to an application error code. The
host switches its reconnect policy on the enum, never on a string.

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

## 6. Per-host fan-out (`/ws/fe`)

Event sequence numbers are **per host** (the session's `ack` and
`hello_ack.ackUp` carry the same per-host watermark), so a browser that
displays one host has no use for another host's stream — and mixing them is actively wrong, not just wasteful.
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

`seq` is that host's current hub-side watermark (`0` after an epoch
change, which resets the FE's per-host coordinate) — the FE **aligns** to it
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

### 6.3 Effect on the host-facing `audience` frame

`hello_ack.audience` and the standalone `audience` frame carry the number
of browsers that **receive that host's** events — its own filtered
subscribers plus every watch-all subscriber — together with the sessions
those pages display. A host pauses its event upload at `watchers == 0` and
resumes on 0→1 by replaying from its own ring; with a filtered FE an
unwatched host stops uploading entirely. Wire a hub to a host and a browser
watching a different host and the host log stays silent; switch and the
0→1 resume line appears.

The snapshot is deduped per host: one page switching hosts produces two
frames (leave → 0 watchers, join → 1), and nothing else.

### 6.4 Session-scoped uplink filter

Per-host fan-out still streams every session of that host. With several
sessions resident and running at once (a background agent, a monitor, a
subagent), a page displaying one transcript was paying for every other
session's chunks and tool output.

The hub therefore tells each host which sessions its pages actually
display, in the same `audience` frame that carries the watcher count:

```
hub → host, absolute state, on change:
{"v":2,"type":"audience","seq":12,"ack":100,
 "gen":34,"watchers":1,"all":false,"sessions":["<sid>", …]}

hub → host, in the handshake: hello_ack.audience (same value)
```

`gen` is a per-host, hub-monotonic ordering stamp the host keeps across
sessions and epoch changes: it discards an `audience` value whose `gen` is
not newer than the last one it applied, so a slow write cannot deliver an
older snapshot after a newer one. A snapshot whose payload is unchanged
keeps its generation, so the host applies each absolute state once.

* `sessions` is the union over every subscriber that receives that host's
  events, plus the subagent children of those sessions (one level, the
  same rule the guest whitelist uses).
* The set is bounded: a session id longer than 128 bytes widens the set to
  `all:true`, and so does having more than 64 distinct sessions. Both
  limits push toward filtering less, never more — the host must not trim a
  transcript the hub could not describe.
* `all:true` means the audience cannot be narrowed — at least one such
  page has not declared a session yet (its socket is new, its first
  `viewing` frame is still in flight). The host then filters nothing, so a
  half-loaded page never loses transcript.
* The frame is **absolute**: a host replaces its set wholesale. A lost
  frame is repaired by retransmission against the cumulative ack.

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
the sequence gapless while removing the payload, so the hub's receiver,
its gap-pull ring and the FE sequencer need no change.

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
