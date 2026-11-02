# wire (capri-hub/wire)

The host↔hub session protocol: the nested Go module in the `capri-hub`
repository. It defines the frame model, the sender/receiver state machines,
the liveness/limit defaults and the single close-reason table. It is
transport-agnostic and side-effect free (no websocket, QUIC, `net` or `os`
imports), so `capri-host` and `capri-hub` cannot drift apart on the protocol.

- **Spec (single source of truth):**
  [`PROTOCOL-V2.md`](./PROTOCOL-V2.md).
- **Reliability model and fault matrix:**
  [`PROTOCOL-V2.md`](./PROTOCOL-V2.md) and
  `../docs/session-v2-protocol-lecture.html`.
- **Transport specifics:** `../internal/hub/PROTOCOL.md` and
  `acp-host/internal/hub/PROTOCOL.md`.

Both documents above only record how one side uses a frame; where they and
`PROTOCOL-V2.md` disagree, the spec wins and the note is the bug.

## Layout

| File | Contents |
|---|---|
| `frame.go` | `Frame` envelope, all 7 frame types, strict encode/decode, `TrimmedEvent` |
| `sender.go` | `Sender`: seq assignment, unacked log, acks, elision |
| `receiver.go` | `Receiver`: contiguous watermark, parked frames, overflow |
| `unit.go` | transport units: 32KiB framing, split and reassembly |
| `identity.go` | epoch, `CloseReason` and the one WS/QUIC close table |
| `limits.go` | `Liveness` / `Limits` defaults and their validation |

## How the binaries consume it

The module path is `github.com/AgentsHarness/capri-hub/wire`.

`capri-hub` is the parent module and resolves it inside its own tree:

```
require github.com/AgentsHarness/capri-hub/wire v0.0.0
replace github.com/AgentsHarness/capri-hub/wire => ./wire
```

`capri-host` is a separate repository and resolves the sibling checkout:

```
require github.com/AgentsHarness/capri-hub/wire v0.0.0
replace github.com/AgentsHarness/capri-hub/wire => ../acp-hub/wire
```

The `replace` is what makes a protocol change land in one commit and apply to
both sides. CI does not use it: a consumer build resolves the module through
the normal module path, so a change that must leave this repository has to be
tagged and the consumers' `require` bumped. Until then both repositories are
expected to be checked out side by side.

## Development

```
go build ./...
go vet ./...
go test ./...
go test -race ./...
```

CI runs exactly these four commands (`.github/workflows/wire.yml` in
`capri-hub`, with `working-directory: wire`). The package has no
non-stdlib dependencies.
