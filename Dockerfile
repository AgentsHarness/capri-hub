# syntax=docker/dockerfile:1

# capri-hub is pure Go: no cgo, no embedded frontend, no external
# binaries. So the image is one static binary plus a couple of data
# files, and the build cross-compiles instead of emulating.
#
# Build on $BUILDPLATFORM and let the Go compiler target $TARGETARCH:
# with CGO_ENABLED=0 that is exactly equivalent to building natively, and
# an arm64 image comes out of an amd64 runner in seconds rather than
# minutes under QEMU.

ARG GO_VERSION=1.26
# Rolling major tag on purpose: a pinned minor that has been superseded
# turns into a broken build months later. Pin it here if you need
# byte-reproducible images.
ARG ALPINE_VERSION=3

# ── build ─────────────────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

# proxy.golang.org is unreachable from some networks (notably mainland
# China), where `go mod download` fails with an i/o timeout after 90s.
# CI keeps the default; build behind a mirror with
#   docker build --build-arg GOPROXY=https://goproxy.cn,direct .
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

# Dependencies first so this layer survives every source-only change.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
# Stamped into GET /api/info. CI passes the git tag or short sha.
ARG VERSION=docker

# The build cache is keyed per target arch: two architectures sharing one
# cache directory only fight over it.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,id=gobuild-${TARGETARCH},target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/capri-hub ./cmd/capri-hub

# ── runtime ───────────────────────────────────────────────────────────
FROM alpine:${ALPINE_VERSION}

# tzdata is not cosmetic here: the pairing code's expiry is logged and
# printed in LOCAL time, and without tzdata a TZ setting silently
# resolves to UTC — an operator in +08:00 would read an expiry eight
# hours off and conclude a perfectly good code was dead.
# ca-certificates keeps any outbound TLS (and `wget https://`) working.
RUN apk add --no-cache ca-certificates tzdata

# Fixed uid/gid, so a bind-mounted data directory has predictable
# ownership. docs/DOCKER.md tells the operator to chown it to 10001.
RUN addgroup -g 10001 -S capri \
 && adduser -u 10001 -S -G capri -h /data capri \
 && mkdir -p /data \
 && chown -R capri:capri /data

COPY --from=build /out/capri-hub /usr/local/bin/capri-hub

# A container has no meaningful home directory, so the default
# ~/.capri-hub would put pairing state in the writable layer and lose
# every paired host on the next `up --force-recreate`.
ENV HUB_DATA_DIR=/data
VOLUME ["/data"]

USER capri:capri
WORKDIR /data

# 8787/tcp — browsers, and the host WebSocket fallback. The hub speaks no
#            TLS; terminate it in a reverse proxy in production.
# 8788/udp — QUIC, the host's PRIMARY transport. Hosts dial
#            <hub-host>:8788 directly and it does NOT pass through the
#            reverse proxy, so this port must be reachable or every host
#            silently downgrades to WebSocket.
EXPOSE 8787/tcp
EXPOSE 8788/udp

# /health sits outside the FE_TOKEN gate on purpose, so the check needs no
# secret. Shell form so ${PORT} is read at runtime, not baked in.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -q -O - "http://127.0.0.1:${PORT:-8787}/health" >/dev/null 2>&1 || exit 1

# Exec form: the binary is PID 1 and receives SIGTERM directly, which is
# what its graceful-shutdown path waits on. Arguments append, so
# `docker run <image> paircode` works too.
ENTRYPOINT ["/usr/local/bin/capri-hub"]
