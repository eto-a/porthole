# syntax=docker/dockerfile:1
#
# Build from the repository root:
#   docker build -f deploy/Dockerfile --build-arg VERSION=$(git describe --tags --always --dirty) -t portholed .

FROM golang:1.27@sha256:e0174e51e81218523251d85d248a90d24c3d5e81543b4f07a5d66229397db190 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/portholed ./cmd/portholed

# The data directory must exist and belong to the non-root user (uid/gid 65532) so that a fresh volume is writable.
RUN mkdir -p /rootfs/var/lib/porthole

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --from=build /out/portholed /usr/local/bin/portholed
COPY --from=build --chown=65532:65532 /rootfs/var/lib/porthole /var/lib/porthole

# SQLite database (tokens). Mount a volume here.
VOLUME /var/lib/porthole

# HTTP(S) listener: control endpoint, health check and HTTP tunnels (set `listen` accordingly; binding a port below
# 1024 as non-root needs net.ipv4.ip_unprivileged_port_start=0, which Docker sets by default, or a different port).
EXPOSE 443
# TCP tunnels use ports from `tcp_port_range` (default 20000-29999). Publish the range you configure, for example
# `-p 20000-20099:20000-20099` with PORTHOLED_TCP_PORT_RANGE=20000-20099, or use host networking.
# The SSH gateway (`ssh_gateway.listen`, PORTHOLED_SSH_LISTEN) is off by default; to use it publish its port, for
# example `-p 2222:2222` with PORTHOLED_SSH_LISTEN=:2222.

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/portholed"]
# Reads /etc/porthole/portholed.yaml (mount it) and PORTHOLED_* variables. Use `serve --config ""` for env-only setups.
CMD ["serve"]
