# LOCAL HTTP/3 fixture

This standalone module tests real HTTP/3 over QUIC through the CHR laboratory.
It is not a product dependency. The server returns the observed UDP peer IP,
request path, and HTTP protocol. The client uses UDP exclusively; there is no
HTTP/1 or HTTP/2 fallback. An independently supplied destination IPv4 permits
routing to a DNS FakeIP while preserving the original TLS hostname.

## Dependency provenance

`github.com/quic-go/quic-go v0.63.0` is pinned in this module and `go.sum`.
GitHub's primary releases API returned v0.63.0 as the latest stable release,
published 2026-09-22T05:39:48Z, during this check on 2026-10-04.

Primary sources:

- [Release v0.63.0](https://github.com/quic-go/quic-go/releases/tag/v0.63.0).
- [HTTP/3 transport at v0.63.0](https://github.com/quic-go/quic-go/blob/v0.63.0/http3/transport.go): custom QUIC Dial function.
- [QUIC client at v0.63.0](https://github.com/quic-go/quic-go/blob/v0.63.0/client.go): Dial using an existing UDP PacketConn.
- [HTTP/3 server at v0.63.0](https://github.com/quic-go/quic-go/blob/v0.63.0/http3/server.go): Serve using an existing UDP PacketConn.

## Build and run

From the repository root:

```sh
cd lab/quic
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 ../../.cache/go/bin/go build -trimpath -ldflags='-s -w' -o ../../.cache/dataplane/mc-quic .
```

Server VM:

```sh
mc-quic serve
```

This binds `10.77.0.20:9443/UDP`. Use `serve -listen 127.0.0.1:9443` for a
local smoke test.

Client VM:

```sh
mc-quic control
```

This exposes HTTP control on `0.0.0.0:8090` and binds outbound UDP to
`192.168.88.10`. `control -source OTHER_IP -listen IP:PORT` overrides these.
POST `/request` accepts:

```json
{"domain":"selected.test","address":"198.18.0.1","source":"192.168.88.10","path":"/quic"}
```

`address` is the real or FakeIP address obtained separately from laboratory DNS.
The executable deliberately does not resolve the name itself. Destination UDP
port is fixed at 9443. The response reports `protocol`, `remote_ip`, `target`,
`elapsed_ms`, and `error` on failure. A successful request has protocol
`HTTP/3.0`. `/health` confirms control availability.

Single request instead of control:

```sh
mc-quic client -source 192.168.88.10 selected.test 198.18.0.1
```

Local smoke test uses `client -source 127.0.0.1 selected.test 127.0.0.1`.

## TLS and scope

The binary generates a deterministic self-signed Ed25519 certificate from a
public, fixed LOCAL fixture seed. Server and client independently derive the
same certificate. The client trusts only this certificate and verifies the
hostname against `selected.test`, `unselected.test`, or `localhost`. TLS
verification is enabled. The key is intentionally public test material: never
reuse it in deployed services. Certificate validity is 2026-01-01 to 2036-01-01.

`go test -race ./...` checks deterministic trust, rejects an unknown hostname,
and performs an actual HTTP/3 loopback request, checking protocol, peer IP, and
path. These checks establish fixture behavior; they do not establish routing
through RouterOS. That requires the separate CHR packet captures and egress-IP
checks.
