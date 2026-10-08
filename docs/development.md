# Development

Tools: Go 1.27.1, sing-box 1.14.2, Python >=3.12, optional QEMU. Pins and SHA-256
for Linux/macOS arm64/amd64 are in `toolchain.lock.json`. Nothing installs globally.

```sh
make bootstrap
make check
make prototype
make cross-build
make probe
```

`make test` runs Go race tests, vet and real sing-box check of golden fixtures.
`make smoke` starts two local sing-box processes plus local HTTP/DNS targets, proves
selected-domain VLESS TCP vs nonselected DIRECT and typed DNS behavior, and tests
invalid-candidate preservation. It is not isolated-VM/RouterOS transparent E2E.

CLI `generate` accepts a local milestone config and saves a validated private
candidate. `plan` prints an **offline**, disabled hybrid RouterOS preview against
empty state. No network mutation command is exposed. `ApplyLab` exists solely for
legacy mock/lab testing. The separate `LabController` has disk journaling and
recovery tests; production capability/order/activation integration is incomplete.

Golden updates require `UPDATE_GOLDEN=1`; review output rather than auto-updating in
CI. Never commit real URI credentials. Lab UUIDs are public disposable fixtures.

The next lab stage is reproducible with `make dataplane-lab`; see `docs/lab.md` for
isolated Ethernet/CHR setup and explicit E2E mode order. `make quic-test` covers the
separate HTTP/3 module. CHR integration tests require a provisioned disposable VM;
they are not silently part of host-only `make check`. Small actual results and
capture hashes are committed under `docs/reports/dataplane-evidence`.

Phase-2 native tests and private controller journal setup are described in
[the lab guide](lab.md#phase-2-proxy-health-static-cached-ip-fallback-and-durable-controller).


`internal/fakeip` implements the bounded durable publication barrier;
`internal/dnsgate` enforces it on UDP/TCP DNS responses. `PublishAlias` preserves
sing-box's allocator; standalone `Publish` is a protocol fixture, not an injection
API into the engine. The RouterOS mapping backend and dynamic gateway stay lab-only.

## Interactive browser preview

`python3 scripts/test-webui.py` uses a disposable HTTPS API with a simulated
RouterOS/runtime, a deterministic one-node subscription fixture, and a local
TLS domain-list source. Chromium and WebKit cover import, list assignment,
selector changes, configuration planning and responsive theme contrast. This
is a browser contract, not proof of traffic forwarding through RouterOS.

For manual testing, build `./tests/e2e/webui/fixture` and start it with
`-real-subscriptions -state <private-directory> -listen 127.0.0.1:<port>`
and `-sing-box <pinned-validator>`. This mode downloads actual subscription
sources using the production TLS/DNS-pinning policy and persists private state.
RouterOS and apply remain simulated and are labelled in the interface. Do not
use the default deterministic provider mode to evaluate a real subscription.
The loopback preview uses a self-signed certificate and a disposable lab password;
it must not be exposed to a network.

## Domain lists and subscription imports

The site-list catalog references `itdoginfo/allow-domains`; custom sources are
HTTPS text files with one domain or canonical public IPv4 prefix per line. Downloads are validated, deduplicated,
and persisted privately before being expanded into draft domain-suffix rules.
Each list has an outbound selector. Refresh preserves its assigned route.
Applying still requires a reviewed configuration plan. Refresh is manual; there
is no scheduled site-list updater. Bounds are 4096 domains/prefixes per source and 64 cached sources.

Subscription sources accept text/Base64 URI lists. Supported profiles include
SS, Trojan, VLESS, VMess, Hysteria2 and TUIC, with the supported TLS/Reality and
WS/gRPC options checked against the pinned engine. Clash YAML and engine JSON
are not URI lists. Mixed URI lists retain supported endpoints and report the
line, protocol and safe rejection reason for skipped entries. XHTTP, custom
gRPC authority and disabled TLS verification are rejected. Failed refreshes
retain the last valid cache. Import can atomically create or extend a selector.
Source URLs, credentials and rejected raw lines are never included in public
resource projections or rejection reports.

## Live selector bridge

The operator-only native profile may set `control_port` (for example 9090) and
`control_secret` (32–256 characters). The port must be distinct from private DNS
and mixed-inbound ports. Generated Clash API configuration binds only
`127.0.0.1`; neither profile fields nor its secret are exposed through the web API.
Omitting these fields leaves the controller disabled. The production runtime
and API server wire the controller when the operator enables it.

`python3 scripts/test-webui.py --live-engine` adds a real local sing-box process
to each disposable browser fixture. It proves live server-card selection without
a policy revision and displays actual failed measurements for unreachable test
nodes. This fixture removes the TUN inbound and does not steer RouterOS traffic.
For a manual preview use `-real-subscriptions -live-engine` with a private
persistent state directory. `-seed-cached-subscriptions` can populate an empty
preview from its saved subscription cache; it preserves existing models/drafts.

The catalog now includes 16 domain lists and 11 public IPv4 lists: Cloudflare,
CloudFront, Hetzner, OVH, DigitalOcean, and network lists for supported services.
Network snapshots create destination-CIDR rules and never add CIDRs to the DNS
namespace. The selected route affects traffic that actually enters the engine;
RouterOS interception of public destination networks requires separate native
acceptance. Network sources reject local/reserved prefixes, IPv6, noncanonical
CIDRs and over-limit data rather than dropping records silently.
