# Product Phase 3: core acceptance

Recorded 2026-10-06. **Product Phase 3 complete for the pinned profile.**
Acceptance scope: pinned sing-box 1.14.2 and RouterOS CHR
7.24.5 x86_64, bounded IPv4 FakeIP namespace, fresh connections and process
failure. The core implementation is separate from the production API, UI and
installable RouterOS App, which belong to subsequent product phases.

## Core deliverables

| Deliverable | Implementation and acceptance |
| --- | --- |
| Endpoint parser | Strict VLESS TCP TLS/Reality/Vision, Shadowsocks SIP002 AEAD, Trojan TLS TCP and Hysteria2 QUIC; unsupported transports fail explicitly |
| Subscription manager | URI-list/base64, verified HTTPS refresh, filters, periodic refresh, private durable LKG and redacted status |
| Groups | Selector, URLTest and application-managed fallback; real authenticated endpoint observations; all-failed quarantine |
| Rules | Stable priority/order, enabled/name metadata, source CIDRs, port/network service tuples, verified immutable local SRS artifacts and bounded HTTPS refresh |
| DNS and FakeIP | Engine-issued aliases, append-only Known namespace, native mapping proof before DNS publication, retired cached aliases DIRECT before sniff |
| Generator and validator | v2 model, private generated candidates, actual pinned engine validation; trusted artifacts and cache paths cannot be injected through model JSON |
| Supervisor and LKG | Single child owner, bounded journals/config retention, staged validation, semantic probes, parent-death handling, namespace-aware recovery |
| WireGuard | Modern sing-box endpoints, validated keys/addresses/routes, real TCP/UDP peer tests and wrong-key/PSK denial; dedicated health peer avoids active-key roaming |
| Coordinated activation | Immutable source/artifact snapshot, shared engine-owned cache, namespace commit before ingress/DNS release, forward recovery across both crash windows |

For WireGuard fallback, the dedicated peer observes server reachability; a
separate bounded canary through the actual active process is required. Native
RouterOS WireGuard interface provisioning remains a future adapter.

## Native CHR acceptance

The separate `lab/coregateway` container exercises the generalized production
`coreactivation.Transition`, supervisor, publisher and platform barriers. Its
198.19/16 namespace and `/data/core-v3` state preserve the older laboratory roots
and 198.18 aliases. Fixture REST/control credentials are public and disposable;
production RouterOS readback requires HTTPS and generated owned observer hooks.

The native kernel places its local-table rule at priority 200. The barrier pins
that exact local exception, scopes ingress to priority 10000/table 100 and
refuses earlier foreign policies. Initial read-only REST transport failure is
retried within the existing quarantine deadline; denial, malformed data and
ownership mismatch fail immediately. Read unavailability never proves DOWN.

The independent literal-IP canary must observe the proxy server source even
with no active user domains. Native readiness grants no lease while DNS
admission, immutable alias/backend readback or the current path proof fails.

The [completed native run](product-phase-3-evidence/native-core.json) retained six
immutable aliases (198.19.0.2–198.19.0.7), with namespace revisions 10–17. It
passed retirement, real DNS after retirement, cached aliases, source .20 PROXY /
.30 DIRECT, all-retired readiness, reactivation, stale-write refusal, container
stop/reopen and damaged-native-binding refusal/forward recovery. Fresh fourth
and fifth additions were proved in an [earlier bounded run](product-phase-3-evidence/fresh-additions.json);
the final run reused the retained namespace rather than resetting its ledger.
The controlled server supplied six names with explicit real-DNS TTL 30 seconds.

Each cached matrix used foreign HTTP Host and HTTP/3 SNI (`unselected.test`).
All **72 UDP workloads** have matching [WAN packet witnesses](product-phase-3-evidence/udp-witnesses.json):
proxy payloads traversed VLESS TCP to 10.77.0.10:8443, DIRECT payloads went to
10.77.0.20:9000. Capture digests are in [the summary](product-phase-3-evidence/captures.json);
raw PCAP stays local outside Git.

At `after-verify`, disk retained committed revision 15 plus pending revision 16.
At `before-release`, disk held committed revision 17 without pending. Both
abrupt parent exits revoked native readiness, preserved cached DIRECT service,
and recovered the intended active policy on restart without changing any alias.

[Offline read-only inspection](product-phase-3-evidence/native-files.json) after
clean RouterOS shutdown confirmed private 0700 state directories and a 0600
namespace journal. The actual container executable SHA-256 equals the rebuilt
fixture binary: `81abfacf2f2d19573d9711c8cbd395440412568f248c0708933f8f33dd316ea4`.
[Build metadata](product-phase-3-evidence/build.json) records the corresponding
rebuild image digest; the imported initial image was updated with that exact
executable during development, so the rebuilt image itself is not a separately
accepted install/upgrade artifact.

[Cleanup](product-phase-3-evidence/cleanup.json) stopped the core and all legacy
containers, restored the observer disabled state and default DNS fixture,
confirmed an empty volatile readiness lease and unchanged existing static
routes/NAT/mangle/services/scheduler/certificates. Connected route IDs and
transient service connections were excluded from static configuration comparison.
All durable core reservations remain. The container disk was expanded offline
from 2 GiB to 4 GiB after a clean shutdown, preserving its filesystem UUID and
an untouched 2 GiB backup; older roots and caches were retained.

## Validation and limits

`make check cross-build` passed: repository race tests, vet, actual pinned engine
schema/namespace/binding smoke checks and Linux amd64/arm64 builds. Protocol tests
use controlled real peers and explicit authentication/TLS failure cases.
Transition unit tests also cover copied immutable rule-set recovery after a
provider refresh and preflight refusal before replacing a healthy process.

Native evidence covers process death and fresh TCP/UDP/HTTP3 connections. It does
not assert power-loss durability, atomic packet cutover, established-flow
migration, IPv6 FakeIP, packet-loss bounds, production authentication or a wider
RouterOS device/version matrix. These remain explicit later-phase acceptance
items. Arbitrary alias reassignment after lost state is never supported.

Reproduce with the pinned lab assets, a separate container root and
`python3 tests/e2e/chr_core.py`; verify packet paths with
`scripts/summarize-lab-pcap.py` and `scripts/verify-activation-capture.py`.
See [core guide](../core.md), [fixture guide](../../lab/coregateway/README.md),
[transition contract](../../internal/coreactivation/README.md) and
[canonical nine-phase roadmap](../product/progress.md).
