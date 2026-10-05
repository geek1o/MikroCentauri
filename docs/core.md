# sing-box core development

The product core uses schema v2, separate from the v1 bounded CHR laboratory
configuration. This block adds endpoint import, subscription persistence, group
and rule generation, and a reusable child supervisor. Product Phase 3 is
[accepted on the pinned CHR profile](reports/product-phase-3-core-completion.md),
including coordinated namespace admission and native recovery.

## Private CLI

Build `./cmd/mikrocentauri`. Input files containing credentials must be regular
0600 files without symlink components. Generated candidates and subscription
snapshots contain credentials; store them outside Git in private directories.

```sh
mikrocentauri endpoint-preview -uri-file /absolute/private/endpoint.txt
mikrocentauri subscription-refresh -config /absolute/private/subscription.json -state /absolute/private/subscriptions
mikrocentauri subscription-status -id provider -state /absolute/private/subscriptions
mikrocentauri subscription-run -config /absolute/private/subscription.json -state /absolute/private/subscriptions -interval 1h
mikrocentauri core-check -config /absolute/private/core.json -sing-box /absolute/path/sing-box
mikrocentauri core-generate -config /absolute/private/core.json -out /absolute/private/candidate.json -sing-box /absolute/path/sing-box
mikrocentauri core-preview -config /absolute/private/core.json
mikrocentauri ruleset-import -id selected-list -format source -file /absolute/private/list.json -state /absolute/private/rulesets -sing-box /absolute/path/sing-box
mikrocentauri ruleset-refresh -config /absolute/private/ruleset-spec.json -state /absolute/private/rulesets -sing-box /absolute/path/sing-box
mikrocentauri ruleset-load -id selected-list -state /absolute/private/rulesets
mikrocentauri core-check -config /absolute/private/core.json -ruleset-state /absolute/private/rulesets -sing-box /absolute/path/sing-box
```

Subscription specification:

```json
{"id":"provider","url":"https://provider.example/subscription/REPLACE_LOCALLY","include":"Europe","exclude":"expired"}
```

Manual refresh reports redacted node previews, timestamps and failure status.
Periodic refresh performs one immediate attempt, then refreshes at the requested
interval. Failures preserve the previous successful nodes on disk. Periodic
state can be inspected with `subscription-status`; SIGTERM/interrupt stops the
loop. The default downloader rejects private and special address ranges,
validates every resolved address, and dials the validated address directly.
Redirects receive the same checks; HTTPS downgrade is refused. The library has
an explicit allowed-CIDR policy for controlled private deployments and tests;
the CLI does not relax the default policy.

The importer accepts a strict subset of VLESS TCP (TLS/Reality), Shadowsocks
SIP002 AEAD, Trojan TLS TCP and Hysteria2 TLS QUIC. Unsupported transport,
plugin, obfuscation and insecure TLS options fail rather than disappearing.
URI-list and base64 subscriptions share this parser. Parser adapters are
pluggable; Clash/Mihomo formats are not implemented yet.

The core model also accepts validated modern WireGuard endpoints in `wireguard`.
Their stable IDs can be selected directly or referenced from groups. Generation
uses sing-box's top-level `endpoints` array; it never revives the removed legacy
WireGuard outbound. `core-preview` omits WireGuard private, public and preshared
keys and proxy credentials. `Model.Clone` revalidates an independent deep copy.
Installing native RouterOS WireGuard interfaces remains a separate future adapter.

Rules carry `id`, `name`, an optional `enabled` flag, `priority`, source CIDRs and
destination predicates. Omitted `enabled` preserves the existing v2 enabled
behavior; explicit false removes the rule from generation. Lower priority values
run first and equal priorities retain the model's declared order. Global source
DIRECT policies precede global source PROXY policies. Exact known FakeIP domain
routes then apply per-rule source, port, network and named-service qualifiers
before sniff. This supports device/service policies without allowing HTTP Host
or TLS SNI to reinterpret an alias's destination. Retired names retain terminal
DIRECT routes; ordinary real-DNS classification follows sniff. Named services
preserve their port/network tuples rather than broadening them into a Cartesian
product. IP and external rule-set predicates do not expand the FakeIP allocator.

Rule-set remote specification:

```json
{"id":"selected-list","url":"https://rules.example/selected.json","format":"source"}
```

Local imports support modern source JSON and SRS binary. The manager accepts a
bounded headless subset, validates with the real pinned compiler, and produces
immutable SHA-256 named binary files with private manifests. Remote refresh uses
verified HTTPS, checks every resolved destination, pins the dial address and
rejects private/special addresses by default. Environment proxies are disabled;
redirects repeat validation. Malformed or unsupported updates preserve the prior
LKG manifest. Regex, legacy GeoSite/GeoIP and unknown predicates are rejected.
Generated configs reference verified local files; the engine never fetches a
remote rule-set itself. A model with `rule_sets` requires `-ruleset-state` during
generation/check; resolved file paths cannot be injected through the model JSON.

## Configuration and activation boundary

See [the core schema contract](../internal/coreconfig/README.md) for model fields,
routing precedence and private listener behavior. The default ports are DNS5353
and mixed2080 on loopback. Hybrid/full candidates contain a TUN with automatic
route installation disabled. `/data/` is the persistent container cache root.

`core-check` and `core-generate` validate with sing-box1.14.2. They do not apply
RouterOS objects or start the engine. A successful syntax check does not prove
that an existing cached FakeIP namespace can accept a changed policy.

Fallback compiles to a selector. The application chooses the first freshly
healthy member through `FallbackSelection`, then creates a validated replacement
with `Model.Select`. [Endpoint health](../internal/grouphealth/README.md) now probes
each enabled endpoint through an isolated checked engine and genuine HTTP(S)
canary. WireGuard probes require a separately provisioned remote peer with a
different key identity and local IP; reusing the active key would redirect the
remote peer to the probe socket. The dedicated peer proves provider reachability.
For WireGuard fallback, `coreactivation.Managed` also requires a bounded
`ProbeCurrent` canary through the actual active process on every successful tick;
failure closes gates and stops the child. It applies selection through the
supervisor, admission and DNS gate. URLTest uses the upstream outbound implementation.

The supervisor API requires semantic validation and quarantine, prepare,
readiness-probe and release hooks. The new [finite core adapter](../internal/coreactivation/README.md)
connects these hooks to the existing DNS gate and finite namespace admission for
one fixed committed snapshot. Its mandatory platform Barrier still requires
native forwarding/lease acceptance. Supplying empty hooks would not establish
transparent readiness.
There is deliberately no transparent `core-run` command before this adapter
is accepted. PID existence alone cannot establish readiness.

The supervisor keeps at most five known-good SHA-256 revisions in a private
0700 directory with 0600 files and an exclusive process lock. It records a
pending revision before replacement, proves readiness, commits the active
revision durably, then releases traffic. Validation failure preserves the
running child; activation failure attempts a quarantined LKG restart.
Unexpected child exit closes readiness and triggers bounded exponential
backoff; repeated failures enter a crash-loop state. Lifecycle event codes
are bounded and redacted, and raw child output is discarded. Linux children
use parent-death termination; startup refuses ambiguous recorded PID ownership
instead of killing a possibly unrelated process. Hooks must honor their context
and perform real readiness checks. `/live` and `/ready` HTTP integration remains
part of the backend work; the supervisor exposes separate process and readiness
state to that integration.

## Accepted core and subsequent work

The generalized transition owner and platform barriers passed native CHR
retirement/reactivation, retained aliases, child replacement, damaged backend
recovery and both namespace crash windows. Private startup permissions and the
actual runtime binary were checked offline; immutable SRS recovery after refresh
also passed fault tests. See [the acceptance report](reports/product-phase-3-core-completion.md)
for the bounded forwarding evidence and explicit limits. Native RouterOS
WireGuard provisioning remains a future adapter. The next product phase is
Backend/API with production authentication, OpenAPI, diagnostics and backup.
