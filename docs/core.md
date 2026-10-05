# sing-box core development

The product core uses schema v2, separate from the v1 bounded CHR laboratory
configuration. This block adds endpoint import, subscription persistence, group
and rule generation, and a reusable child supervisor. Product Phase 3 remains
in progress until the generalized runtime is connected to namespace admission
and the complete rule/endpoint requirements are accepted.

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
with `Model.Select`. It still needs a real health observation adapter and a
supervised apply loop. URLTest uses the upstream outbound implementation.

The supervisor API requires semantic validation and quarantine, prepare,
readiness-probe and release hooks. These hooks are the integration boundary
for the existing DNS gate, finite namespace admission and RouterOS activation
controller. Supplying empty hooks would not establish transparent readiness.
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

## Remaining Phase 3 work

Connect the generalized model and supervisor to the existing transparent
activation runtime; implement real health observations and fallback switching;
extend ordered rules with names, enable/priority state, service lists and modern
remote rule sets. Complete protocol runtime coverage beyond the current local
VLESS and Shadowsocks TCP evidence. Add WireGuard through the modern endpoint
abstraction: upstream documents [WireGuard endpoints](https://sing-box.sagernet.org/configuration/endpoint/wireguard/)
since1.11; the old outbound must not be revived. Native RouterOS WireGuard
remains a future adapter. Backend/API and its authenticated health endpoints
belong to Phase4.
