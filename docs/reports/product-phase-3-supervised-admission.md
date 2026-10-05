# Product Phase3: supervised admission and fallback

Recorded 2026-10-06. Product Phase3 remains in progress.

The v2 generator now accepts a committed finite namespace, retains every Known
allocator key, routes retired cached aliases DIRECT before sniff, and performs
strict regeneration-based preflight. Trusted runtime cache mapping is included
in that comparison. Existing v1 laboratory behavior is preserved.

`grouphealth` obtains real per-endpoint observations from isolated authenticated
loopback sing-box processes. It records latency, last success/failure and
availability. Fresh successful status/body/TLS/optional egress checks determine
health. Wrong credentials cannot succeed through an implicit DIRECT bypass.
Fallback switches through a supervised apply callback; all failed endpoints
quarantine. Model edits stage first and only apply after fresh observation.

`coreactivation.Managed` connects fallback decisions to a durable model registry,
supervisor, admission and DNS switcher. Commit precedes traffic release. Every
tick verifies alias/backend state even when no group switch is needed. Source
models needed for LKG/pending recovery remain private and survive reopen; unused
models are pruned from the supervisor's retained revision set.

| Evidence | What it proves |
| --- | --- |
| Real pinned cached-alias test | Active/retired alias identity across graceful restart; hostile HTTP Host/TLS SNI cannot change terminal routing; real SS relay counters confirm paths |
| Real pinned health tests | Two local SS endpoints, incorrect credentials, failure/switch/recovery, all-failed quarantine, trusted HTTPS and refusal of untrusted TLS, redirects/status/body limits |
| Composition fault tests | Supervisor/admission/gate order, commit-before-release, durable registry reopen, backend outage, cache loss before allocator access, foreign alias refusal, namespace drift refusal |
| Managed controller tests | Ordered fallback, staged model edits, all-failed child stop, fresh recovery, backend failure despite healthy canaries, revision pruning and closed lifecycle |
| Regression checks | `make check cross-build`: race/vet, actual pinned host smoke/binding/namespace checks, CLI and internal packages compile for Linux amd64/arm64 |

The composition tests use a deterministic child and injected ledger/engine/
forwarding dependencies. The actual engine tests use private mixed sockets and
controlled local servers. The new bridge has **not** been accepted on native CHR:
its platform Barrier, private startup umask and coordinated namespace changes
remain to be integrated and tested. No new router mutation or public endpoint
was introduced in this block. Full rule metadata/service lists/remote rule sets,
modern WireGuard and broader protocol runtime coverage remain Phase3 work.

See [the adapter contract](../../internal/coreactivation/README.md),
[health contract](../../internal/grouphealth/README.md) and
[ADR0019](../adr/0019-supervised-core-admission-and-group-health.md).
