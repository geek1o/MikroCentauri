# Product Phase 4: runtime host and resource adapters

Recorded 2026-10-06. Phase 4 remains in progress.

The API now accepts an application lifecycle host around the existing
`coreactivation.Transition`. Startup holds readiness, recovers the durable
intent and requires ledger/core/current-canary proofs. Periodic failures hold
and stop the core; recovery preserves the pending namespace and alias history.
Shutdown cancels work and closes the owner once. A separate private boolean
readiness handler serves the native observer; authenticated `/system/recover`
provides explicit recovery. Trusted composition callbacks are not HTTP inputs.

Plans now bind the generated candidate as well as the draft and revision. A
rule-set refresh after planning returns `409 candidate_changed` before replacing
a healthy process. The real coordinator resolves artifacts once under its owner
lock, compares the candidate fingerprint and pins that same artifact snapshot.
Regression tests prove refusal without namespace/PID change and freezing when
the resolver's latest artifact changes immediately after its read.

The standalone HTTPS CLI wires its private subscription registry/cache and an
optional verified RouterOS connection. RouterOS resources perform GET only and
expose capabilities/owned counts rather than raw rows. Subscription configure,
refresh, bounded inspection and restart persistence are available; malformed
updates retain the last successful nodes. Refresh does not activate imported
nodes or bypass configuration plans. Subscription URLs and node credentials
remain absent from HTTP status, logs and diagnostics.

A downloadable diagnostics archive uses fixed private names, redacted
projections and an 8 MiB JSON limit. OpenAPI includes the new endpoints and typed
RouterOS/subscription GET responses.

## Validation

Tests cover actual HTTPS RouterOS discovery with Basic Auth and zero mutations,
real trusted HTTPS subscription refresh/LKG retention, default SSRF and untrusted
TLS refusal, private registry ownership/reopen, bounded node pages, diagnostic
archive structure/redaction, host recovery/canary/shutdown and authenticated host
apply/recovery. Host failure tests use a deterministic CoreOwner; actual
coordinator tests exercise the prepared candidate guard with deterministic child
and admission seams. They are distinct from native packet-path acceptance.

`make check cross-build` passed with repository race tests, vet, pinned engine
smoke and Linux amd64/arm64 builds. The generated OpenAPI matches its tracked
contract; no production router or subscription was modified during validation.

## Open deployment boundary

The current native mapping backend is explicitly lab-specific. This block does
not relabel it as a production profile or construct it from untrusted API input.
A native application factory must supply an accepted mapping chain, placement,
boot/lease guard and listener profile. Standalone `api-serve` still reports
not-ready and cannot apply until that runtime is composed by the application.
New native API/runtime-host acceptance, unified RouterOS/core plans,
application-wide backup/restore and complete resource-response schemas remain
Phase 4 work. Subscription deletion/import-to-draft and periodic scheduling are
also separate resource-management steps.

See [API contract](../api/README.md), [OpenAPI](../api/openapi.json) and
[the product roadmap](../product/progress.md).
