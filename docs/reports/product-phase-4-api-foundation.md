# Product Phase 4: authenticated API foundation

Recorded 2026-10-06. Phase 4 remains in progress.

The first backend block adds a TLS-only v1 HTTP boundary, private initialized
password hash, rate-limited login, expiring opaque bearer sessions and generated
OpenAPI. Draft persistence is separate from actual activation; plans bind the
candidate, namespace revision and expiry. Replay, stale revision and pending
state fail closed. Dependency errors are projected to fixed error codes.

`api.CoreRuntime` delegates to the accepted `coreactivation.Transition` owner.
Its new read-only model/preflight methods are tested against the real coordinator
fixture: validation leaves the active PID, namespace and alias ledger unchanged.
The standalone CLI remains an offline configuration service until its runtime
factory is connected; it explicitly reports not-ready and cannot apply.

Coverage includes actual TLS HTTP login/read, wrong origin/client/header/query
refusal, authentication expiry/restart/rate limit, private directory/file modes,
second-owner refusal, draft reopen, model/schema errors, single-use/stale/expired
plans, failed runtime apply with pending readiness, and secret-free safe export,
restore preview and diagnostics. Tests use deterministic runtime callbacks for
HTTP apply; they do not establish a new native RouterOS API acceptance.

Next required blocks are production runtime composition/startup, RouterOS and
subscription resource adapters, unified RouterOS/core preview and apply history,
complete response schemas, diagnostics bundle and application-wide backup/restore.
The current `501` routes and offline `503` apply are documented boundaries, not
completed adapters. Full encrypted backup remains outside this first block.

`make check cross-build` passed, including all repository race/vet checks,
pinned engine smoke and Linux amd64/arm64 builds. Additional final tests passed
for persistence-error poisoning and generated/published OpenAPI consistency.

See [API usage and security contract](../api/README.md),
[generated OpenAPI](../api/openapi.json) and [roadmap](../product/progress.md).

The runtime-host/resource block is now recorded in
[Phase 4 runtime host and resources](product-phase-4-runtime-resources.md);
its implemented adapters supersede those earlier open items only.
