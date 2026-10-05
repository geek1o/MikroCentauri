# Phase 8, step 1: reusable activation and recovery core

Date: 2026-10-05. Implementation: `internal/activation`.

Added a serialized policy coordinator over the existing private namespace store.
It validates new intent before stopping service, then orders quarantine, durable
Prepare, Stage, Verify, Commit and Release. Recovery repeats proof for either a
pending or committed revision before releasing traffic. Cleanup remains possible
after request cancellation; a failed cleanup is reported rather than interpreted
as successful quarantine. See [ADR 0016](../adr/0016-policy-activation-recovery.md).

Fault tests use the real durable namespace store and a recording runtime adapter.
They cover failures at quarantine/stage/verify/release, cancellation before Commit
and after partial Release, close/reopen recovery, stale/invalid/capacity rejection,
pending-intent protection, copied callback inputs, repeatable committed recovery,
cleanup errors and concurrent compare-and-swap. Release inspects the actual store
and rejects a pending or mismatched revision. These tests model process restart
through store reopen; they do not prove hardware power-loss behavior.

Validation: `make check cross-build` (race suite, vet, real pinned sing-box
namespace/binding/smoke checks and Linux CLI builds). The activation package also
builds for Linux amd64 and arm64. No native CHR replay was run for this step.

This is the first bounded step of Phase 8. The new core is not wired into the
lab gateway or CLI, so native behavior is unchanged. Next: implement a runtime
adapter that separates engine admission from DNS release, then replay pending
recovery and the post-Commit crash boundary on CHR. Production controller,
authenticated management, supervisor/LKG and device coverage remain open.

The runtime integration and native acceptance followed in the
[completed engineering milestone report](phase-8-activation-recovery.md).
This document preserves the scope of the first core-only step.
