# ADR-0004: Owned desired state and compensation

Status: ACCEPTED for prototype planner/mock; production apply deferred.

Use exact comments `mikrocentauri:<instance>:<kind>:<id>`, validated against the
resource path. Compare owned current state with desired fields, ignoring REST-only
runtime fields. Never delete unknown/other-instance objects. Duplicate ownership
is a hard error. User comments are not an authorization boundary.

Prototype implements bounded REST discovery for five supported collections, HTTPS
by default, no redirects, credential-redacted errors, deterministic plan, and
lab-only apply with compensating operations. Before mutation, reject stale IDs,
changed fields, malformed actions and ownership transfers. Mock proves repeated
apply→discover→plan is empty and failure restores prior touched values.

No live product apply entrypoint is provided. Phase 2 adds a separate lab-only
`LabController`: a private fsynced write-ahead journal, per-directory process lock,
intent before mutation, fresh ownership checks, rediscovery after lost replies,
realized writable-state verification, and explicit restart recovery. Recovery
refuses conflicting managed-field edits. Journal errors leave pending state visible.
Resource allowlists exclude runtime fields and credentials; scripts cannot enter
rollback payloads. Ordered firewall deletion is refused because recreation loses
placement. Route rollback may recreate an object under a new ID.

Actual CHR 7.24.5 tests prove disabled-route create/update/idempotence/delete and
recovery by a new process after a successfully executed PUT with a lost reply.
Native compatibility required preserving literal `*` in REST object-ID paths and
recognizing RouterOS `static` as a runtime flag. Mock tests additionally cover
crash boundaries, external conflicts, writable-field rejection and process locking.
See [Phase-2 evidence](../reports/phase-2-resilience.md).

Outstanding: capability discovery, complete release-specific writable schemas,
ordered placement, whole-generation activation protocol, startup reconciliation,
LKG router revision and coordination with native watchdog mutations. The journal
is scoped to one controller destination/instance, not a distributed lock for other
writers. Exact comments do not secure ownership against an administrator. Lab
proof is not full production transactional-controller acceptance.
