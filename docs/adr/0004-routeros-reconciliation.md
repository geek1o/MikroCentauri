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

No live product apply entrypoint is provided. Outstanding: durable mutation journal,
capability discovery, version-specific writable field schemas, ordered placement,
verification of realized state, reconcile startup loop, LKG router revision, concurrency
serialization/recovery. A successful POST followed by a dropped response is ambiguous;
controller must rediscover and compensate by ownership. Lab prototype reports that
limitation, but does not constitute a durable transactional controller.

Deletion rollback recreates objects with new RouterOS IDs; current lab code filters
some runtime fields but full resource-specific writable-field handling is not ready.
Never present mock tests as real RouterOS REST compatibility proof.
