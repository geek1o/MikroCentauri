# ADR-0015: append-only allocation history and active policy revisions

Status: accepted for the bounded IPv4 CHR laboratory; production controller OPEN.

Separate the ordered accumulated `Known` namespace from its `Active` subset.
Retirement removes a domain from Active only. Its original engine alias and
persisted native fallback remain reserved forever. Reactivation uses that alias;
new names append after all existing names. There is no TTL-based deletion,
compaction, transfer or reuse. Capacity exhaustion rejects a candidate.

`internal/namespace` persists a committed revision and a pending candidate under
an exclusive process lock, mode0700 directory/mode0600 files, atomic rename and
file/directory fsync. Preview validates a candidate without mutation; Prepare
rechecks the expected revision before recording its intent. A failed durable
write poisons the handle until reopen. Commit accepts only the pending revision.
The library's Abort consumes the revision and retains added Known reservations;
the gateway exposes explicit resume, not automatic abort or garbage collection.

The isolated gateway transition holds public DNS, revokes generation receipts,
quarantines ingress, gracefully closes the old engine and observes native DOWN
with no readiness lease. It durably prepares the candidate before any new engine
allocation, validates/writes its exact engine configuration, checks all existing
ledger bindings before querying additions, and verifies every native fallback.
Only then does it commit the revision, enable TUN and release public DNS. Native
UP still requires the normal health hysteresis. Pending startup is quarantined
with no child and requires an explicit matching resume request.

Engine DNS retains FakeIP allocation for every Known name. Public DNS sends
retired/nonactive queries to a separate real resolver with FakeIP-leak validation.
Active PROXY and retired DIRECT terminal routes both precede sniff and follow
source overrides. Removing only the public DNS rule or adding only a late DIRECT
rule would leave cached clients vulnerable to Host/SNI reclassification.

One immutable DNS handler is installed for each generation. Hold cancels all
in-flight requests, including real DNS, and an epoch check refuses their late
Handle results. This does not promise an atomic boundary at the transport write,
nor invalidate answers clients already received before the transition.

A verification that crosses the remaining whole-second DNS lease floor can be
retried once by background Reconcile, obtaining a new authoritative lease and
fresh backend proof. No old TTL is extended. Publication itself continues to
reject expired receipts, and unrelated failures are not retried by this rule.

The gateway keeps selected.test active as its fixed lab health canary. The core
store and policy validator can represent an empty Active set, but that is not an
accepted gateway scenario. Controls are explicit unauthenticated lab endpoints;
production authentication, writer isolation, coordinated rollback/automatic
recovery and hardware/device coverage remain open. Existing conntrack sessions
are outside the fresh-flow policy proof. See the
[Phase7 report](../reports/phase-7-namespace-lifecycle.md).
