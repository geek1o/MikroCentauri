# Product Phase 2: RouterOS Controller completion

Acceptance profile: RouterOS CHR 7.24.5 stable, x86_64, native `www-ssl`, trusted CA.
This closes the nine deliverables of original product Phase 2 on that profile.
It does not declare the application an MVP or extend acceptance to untested
releases/devices. Phases 3–8 still carry core lifecycle, API/UI, installation,
security/device coverage and release acceptance.

## Deliverable checklist

| Original deliverable | Implementation and acceptance |
| --- | --- |
| REST client | Authenticated certificate-verified HTTPS, no redirects, bounded string-valued responses, duplicate/invalid row rejection and redacted failures |
| Capability discovery | Version/platform/packages/interfaces plus managed resource availability; native CHR profile gate |
| Desired-state model | Explicit owned objects, complete desired set, explicit disabled state, optional firewall placement anchor; generated observer/boot guard bundle |
| Planner | Fresh logical diff; exact ownership; deterministic safe object order; missing/dynamic/moved placement anchors refused |
| Apply | Active and staged constructors; durable intent, native readback and final verification; exact repeated committed apply is a no-op retaining rollback |
| Rollback | Explicit committed rollback, interrupted-write recovery, bounded automatic compensation for managed apply/reconcile, preserved pending journals on ambiguity |
| Reconcile | Recovery, discovery, planning and application under one exclusive lock; complete-set verification and CleanupManaged |
| Managed ownership | Exact instance/kind/comment checks; no unknown deletion; external edits and ambiguous duplicate ownership refused |
| Netwatch fail-open | Generated HTTP observer, immediate DOWN, three-positive-probe UP debounce, exact target and endpoint checks, generated native startup guard |

Source: [controller](../../internal/platform/routeros/controller.go),
[operations](../../internal/platform/routeros/operations.go),
[placement](../../internal/platform/routeros/placement.go),
[watchdog](../../internal/platform/routeros/watchdog.go),
[CLI](../../cmd/mikrocentauri/router.go).

## Managed execution contract

The existing `router-stage`, `router-reconcile` and `router-recover` retain their
explicitly disabled-object restriction. Operational commands are separate:
`router-managed-plan`, `router-watchdog-plan`, `router-apply`,
`router-managed-reconcile`, `router-managed-recover`, `router-verify`,
`router-rollback` and `router-cleanup`. Connection files, desired state, plans and
watchdog specifications are private regular 0600 files; journal directories are
private and exclusively locked. See the [CLI guide](../controller.md).

Netwatch and scheduler hooks are accepted only after decoding their inert
structured specification and regenerating every writable field. Merely adding
an ownership comment does not admit an arbitrary executable script. Scheduler
access was added narrowly for the generated startup guard; discovery now covers
six managed collections. The default staged path enforces the same hook checks.

Operational desired state is an explicit management request. Its caller supplies
valid routing semantics and a readiness endpoint that checks the applied
configuration, engine, DNS and dataplane. A plain HTTP200 alone is not proof of
those conditions. Core runtime supervision and readiness integration belong to
Phase 3; production App provisioning belongs to Phase 6.

## Placement and compensation

A desired firewall object can specify `place_before` as a native static anchor ID
in the same collection. New objects are created there and their position is read
back. A moved existing rule is refused; the caller must review an explicit
replacement rather than silently rearranging user rules.

Immediately before each firewall DELETE, the journal records table order, native
IDs, ownership keys and configuration digests. Compensation verifies the complete
surviving order/configuration, restores the rule before its original successor or
at a verified end, then verifies the restored table. Reverse compensation handles
multiple deletions and new IDs from restored owned rules. Runtime packet counters
are excluded; configurable user edits are not ignored. A conflicting anchor stops
recovery before a compensating write. The journal contains digests of unrelated
rule configuration, not raw user rule snapshots.

The local lock serializes cooperating controllers, not arbitrary RouterOS clients.
Native scripts and external administrators can still act concurrently. Quiesce
the observer before changing its targets; stale or conflicting values cause a
refusal and retain recoverable state. No REST transaction or atomic traffic switch
is claimed. The most recent transaction is rollback history, not a full LKG
configuration store.

## Native watchdog

The observer uses a dedicated HTTP root readiness port, HTTP200, a 2s interval,
1s timeout and three consecutive positive probes. DOWN is applied on the first
failed probe. Every probe verifies its own host/type/port/code tuple, the unique
exact owned target set and all supplied non-disabled target fields. Routing is
enabled before DNS interception; disable order removes DNS steering first.
Already-correct disabled switches are left alone to avoid repeated writes.

Debounce state is a RAM-only dynamic address-list row with a finite 5s timeout,
exact generated list/comment and bounded encoded count. Static, foreign or
multiple counter rows cannot grant readiness. DOWN and boot cleanup remove only
exact owned dynamic rows; foreign/static blockers remain intact for diagnosis.
This is debounce state, not the dataplane readiness lease.

The initial native experiment showed a `:global` counter returning to one for
each test invocation. It was replaced with native RAM state. Native selector
syntax also required `dynamic=yes`; `start-delay=0s` is returned as `0ms`. These
compatibility corrections were incorporated before final acceptance.

A generated startup scheduler disables the exact target set and clears dynamic
counter state after reboot. The test observes state after management returns;
it does not establish ordering before the first LAN packet. FakeIP installations
still require the independently proved volatile lease and cached-alias fallback
from [ADR 0014](../adr/0014-bound-domain-and-volatile-readiness.md). Existing
conntrack sessions are not migrated or globally cleared.

## Evidence and limits

The final native runner covers active apply, exact repeated apply, complete-set
verification, initial placement between foreign anchors, two deletions and exact
ordered rollback, conflicting-anchor refusal/repair, cleanup, native generated
observer/guard installation, initial DOWN, debounced UP, failed readiness, healthy
recovery, incorrect target generation, duplicate ownership, counterfeit static
counter, unrelated healthy endpoint, actual reboot and recovery, idempotent
reconciliation and final cleanup. Unrelated configured-state hashes are compared
before and after. Test fixtures use documentation addresses and a controlled
readiness listener; the existing gateway is not started by this test.

[Native results](product-phase-2-completion-evidence/results.json),
[executed binary](product-phase-2-completion-evidence/binary.json),
[account policy](product-phase-2-completion-evidence/account-policy.json) and
[host checks](product-phase-2-completion-evidence/host-checks.log) are retained.
The native run completed successfully. Unrelated configured-state hash before and
after: `79cf5c09b7603aa4ede9befb3d9450d353f5b9808419db18b49a0e79fff0b580`.
Observed DOWN after failed readiness: 2.318s; healthy UP: 6.290s; post-reboot healthy
UP: 6.240s. These are this runner's sampling times, not hardware latency bounds. The preceding
[HTTPS staging report](product-phase-2-staged-controller.md) additionally supplies
native lost-PUT-reply/fresh-process recovery and certificate-trust rejection.
Host acceptance runs race tests, vet, pinned sing-box validation/integration and
linux/amd64 plus linux/arm64 builds. Unit fault cases additionally cover rollback
response loss, unknown fields, malformed journals, foreign edits, file permissions
and process locks.

Account used on CHR: dedicated `mc-lab`, policies `read,write,test,api,rest-api`,
with no `full` group and no production credentials. Netwatch and the generated
scheduler use read/write/test; permission checks remain enabled. RouterOS
permissions are coarse and cannot enforce our ownership namespace. Host management
ports bind to loopback in the disposable lab; installation must restrict management
reachability to its controller network. API authentication, broad security
hardening, power-loss/early-boot traffic acceptance and other versions/hardware
remain future-phase requirements, not evidence established by this report.

Primary interfaces: MikroTik [REST API](https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST%2BAPI),
[Netwatch](https://help.mikrotik.com/docs/spaces/ROS/pages/8323208/Netwatch),
and [address lists](https://manual.mikrotik.com/docs/firewall-and-quality-of-service/firewall/address-lists/).

## Final cleanup

[Cleanup evidence](product-phase-2-completion-evidence/cleanup.json) confirms
removal of the controller scope, foreign test anchors, dynamic debounce counters
and temporary certificate/archive, with native TLS service settings restored to
the initial baseline. CHR is shut down normally and its existing persistent lab
disk is retained. Private connection/key material remains ignored locally.
