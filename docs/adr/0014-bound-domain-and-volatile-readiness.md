# ADR-0014: bound-domain authority and volatile native readiness

Status: accepted for the finite Phase6 laboratory; production integration OPEN.

A published alias has an immutable admitted domain. HTTP Host and TLS/QUIC SNI
must not replace this domain when choosing PROXY. In stock sing-box1.14.2 the
FakeIP destination is rewritten to the stored domain before rule evaluation;
sniffing can subsequently introduce another domain, preferred by the domain
matcher. A FakeIP CIDR rule cannot repair this because its matcher examines the
rewritten destination rather than `OriginDestination`.

The bounded engine configuration therefore requires six rules in exact order:
DNS hijack, source DIRECT, source PROXY, terminal selected-domain PROXY, sniff,
selected-domain PROXY. The first domain route protects admitted aliases before
sniffing. The last retains cohost classification for real-IP traffic that enters
the engine. Hybrid traffic addressed directly to a real IP bypasses this engine.
This is a closed three-name/source fixture, not a general policy compiler.
The guard rejects alternative order, destination override and CIDR substitutes.
See the pinned source links in [engineguard](../../internal/engineguard/README.md).

Persistently enabled RouterOS selectors depend on one RAM-only readiness lease:
`mc-lab-up-lease`, address192.168.88.0/24, finite timeout6s. DNS DNAT requires
membership; the permanent cached-alias fallback jump requires nonmembership.
Every issued alias must already have an exact persisted DIRECT mapping before
publication. On reboot the lease is absent: fresh DNS stays native and mapped
aliases are DNATed before routing. The startup scheduler is defense in depth.
The permanent FakeIP route alone offers no fallback for unpublished aliases.

One existing Netwatch observer renews the lease through `test-script`, not just
its transition callback. UP validates exact observer target/status, all selectors,
and uniqueness/dynamic shape of the token before its final renewal mutation.
DOWN removes the lease first. Static/duplicate tokens or an unrelated HTTP200
endpoint cannot grant readiness. Scripts retain read/write/test permissions.
The lease backend is an explicit laboratory opt-in; historical fixtures remain.
The one-shot migration is not atomic; a failed import requires explicit repair.

Finite address-list entries are documented as RAM-only and lost on reboot in
[MikroTik address lists](https://manual.mikrotik.com/docs/firewall-and-quality-of-service/firewall/address-lists/).
[Netwatch](https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/netwatch/)
documents `test-script` execution for each probe. Native Phase6 evidence verifies
both behaviors on CHR7.24.5. The configured6s timeout is not an exact failover
bound: an expired row can remain visible with timeout0s before deletion.
Existing conntrack translations, power-loss recovery, all devices/releases and
namespace reuse are outside this decision's accepted proof.
