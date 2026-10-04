# Phase 3: dynamic DNS publication after router acknowledgement

Executed 2026-10-04 UTC / 2026-10-05 Moscow. **Publication protocol lab step complete;
production lifecycle acceptance remains OPEN.** Same isolated CHR7.24.5/Alpine3.24.2,
sing-box1.14.2 musl and QEMU TCG topology as earlier phases. No production router,
subscription, real credential or external proxy was used.

## What changed

The gateway retains the stock sing-box allocator/cache behind loopback5354. A new
UDP/TCP DNS gate on5353 asks that allocator for an alias, then withholds the selected
A answer until the publication service has saved pending intent, installed/read
back the exact router backup mapping and fsynced ready state. Publication errors
produce SERVFAIL without an A address. Every later gated response repeats fresh
router verification; local ready state alone never authorizes a reply.

The private ledger pins domain, engine alias and real IPv4 target across restart.
It refuses alias changes/collisions and never frees reservations after failed
publication. The gateway uses32 entries; the package is bounded4096. Standalone
allocation exists for protocol tests, but the active gateway uses engine-issued
aliases, preserving native TUN domain/UDP restoration. All ledger entries and
engine aliases are checked before health qualifies UP. Real addresses are pinned
to initial resolution; TTL does not release aliases or refresh their real targets.

Router backup rules are immutable and enabled in `mc-dynamic-backup`. The existing
native watchdog switches one scoped jump instead of modifying each mapping. The
jump is disabled during healthy PROXY and enabled during native DIRECT fallback.
Map publication never changes that switch. The previous static fallback is disabled.
See [ADR-0011](../adr/0011-dynamic-dns-publication.md) for semantics and limitations.

## Native result

The final full E2E run passed, including retries recorded below:

| Experiment | Actual observation |
| --- | --- |
| selected.test | Allocator198.18.0.2; verified router map to10.77.0.20 before positive reply |
| second.test | Allocator198.18.0.3; distinct verified map to the shared real target |
| Break gateway-to-REST TCP transport before third publication | Client DNS error, no address, router still has only two maps |
| Restore transport | third.test publishes198.18.0.4 after verification; three maps present |
| Healthy saved aliases | All three: TCP, UDP echo and verified HTTP/3; HTTP targets see proxy10.77.0.10 |
| Stop whole container | Native DOWN observed4.233s from polling start; all three saved aliases work DIRECT |
| Restart whole container | Native UP observed6.909s from polling start; saved aliases work PROXY again |
| Query domains after restart | All three aliases unchanged; private ledger retains three ready records |
| Unselected traffic | Native DIRECT target peer10.77.0.1 |

Cached tests use literal saved IPs for TCP/UDP and original domain names for TLS
over HTTP/3; no fresh DNS resolution can hide a broken cached alias. The UDP echo
does not report its peer; captures contain native UDP9000 and markers inside VLESS
TCP8443. TCP/HTTP3 DIRECT targets report10.77.0.1. New connections are tested;
uninterrupted survival or automatic migration of old conntrack sessions is not.

The transport failure uses an exact temporary input reject for172.30.0.2->172.30.0.1
TCP80. Host management remains available and the rule is removed in `finally`.
Changing service access lists alone left existing HTTP keep-alive connections
working; that preliminary experiment was not accepted as a control-link outage.
Captured client-facing UDP DNS responses confirm RCODE2/SERVFAIL and zero answers,
not merely an application error string.

## Transients and practical limits

The final run needed three publication attempts for second.test: two DNS errors
with no resolved address, then success. selected.test and third.test after recovery
succeeded on their first recorded attempts. The E2E runner preserves all attempts;
it retries only DNS failures without an address, never broken traffic to an issued
alias. Transient cause is not fully isolated, so cold-DNS availability bounds remain
open. Single-run transition times include polling and1s settling allowance; they
are not outage maxima or first-client-success bounds.

A preliminary full-snapshot implementation also had a first HTTP/3 timeout; a
following request succeeded. Map verification was then narrowed from five REST
collections to NAT alone. This removes unrelated reads and reduces load on this
free-license/emulated lab. The final complete replay had no HTTP/3 failures.
This is not proof of the transient's exact cause or hardware performance.

The tested final archive and a reproducible rebuild have SHA256:
`e3e6aad14b0959c6a8a1e29c27902ef0a3d17e9d75fd16866c240325b1027e1e`.
It was imported into a fresh root with privileged=no and user0:0. Earlier roots
are preserved as separate stopped experimental generations. Fixture resets removed
only dynamic lab maps while steering was stopped; no production state was involved.

After restart, an administrator read the container ledger and permissions directly:
three ready domain/alias/real records, known fixture TTL5s, directory0700/file0600.
No LAN-accessible ledger inspection endpoint was added. Router map counters and
private metadata snapshots are committed as small sanitized evidence.

## Verification and evidence

`make check`, `make quic-test` and `make cross-build` pass. Publication race tests
exercise blocked verification, write/readback failures, lost replies, pending restart,
immutable aliases, capacity, concurrency, canceled requests, corrupt journals and
uncertain fsync. DNS tests exercise UDP/TCP, mismatched IDs/questions/receipt mappings,
selected AAAA suppression and alias leaks through unselected additional records.
Codec fuzzing completed214446 executions during this stage. Router adapter tests
cover exact selectors, immutable target conflicts and rejection of broad chain rules.
Implementation and reproduction tools are committed locally as `35b009b`.

[Native results and witnesses](phase-3-evidence/) include positive/negative client
outcomes and router state. Capture hashes refer to ignored local PCAP files; session
captures include preliminary and final runs, not exclusively the passing replay.
The proxy and target still share a server VM, so their internal delivery is not
visible on Ethernet. Captures are endpoint/DNS witnesses, not packet-loss proofs.
[Lab guide](../lab.md#phase-3-dynamic-publication-gate) documents reproduction.
Temporary VMs and services were shut down; native fallback was enabled first.

## Next gate

This is a dynamic publication foundation for three exact pinned IPv4 domains,
not a full arbitrary-domain fail-open product. Next work must define safe endpoint
churn and alias/cache lifecycle: real-address TTL/CNAME/multiple-A policy, engine
cache replacement/wrap, ledger/router identity, bounded capacity and restart
reconciliation. The prototype does not reclaim aliases or follow changing real IPs.
New-domain publication refusal cannot by itself prevent the engine from reusing an
old alias for already cached traffic; engine lifecycle must enforce that separately.

Early boot/power-loss persistence, existing conntrack handoff, IPv6, device/release
coverage, production TLS/credentials and ordered placement also remain open.
The lab resolver uses its controlled upstream's known5s TTL; production authoritative
TTL/CNAME processing is absent. No subscription manager, auth API, UI or release App
was activated. User-provided servers/subscriptions are not needed for this local
protocol stage; later interoperability and hardware acceptance will benefit from them.
