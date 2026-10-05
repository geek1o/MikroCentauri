# Phase 4 — real-target leases and refresh

**Status: TTL-driven target refresh implemented; isolated CHR proof passed.
Production alias lifecycle remains OPEN.** CHR7.24.5 on QEMU TCG, Alpine3.24.2,
stock sing-box1.14.2, Linux/amd64 gateway. No production router, subscription,
external proxy service or remote Git publication was used.

The domain/FakeIP binding stays immutable. A real IPv4 target now has a separate
wire DNS lease and can change through a durable before/after intent. A bounded
TCP stub resolver reads actual TTLs, follows a complete answer CNAME chain up to
eight links, and selects terminal answer A records only. It takes the minimum
relevant TTL, deduplicates/sorts candidates and rejects malformed, unsuccessful,
incomplete or zero-TTL answers. It is not a DNSSEC validator. The publisher keeps
its existing target while that target remains in the RRset; otherwise it chooses
the smallest usable address. Those CNAME/multiple-A policies have protocol fixture
proof, not native public-DNS deployment proof.

A deadline begins before resolution and is capped at30s. DNS publication returns
only remaining whole seconds after exact RouterOS verification, without extending
freshness for network or persistence latency. Less than one full second remaining
fails closed. Journalv2 records pending target changes before backend mutation,
then commits only after fresh readback. Restart never trusts persisted wall-clock
expiry; v1 journals migrate while retaining every alias reservation.

RouterOS PATCH changes only `to-addresses` on the same owned NAT object. An exact
before or after rule is accepted during recovery; a third target, selector conflict,
missing rule or alias transfer is rejected. REST preflight/readback is not atomic
compare-and-swap: this lab requires one writer. The native watchdog still owns only
its existing scoped jump, DNS interception and FakeIP route. No conntrack flush.
See [ADR-0012](../adr/0012-real-target-refresh.md) for policies and official sources.

## Native outcome

`second.test` retained alias198.18.0.3 throughout the tested sequence. The native
map kept one object ID while its target changed10.77.0.20 →10.77.0.21 →10.77.0.20.
New proxy HTTP connections reported local target10.77.0.21 and proxy peer10.77.0.10.
After a full container stop, saved-alias TCP, UDP echo and TLS-verified HTTP/3
worked through native DIRECT; HTTP/HTTP3 reported peer10.77.0.1. Cached TCP/UDP
requests explicitly skipped DNS, and the HTTP/3 client used the saved alias.

After restart the alias stayed unchanged. A controlled upstream SERVFAIL after
lease expiry made readiness DOWN, preserved the native10.77.0.21 target and still
allowed cached DIRECT TCP/UDP/HTTP3. A forced intercept in the disposable lab
returned no-address SERVFAIL from the gate; diagnostics categorized it as
`publication/resolve_error`. Restoring upstream DNS and management completed
refresh and returned healthy proxy delivery through the same alias.

The extended replay also blocks the gateway's actual REST transport, explicitly
queries the expired domain to stage its target intent, restarts the full container
while that transport remains unavailable, then restores transport. Before recovery
the old10.77.0.21 native map and cached DIRECT connections remain available; after
recovery the same rule targets10.77.0.20. Positive DNS publication is denied during
the blocked update. Host tests separately inspect the persisted pending intent
before mutation and test lost replies and uncertain durable-write failure.

Evidence: [final replay](phase-4-evidence/results.json),
[first passing run](phase-4-evidence/first-passing-results.json),
[native map state](phase-4-evidence/native-map-state.json),
[native journal](phase-4-evidence/native-journal.json),
[DNS witnesses](phase-4-evidence/dns-witnesses.json),
[capture summary](phase-4-evidence/capture-summary.json).
Packet summaries retain public fixture addresses/markers only. Raw PCAP remains
ignored locally. Captures include preliminary failures and both passing runs;
they are not a filtered success-only sample or a latency/loss bound. The combined
LAN witness set contains17 SERVFAIL responses with zero answers and eight positive
A responses forsecond.test; observed alias TTLs were1s,3s and4s, below the5s
upstream fixture TTL. These counts span preliminary failures and both passing runs.

## Failures retained

The first preliminary HTTP/3 request to the changed target timed out because the
server fixture listened only on10.77.0.20:9443. Its bootstrap now listens on all
IPv4 interfaces. The next preliminary DIRECT UDP echo timed out because its
wildcard socket replied with source10.77.0.10 after receiving a request addressed
to10.77.0.21. WAN capture showed10.77.0.1 →10.77.0.21:9000 followed by
10.77.0.10:9000 →10.77.0.1, which cannot match the expected DNAT reply tuple.
The fixture now binds separate echo sockets to both target addresses. These were
lab workload defects; preserved evidence is
[HTTP/3 failure](phase-4-evidence/http3-fixture-failure.txt) and
[UDP failure](phase-4-evidence/udp-fixture-failure.json).

Cold DNS failures are still present. The first passing instrumented run retained
one failed application DNS attempt before the successful initial publication.
A separately observed pre-restart diagnostic snapshot recorded four
`publication/ensure_error` outcomes, including three forsecond.test. This localizes
the failures to backend Ensure, rather than real-DNS parsing or an invalid alias.
It does not establish the exact RouterOS/backend cause: lower-level transport/status
or readback failures share that category. The extended replay also observed one
uncategorized `publication/publisher_error` during a health DNS probe after recovery;
its three application publication checks each succeeded on the first attempt. No cold-DNS availability guarantee is
claimed. [Observed cold diagnostics](phase-4-evidence/cold-diagnostics.json).
Counters are volatile and reset on container restart; aggregate diagnostics are
not correlated to application request IDs.

## Validation and limits

`make check` passed: repository race tests, vet and real sing-box process smoke.
`make quic-test` passed. CLI Linux/amd64 and Linux/arm64 cross-builds passed; the
integrated gateway also built for Linux/arm64. The resolver parser had1,041,777
fuzz executions without a failure in its short fixture run. Host tests cover
lease consumption, stable RRsets, target churn, journal migration, pending intent
recovery before re-resolution, lost replies, malformed DNS and diagnostic privacy.

Implementation is recorded locally in commit `f2fe08e`; evidence and decisions
are committed separately. The workspace was clean before this stage.

Final lab image SHA256:
`93d5541e58a553640cb84d843c24bd77287ba1f837a9e0d5b38b77d021d672c6`.
An independent rebuild produced the same hash. Native gateway binary SHA256:
`e66591053f690702a0e0eaf45839ab0e602a3030d67a9de25c3114913e4d28ce`.
The native journal was v2 with two ready records and no pending transition at
observation, directory0700 and file0600. Its expiry timestamp is diagnostic metadata,
not post-restart freshness authority.

This accepts a bounded real-target refresh mechanism and new-flow fallback cases.
It does not accept alias retirement/recycling, engine cache wrap or replacement,
journal loss, router migration, concurrent writers, established-session continuity,
IPv6, public-DNS/DNSSEC behavior, power-loss/early-boot safety or performance.
QEMU TCG and a free CHR license are unsuitable for throughput claims. Production
TLS/identity, subscriptions, LKG supervisor, API/UI and release activation remain
unfinished. Next gate: engine generation admission and immutable cached-alias
safety across cache replacement, capacity and restart/boot ordering.
