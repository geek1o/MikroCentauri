# Phase 5 — finite engine generation admission

**Status: bounded startup admission implemented and verified on isolated CHR.
Production FakeIP lifecycle remains OPEN.** RouterOS7.24.5, stock sing-box1.14.2,
Alpine3.24.2, Linux/amd64 gateway, QEMU TCG. No production router, external proxy,
subscription or remote Git publication was used.

The gateway now quarantines forwarded ingress before engine startup. It preloads
the complete three-name namespace, compares every engine alias against durable
publisher reservations before any publication, then verifies all native DIRECT
maps before enabling TUN ingress. Selected DNS cannot allocate before admission;
revocation cancels in-flight requests from the old generation. Configuration and
cache metadata preflight enforce the closed namespace and private engine listeners.
See [ADR-0013](../adr/0013-engine-generation-admission.md).

## Native proof

All three bindings remained selected.test→198.18.0.2, second.test→198.18.0.3 and
third.test→198.18.0.4. Healthy delivery and full-container restart preserved them.
Each saved alias was exercised with new TCP HTTP, UDP echo and certificate-verified
HTTP/3 connections through PROXY, native DIRECT while stopped, and PROXY after
restart. HTTP and HTTP/3 reported proxy peer10.77.0.10 versus direct peer10.77.0.1.
UDP echo proves delivery; its proxy path also requires capture evidence, rather
than treating a successful echo as an egress identity measurement.

Moving the engine cache aside while the child was stopped denied startup without
launching the child. Creating a different cache with the stock engine, allocating
third.test first, then selected.test and second.test, produced .2/.3/.4 in that
foreign order. Admission rejected it as `ledger_mismatch`, killed the child and
retained table100 blackhole. The helper used normal DNS; it did not edit bbolt.
Both faults retained native DIRECT TCP/UDP/HTTP3 for every saved alias.

For each fault the test deliberately ran the owned native UP script while the
engine was unadmitted. A cached TCP request failed at the quarantined ingress;
a selected DNS query returned no address. Restoring the original cache admitted
the original set and restored PROXY delivery. Lower-case, uppercase and mixed-case
terminal-dot DNS queries returned the same second.test alias through UDP workloads.

Curated records: [healthy/restart](phase-5-evidence/healthy.json),
[missing cache](phase-5-evidence/missing.json),
[foreign generation](phase-5-evidence/mismatch.json),
[restoration](phase-5-evidence/recovered.json),
[target-refresh regression](phase-5-evidence/target-refresh-regression.json),
[native state](phase-5-evidence/native-state.json),
[packet summary](phase-5-evidence/capture-summary.json) and
[DNS witnesses](phase-5-evidence/dns-witnesses.json).
Raw PCAP and cache databases remain ignored locally.

The prior TTL/target-churn replay also passed against this generation: the same
alias and NAT object survived .20→.21→.20, upstream SERVFAIL and an actual REST
transport outage with a full-container restart. Startup while management was
blocked ended unadmitted, with no child and a blackhole. After restoring transport
the test explicitly requested fresh admission, which repaired the pending target
and restored PROXY. Automatic controller retry is not implemented by this lab
wrapper; it does not silently expose an engine when management returns.

Captures span preliminary attempts, both generation replays and the regression
attempts. They contain22 cached-UDP marker packets to VLESS TCP8443 and30 to direct
UDP9000 on WAN. These are packet witnesses, not transaction or loss counts. LAN
contains20 zero-answer SERVFAIL responses and16 positive second.test A responses,
all198.18.0.3 with TTL1s,3s or4s. No latency or availability bound is inferred.

## Retained failures and limits

The first container start failed before application execution with RouterOS
`error creating hosts file`. The 2GiB lab volume had about85MB reported free after
image extraction. Removing only the already preserved host archive copy from the
router freed about112MB; the same extracted root then started. An older previously
working root failed identically before that cleanup. This establishes a storage
availability failure on this fixture; the exact RouterOS/ext4 allocation threshold
was not independently measured. [Failure record](phase-5-evidence/startup-failure.txt).

An initial admission attempt rejected a native mapping as unsafe. A subsequent
full-container restart passed with the existing rules; the exact transient cause
remains unresolved. Diagnostics now identify a bounded mismatched schema field
without echoing discovered data. This does not claim to fix cold backend errors.

An initial mixed-case terminal-dot HTTP workload returned the correct FakeIP but
used DIRECT. The route sniff action can replace the engine's recovered domain with
the HTTP Host spelling, which the selected rule does not normalize. The DNS casing
test therefore isolates DNS using UDP; canonical cached HTTP/HTTP3 traffic is
tested separately. [Observed HTTP result](phase-5-evidence/http-host-case-failure.json).
HTTP Host/SNI normalization and policy precedence remain explicit routing gates.

Review also found that the test SOCKS listener could bypass forwarding quarantine.
The final configuration binds it to127.0.0.1:2080, enforced by preflight and a
negative config test. All reported passing scenario records were replayed with
the final gateway binary and configuration.

The first regression replay assumed that a child denied admission would recover
without another startup request. It timed out waiting for the target change.
The next replay queried diagnostics before the bounded startup attempt had ended;
the lab HTTP server was not listening yet. The final scenario waits for that
attempt, verifies rejection, restores transport and explicitly starts admission.
Both earlier results are retained: [old recovery assumption](phase-5-evidence/old-recovery-contract-failure.json)
and [diagnostic timing](phase-5-evidence/startup-diagnostic-timing-failure.json).

`make check` passed repository race tests, vet and real process smoke;
`make quic-test` passed. CLI amd64/arm64 and integrated gateway arm64 cross-builds
passed. Host tests cover complete-set comparison before writes, immutable ledger
bindings, revoked/late operations, strict configuration/cache checks, malformed
allocator replies, canonical questions and denial before internal allocation.

Final archive SHA256:
`0285908384084cc59ed1283423e5e363578229f08f6b21b481dcbf6b4733410a`.
Native gateway binary SHA256:
`feba40e264bb43d7c0a401fb3c26ed291dc2242de0019084d7b89707768e024e`.
The final executable/config were copied into the isolated extracted root to avoid
another full image extraction on the small disk; their hashes were read back.
An independent archive rebuild produced the same SHA256. Implementation is
recorded locally in commit `bf1e745`; evidence is committed separately.

No alias recycling, namespace expansion, arbitrary subscription-domain support,
IPv6, unobserved in-process corruption, earliest boot ordering, production kernel
ownership or established-session continuity is accepted. Native DIRECT relies on
the surviving durable maps; ledger loss does not reconstruct safe aliases. This
lab admission barrier does not activate the production controller, API, UI or App.
Next work is boot ordering and routing-policy proof before production integration.
