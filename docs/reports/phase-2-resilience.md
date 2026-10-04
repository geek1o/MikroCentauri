# Phase 2: independent proxy health and recoverable lab mutations

Executed 2026-10-04 UTC / 2026-10-05 Moscow on the isolated Phase-1 CHR lab.
**Lab step complete; production fail-open acceptance remains OPEN.** No production
router, subscription, external server or real credential was used.

## Implemented behavior

The gateway now checks a controlled HTTP canary through its local SOCKS5 listener
and selected VLESS outbound, using a fresh connection for every sample. The canary
must return HTTP200 and target-observed peer10.77.0.10; successful DIRECT egress
cannot qualify it. Readiness also checks TUN, selected DNS and the ingress policy
rule/route. Initial readiness is HTTP503; three consecutive successful samples
permit UP. Two consecutive failed proxy samples cause DOWN. Stopping the child
invalidates readiness immediately and invalidates any in-flight sample. Native
RouterOS Netwatch polls this state every2s and remains independent of the gateway.
Starting the engine returns HTTP202 with `starting:true`, not a readiness promise.

One persisted RouterOS DNAT rule maps saved synthetic198.18.0.2 to real10.77.0.20
during DOWN. The rule applies to LAN192.168.88.0/24 and preserves destination port
and protocol. DOWN disables DNS interception, enables the validated map and removes
FakeIP steering. UP validates the fixture generation, restores gateway steering,
disables backup translation and enables DNS interception. Both paths reuse the
existing native watchdog; no second competing monitor is installed.

The separate lab controller records intent in an fsynced private journal before
mutation, locks its directory across processes, rediscovers after lost responses,
verifies writable state and supports explicit restart recovery. It rejects stale
plans, unsupported writable fields and conflicting managed-field edits. Firewall
deletion is refused until placement-aware recovery exists. The product CLI still
has no activation command. The lab driver targets only localhost disposable CHR
and one disabled route in reserved ownership instance `stage2`.

## Native results

Environment remains CHR7.24.5, sing-box1.14.2 static musl, Alpine3.24.2 and QEMU TCG.
New archive imported into a fresh container root, with privileged=no and user0:0.
The tested image and a subsequent rebuild have identical SHA256:
`635f1235347de5b40120d5f41f99cb22d0909b1de701a6609cc57c176959c9d7`.

| Injection | Observed transition | Result for new connections |
| --- | --- | --- |
| Stop sing-box child only | DOWN2.551s | Saved FakeIP TCP, UDP echo and verified HTTP/3 succeed through DIRECT |
| Start child | UP4.073s | Same cached address returns to VLESS; fresh selected DNS uses FakeIP |
| Stop whole gateway container | DOWN1.780s | Same TCP/UDP/HTTP3 requests succeed without any container code |
| Restart whole container | UP7.980s | Cached address and fresh selected traffic return to VLESS |
| Stop external VLESS service only | local_ready=true, ready=false, failures=2 | Native DOWN; cached and fresh selected clients succeed DIRECT |
| Restore external service | successes=3, ready=true | Native UP; selected traffic returns to VLESS |
| Corrupt mapping to10.77.0.99, attempt UP | Native script rejects map | FakeIP route, DNS interception and malformed fallback all remain disabled |
| Lose successful route PUT reply and disconnect controller | Pending journal; route exists, disabled | Independent new process recovers and removes only that route |
| Route create/update/reapply/delete | 1 / 1 / 0 / 1 verified changes | Desired state verified on CHR; canary absent at end |

TCP and HTTP/3 targets report DIRECT peer10.77.0.1 versus VLESS peer10.77.0.10.
UDP proves payload delivery; the echo endpoint does not report its peer. Captures
show both direct UDP9000 packets and UDP probe markers inside VLESS TCP8443.
Unselected requests remain DIRECT during every failure/recovery. Static filter and
mangle configuration, including order and IDs, remains unchanged; packet counters
and dynamic FastTrack diagnostic rows are excluded from configuration comparison.
The fallback NAT packet counter increases in the native state snapshot.

The four child/container times are single-run observations from injection to
observed native flags/status, including an explicit1s dataplane settling allowance.
They include REST polling overhead and are not maximum outage or first-success
bounds. External-service runs are separate console injection and host observation;
their evidence timer starts at runner invocation, so it cannot measure injection
latency. Existing established sessions were not tested for uninterrupted survival.

Actual REST exposed two issues hidden by decoded-path mocks: percent-encoded `*`
in Go object-ID URLs fails on CHR, and the route `static` flag must never be replayed
as writable configuration. Both are corrected; regression tests cover them.
RouterOS address shape checks also require `:tostr` normalization. Corrected RSC
was transferred and imported natively without errors.

## Reproduction and evidence

[Lab guide](../lab.md#phase-2-proxy-health-static-cached-ip-fallback-and-durable-controller)
describes VM setup and the four explicit E2E runners. Small results and native
state live in [phase-2-evidence](phase-2-evidence/); capture summaries and hashes
refer to ignored local PCAP files. Capture topology limitations remain those of
[Phase 1](phase-1-dataplane.md): proxy and target share a server VM, so their mutual
delivery is not visible on its Ethernet capture. Raw images and packets stay local.

Host verification: `make check`, `make quic-test`, `make cross-build`; native tests
are explicit and separate from host tests. Mock crash/recovery, concurrency,
cancellation, invalid health replies and wrong-egress canary tests also pass.
Implementation and reproducible lab tests are committed locally as `2eac0e0`.
Temporary VMs and capture services were stopped after recording results.

## Next gate

The router mapping is deliberately static and the lab health check requires the
exact FakeIP198.18.0.2. This does not implement arbitrary-domain fail-open. The next
step is a durable DNS publication protocol: resolve real addresses, commit and
verify the exact router mapping, then publish a synthetic answer. It needs alias
lifetime/no-reuse rules, real-address churn, multiple A answers, failure handling,
bounded rule capacity and a complete selector/order schema. See
[ADR-0010](../adr/0010-cached-fakeip-fallback.md).

Also open: early-boot packet ordering, existing conntrack handoff, IPv6, release
and device capabilities, watchdog/controller generation coordination, ordered
firewall activation, authentication, subscription processing and App packaging.
One TCP canary does not prove every UDP destination or every subscription outbound.
Production canary trust/configuration is not implemented. This stage requires no
user-provided server or subscription; those become useful for later interoperability
and hardware acceptance, after the publication protocol is established.
