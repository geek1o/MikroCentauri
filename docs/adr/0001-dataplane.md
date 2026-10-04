# ADR-0001: Transparent ingress and selective dataplane

Status: **PROPOSED / BLOCKED ON EXPERIMENTAL ACCEPTANCE**. Date: 2026-10-04.

## Context

RouterOS must keep ordinary DIRECT routing while a container handles selected
resources/devices. VETH is not itself a transparent inbound. RouterOS DNAT does
not transfer its conntrack original-destination metadata into a container socket.
Stock sing-box 1.14.2 has no AF_PACKET inbound. TUN needs a usable device and Linux
network privileges; current RouterOS exposes the node, but release/capability
boundaries and `/app` privilege translation need testing.

## Options considered

A. Hybrid TUN gateway: only FakeIP/manual CIDR/full-proxy sources go to VETH.
B. Full TUN gateway: LAN internet traffic enters sing-box, final DIRECT.
C. RouterOS Socksify → SOCKS inbound: TCP candidate, no UDP/device parity claim.
D. Hybrid real-IP selection using RouterOS DNS FWD/address-list, if FakeIP's crash
semantics cannot meet acceptance; CDN sharing, rule ordering and device policies
must be measured independently.

## Experiments

TESTED: real sing-box check for generated A/B/C config shapes; typed FakeIP A and
managed AAAA suppression over UDP/TCP DNS; process-only selected VLESS TCP versus
unselected DIRECT; mock RouterOS ownership/idempotence/compensation/stale-plan tests;
official CHR 7.24.5 boot/container import and TUN creation with privileged=no on QEMU TCG. See `docs/reports/phase-0-1.md`.

NOT RUN: CHR transparent ingress/source retention, distinct egress identity,
TCP/UDP/QUIC packet capture, FastTrack, watchdog crash/recovery/reboot and benchmarks.
No dataplane is declared experimentally accepted by these process-level results.

## Results

Current generated TUN has `auto_route:false`; it deliberately needs explicit Linux
routes/exclusions. `sing-box check` proves schema correctness, not packet delivery.
The CLI's RouterOS hybrid preview contains **disabled** objects only and leaves rule
ordering/watchdog/FastTrack/source steering as gates. Its offline plan uses empty
current state, not live discovery. C emits real DNS, because synthetic addresses
cannot be made usable by a plain SOCKS ingress without domain restoration.

## Decision

Keep A as the primary hypothesis and implement capability/lab tooling first. Keep
B as a benchmark alternative and C only as a limited comparison. **Do not accept
ADR-0001 or begin UI work until packet-path and failure evidence passes.** Requested
7.22 remains an installation target, not a verified full transparent support floor.

## Consequences

No production activation CLI, finished app image, or feature-complete backend is
shipped in this milestone. Need source-preserving ingress plus outbound-loop
exclusions, Linux forwarding, isolation, native watchdog and IPv6 behavior. Avoid
unconditional privileged mode or modification of user FastTrack rules.

## Fallback design

If TUN cannot run on a target release, report unsupported transparent capability;
prototype C with explicit limitations or investigate D. FakeIP cannot satisfy
instant direct recovery of cached destinations by disabling routes alone. If D is
chosen, add a fresh ADR comparing DNS/CDN/source tradeoffs and packet evidence.
