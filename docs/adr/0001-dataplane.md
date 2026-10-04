# ADR-0001: Transparent ingress and selective dataplane

Status: **TUN INGRESS PROVED / COMPLETE FAIL-OPEN ACCEPTANCE OPEN**. Date: 2026-10-04.

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

TESTED: CHR 7.24.5 root/privileged=no TUN ingress, retained client source,
distinct native/proxy egress, selected TCP/UDP/HTTP3, direct-source priority,
fixture full gateway, native TCP Socksify, Netwatch engine/container stop and
recovery, eventual startup-guard repair, and managed FastTrack exclusions.
Real-IP RouterOS FWD/address-list fallback was also compared. Transfer diagnostics
are limited by TCG and the free CHR license. See
[Phase-1 evidence](../reports/phase-1-dataplane.md).

FAILED ACCEPTANCE: cached FakeIP cannot restore native DIRECT while the gateway
is dead; remote VLESS outage is not reflected by local engine/DNS readiness.
NOT ACCEPTED: zero-loss boot ordering, IPv6, full arbitrary device tunnel,
source-domain matrix, full-group health, durable reconciliation and target-version
or ARM64 support. Passing CHR functional cases does not establish those gates.

## Results

Current generated TUN has `auto_route:false`; it deliberately needs explicit Linux
routes/exclusions. `sing-box check` proves schema correctness, not packet delivery.
The CLI's RouterOS hybrid preview contains **disabled** objects only and leaves rule
ordering/watchdog/FastTrack/source steering as gates. Its offline plan uses empty
current state, not live discovery. C emits real DNS, because synthetic addresses
cannot be made usable by a plain SOCKS ingress without domain restoration.

## Decision

Keep A's source-preserving TUN as the proven ingress for further controller work.
Keep B as a bounded benchmark alternative and C as a limited TCP comparison.
D is tested but lacks generic UDP/domain parity (ADR-0009). **Do not accept the
complete fail-open contract or begin UI polish until its remaining gates pass.** Requested
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
