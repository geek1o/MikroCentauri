# Phase 0 / initial Phase 1 report

Date: 2026-10-04, Europe/Moscow. Repository: MikroCentauri. Status:
**research complete; dataplane spike started; first transparent E2E milestone NOT MET**.

## Completed

Current official RouterOS/sing-box/reference research, exact versions and toolchain
hashes, license/provenance audit, product flow and eight ADRs. Three parallel
research agents worked in separate documents; root integrated conclusions and code.

Core CLI: strict milestone config and VLESS/TCP subset; generator for hybrid/full/
Socksify comparison; pinned binary validation; private atomic candidate output;
RouterOS ownership planner + bounded TLS REST client + lab-only compensating apply;
unit/golden/mock failure injection. Lab: local two-process VLESS/DNS/HTTP smoke,
official CHR QEMU runner and locally built container TUN capability probe.

## Test evidence

| Check | Result | Boundary |
|---|---|---|
| `make test`: Go race + vet | PASS | Config/parser/planner/mock, not live router apply |
| Golden configs ×3 + real sing-box 1.14.2 check | PASS | Schema, not TUN routing |
| Selected exact domain through local VLESS | PASS | Explicit SOCKS process smoke, server logs |
| Nonselected domain DIRECT | PASS | No corresponding VLESS server request; not native RouterOS bypass |
| DNS UDP/TCP: selected A FakeIP | PASS | Real sing-box listener, local resolver |
| Managed AAAA NOERROR/empty; other A real | PASS | No complete IPv6 leak claim |
| Invalid URI preserves previous validated file | PASS | Local candidate lifecycle, no runtime supervisor/LKG |
| Failure injection restores created/updated owned objects | PASS | Mock REST; unknown remote commit remains a production journal gate |
| Stale ownership rejected before mutation | PASS | Mock |
| linux/amd64 + linux/arm64 CLI static cross-build | PASS | No hardware execution or full app image |
| Official CHR 7.24.5 boot/package/device mode | PASS | Isolated QEMU TCG on macOS arm64 |
| Local Docker-save probe import, VETH/bridge, start | PASS | `/container`, not `/app` |
| TUN open + create with root, privileged=no | PASS | Distinct TUN name; capabilities `0000003fffffffff` |
| Full CHR LAN packet path / distinct egress | NOT RUN | Client/proxy VM isolation and ingress routes not yet provisioned |
| UDP/QUIC proxy traffic / FastTrack / loops | NOT RUN | DNS-over-UDP is not proxy-UDP proof |
| Watchdog/fail-open/recovery/reboot/app update | NOT RUN | No production activation or watchdog implemented |
| Performance/image size/idle or load RSS | NOT RUN | CLI sizes are not image/runtime benchmarks |

CLI binaries observed about 4.8 MiB amd64 / 4.5 MiB arm64; this is only stripped
CLI size. No performance, complete image-size or application RSS claims.

## Findings and decision

TUN is feasible at device-creation level on tested CHR7.24.5 without privileged flag.
Do not infer 7.22/hardware compatibility or `/app` privilege translation. Initial
probe EINVAL was an interface-name collision with RouterOS VETH, corrected in code.
Matching NPK must be installed using graceful RouterOS reboot; cold emulator reset
proved insufficient in the first attempt. Both vendor download hashes verified.

FakeIP cached destinations cannot simply fail over to WAN. Readiness/Netwatch alone
is insufficient for instant recovery of cached synthetic destinations. A hybrid
real-IP DNS/address-list alternative is retained for comparison. All activation
objects remain disabled; product CLI does not apply to routers. A/B generated engine
shapes are similar because the meaningful difference is RouterOS ingress selection,
which has not been measured. No frontend started; ADR-0001 remains PROPOSED.

## Known implementation limits

Prototype supports exact domains and a narrow TCP VLESS URI set; other protocols,
subscriptions, groups, rulesets, migrations, semantic engine, supervisor, API/auth,
backup and safe diagnostics are future work. Offline `plan` starts from empty state
and emits only disabled FakeIP route and scoped TCP/UDP DNS NAT. Full-source/manual
CIDR steering, rule placement, FastTrack and native watchdog are not generated.

Lab-only compensation is not a durable transaction. Unknown remote mutation outcomes,
resource-specific writable fields, delete restoration ordering/IDs, concurrency and
applied-state verification remain mandatory before product apply. PlatformAdapter
is currently a declared contract. `/app` manifest uses an intentional image placeholder.

## Next phase

Provision Linux client and isolated VLESS server, establish explicit TUN ingress and
outbound exclusion routes, capture original-source TCP/UDP paths for A/B, compare
C, measure failure envelope including cached FakeIP, and either accept ADR-0001 with
evidence or change the candidate. Then complete controller/supervisor before API/UI.

Lab VM and temporary host HTTP server are stopped at the end of this milestone;
ignored working disks/tool binaries remain for reproducibility. No network/router
outside the disposable local CHR was modified and no remote Git push was performed.
