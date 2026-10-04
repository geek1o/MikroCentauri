# MikroCentauri

RouterOS-native selective routing application. **Current stage: research and
transparent CHR laboratory, not a functional MVP.** RouterOS remains the main router;
sing-box is the proposed selected-traffic gateway. No anti-DPI components.

Target installation: RouterOS >=7.22; linux/arm64 and linux/amd64. Full transparent
capability must be proved on each supported release/device. Latest researched
stable: RouterOS 7.24.5 and sing-box 1.14.2. See [baseline](docs/research/version-baseline.md).

## Implemented and verified

- Strict VLESS/TCP URI and milestone configuration parsing, rejecting unsupported options.
- Version-pinned sing-box generator, three golden fixtures, real `sing-box check`.
- Real local VLESS TCP and DIRECT routing smoke, typed FakeIP DNS over UDP/TCP,
  selected AAAA suppression, invalid-candidate preservation.
- Private validated atomic output; exact RouterOS ownership planner, scoped REST
  client, mock idempotence/compensation/stale-plan tests.
- Native QEMU CHR runner, container probe archive builder, and real CHR 7.24.5
  TUN ingress with privileged=no, retained sources and distinct proxy/DIRECT egress.
- Real CHR selected TCP/UDP/HTTP3, source priority, bounded full-gateway and Socksify
  comparisons, native Netwatch stop/recovery, boot guard and FastTrack exceptions.
- Dynamic DNS publication only after durable reservation and fresh RouterOS map
  verification; three-domain TCP/UDP/HTTP3 cached-address recovery on CHR.
- Proxy canary health with hysteresis, cached-IP failover for one static mapping,
  and durable lab controller recovery after a lost REST reply on actual CHR.
- Phase-0 research, license inventory, UX specification, eight ADRs and a draft `/app` manifest.

## Try the local prototype

Requires Python >=3.12; tools download into ignored `.cache` with pinned SHA-256.

```sh
make bootstrap
make check
make prototype
make cross-build
```

`generate` writes a validated private sing-box candidate; `plan` prints an offline
hybrid preview with **disabled** objects against empty router state. It does not
connect to or mutate your router. Example URI is a disposable lab fixture.
Full-gateway and Socksify have bounded CHR experiments, not production modes.

## Remaining gates

The transparent CHR path and dynamic publication for three pinned IPv4 domains
are proved for lab cases. Complete FakeIP lifecycle, IPv6, version/device coverage
and production controller activation remain open. See [current phase report](docs/reports/phase-3-publication.md),
[Phase-2 comparison](docs/reports/phase-2-resilience.md),
[publication ADR](docs/adr/0011-dynamic-dns-publication.md) and [lab guide](docs/lab.md).
Next gates are endpoint churn/alias lifecycle, early boot and production integration;
publication does not make arbitrary cached aliases safe after ledger loss or reuse.

No full subscription/group/rule manager, supervisor/LKG lifecycle, auth API, UI or
release image yet. Full frontend work starts only after dataplane acceptance.
Production packaging is a placeholder, not an installation-ready App.

replaces its temporary name. Source is independently written under MIT; sing-box
binary distribution has separate GPL/source obligations in [notices](THIRD_PARTY_NOTICES.md).
All changes are committed locally; no remote publication.
