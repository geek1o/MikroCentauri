# MikroCentauri

RouterOS-native selective routing application. **Current stage: research and
first dataplane spike, not a functional MVP.** RouterOS remains the main router;
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
  TUN creation with privileged=no.
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
Full-gateway and Socksify are configuration/experiment candidates, not completed modes.

## Remaining gates

No working RouterOS transparent packet path or fail-open is claimed. See
[phase report](docs/reports/phase-0-1.md), [dataplane ADR](docs/adr/0001-dataplane.md)
and [lab guide](docs/lab.md). Cached FakeIP does not become a public address after
container failure; that is an explicit architectural acceptance issue.

No full subscription/group/rule manager, supervisor/LKG lifecycle, auth API, UI or
release image yet. Full frontend work starts only after dataplane acceptance.
Production packaging is a placeholder, not an installation-ready App.

replaces its temporary name. Source is independently written under MIT; sing-box
binary distribution has separate GPL/source obligations in [notices](THIRD_PARTY_NOTICES.md).
All changes are committed locally; no remote publication.
