# MikroCentauri

RouterOS-native selective routing application. **Product Phases 2–4 are accepted on the pinned
CHR profile; next is Phase 5 Web UI.** RouterOS remains the main router;
sing-box supplies the selected-traffic gateway. No anti-DPI components.

Target installation: RouterOS >=7.22; linux/arm64 and linux/amd64. Full transparent
capability must be proved on each supported release/device. Pinned researched
baseline: RouterOS 7.24.5 and sing-box 1.14.2. See [baseline](docs/research/version-baseline.md).

## Implemented and verified

- Strict VLESS/TCP URI and milestone configuration parsing, rejecting unsupported options.
- Generalized core v2: four-protocol URI import, private subscription LKG,
  selector/URLTest/fallback policy, ordered rules and DNS generation; see [core guide](docs/core.md).
- Namespace-aware v2 preflight and isolated endpoint health/fallback, composed
  with supervisor/admission/DNS gates; [native core acceptance](docs/reports/product-phase-3-core-completion.md).
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
- Real DNS TTL/CNAME/A-RRset processing and journaled real-target refresh while
  retaining immutable FakeIP bindings; categorized publication diagnostics.
- Finite three-domain engine admission before forwarding, private allocator,
  canonical DNS queries and startup quarantine against missing/foreign caches.
- Proxy canary health with hysteresis, cached-IP failover for one static mapping,
  and durable lab controller recovery after a lost REST reply on actual CHR.
- Bound-domain routing before sniffing; native RAM readiness lease, continuous reboot probes
  and monitor-expiry/invalid-token rejection on CHR.
- Durable append-only Known/Active namespace revisions, retired real DNS and cached
  DIRECT, addition/reactivation and explicit pending recovery on CHR.
- Integrated serialized activation/recovery with automatic pending/committed
  startup proof, both crash windows and native REST outage acceptance on CHR.
- HTTPS controller discovery, active/staged apply, exact repeated apply, complete
  reconcile/verify/cleanup and placement-preserving rollback on native CHR.
- Generated Netwatch/startup guard with RAM debounce, fail-open, generation/counter
  refusal and reboot recovery; staged/lost-reply acceptance retained.
- Phase-0 research, license inventory, UX specification, nineteen ADRs and a draft `/app` manifest.

The [product roadmap](docs/product/progress.md) has nine phases (0–8).
Historical engineering report numbers differ from the product phases; current
product Phase 2 controller is complete for the pinned CHR profile. Current product
work advances Phase 3 core requirements; installation and release gates remain.

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

## HTTPS staging CLI

The verified mutation baseline is CHR x86_64 RouterOS 7.24.5. Configure the native
`www-ssl` service and a trusted certificate first. Store connection JSON in a
regular 0600 file, with no symlink components in its path:

```json
{"base_url":"https://router.example/rest","username":"controller-user","password":"REPLACE_LOCALLY","ca_file":"/absolute/path/router-ca.pem"}
```

`ca_file` is optional when the certificate chains to a system trust root.
Credentials remain in this local file; TLS certificate validation is mandatory.

```sh
mikrocentauri router-inspect -router-config /absolute/path/router.json
mikrocentauri router-plan -router-config /absolute/path/router.json -config /absolute/path/app.json -out /absolute/path/plan.json
mikrocentauri router-stage -router-config /absolute/path/router.json -plan /absolute/path/plan.json -journal /absolute/path/journal
mikrocentauri router-reconcile -router-config /absolute/path/router.json -plan /absolute/path/plan.json -journal /absolute/path/journal
mikrocentauri router-recover -router-config /absolute/path/router.json -journal /absolute/path/journal
```

Review the plan before staging. `router-stage` applies its exact preconditions;
`router-reconcile` creates a fresh plan from its complete desired set and can
remove owned disabled objects omitted from that set. All mutations remain
restricted to explicitly disabled owned objects. See the
[controller acceptance report](docs/reports/product-phase-2-staged-controller.md).

Operational active-state commands and generated watchdog setup are described in
the [controller CLI guide](docs/controller.md). The default staged commands above
retain their disabled-object restriction.

## Remaining gates

The [backend/API phase is complete](docs/reports/product-phase-4-api-completion.md):
authenticated HTTPS v1, typed OpenAPI, private drafts and verified apply,
subscription/policy editing, safe application backup/restore and diagnostics.
Production CLI lifecycle passed CHR TCP/UDP/HTTP3 and SIGKILL recovery.

The transparent CHR path and dynamic publication for a bounded IPv4 namespace
are proved for lab cases. Complete FakeIP lifecycle, IPv6, version/device coverage
and installation/release integration remain open. See the
[completed controller phase](docs/reports/product-phase-2-controller-completion.md),
[latest dataplane engineering report](docs/reports/phase-8-activation-recovery.md),
[Phase-7 namespace lifecycle](docs/reports/phase-7-namespace-lifecycle.md),
[Phase-6 boot and binding](docs/reports/phase-6-boot-and-policy.md),
[Phase-5 admission](docs/reports/phase-5-generation-admission.md),
[Phase-4 target refresh](docs/reports/phase-4-target-refresh.md),
[Phase-3 publication](docs/reports/phase-3-publication.md),
[Phase-2 comparison](docs/reports/phase-2-resilience.md),
[publication ADR](docs/adr/0011-dynamic-dns-publication.md) and [lab guide](docs/lab.md).
The [core phase is complete on the pinned profile](docs/reports/product-phase-3-core-completion.md).
Next gates are Web UI, installable RouterOS App and wider boot/device coverage;
publication does not make arbitrary cached aliases safe after ledger loss or reuse.

The core now provides subscription/group/rule management and supervisor/LKG
lifecycle. The backend is connected to that owner; UI and release images remain open.
Production packaging is a placeholder, not an installation-ready App.

replaces its temporary name. Source is independently written under MIT; sing-box
binary distribution has separate GPL/source obligations in [notices](THIRD_PARTY_NOTICES.md).
Development is recorded in local Git and published to the private
[MicroCentauri repository](https://github.com/geek1o/MikroCentauri).
The product name remains MikroCentauri.

The [backend API guide](docs/api/README.md) covers private configuration workflows
and the production native owner. Offline mode reports readiness false; the
[operator runtime profile](docs/api/runtime.md) connects the accepted CHR dataplane.
