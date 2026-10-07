# Product roadmap and engineering milestones

The roadmap contains nine product phases (0–8). Historical report
numbers after Phase 1 label additional engineering milestones; they do not mean
that the corresponding product phase is complete. In particular, engineering
Phase 8 activation/recovery is not product Phase 8 release candidate.

| Product phase | Scope | Current status |
| --- | --- | --- |
| 0 | Research | Research recorded for the pinned lab architecture; refresh before a release |
| 1 | Dataplane laboratory | Bounded CHR TCP/UDP/HTTP3 proof completed; device/version coverage remains limited |
| 2 | RouterOS Controller | Complete for CHR 7.24.5 x86_64: HTTPS discovery, desired model/planner, active/staged apply, placement-preserving rollback, reconcile/verify/cleanup, exact ownership and generated native Netwatch/startup guard; wider release/device acceptance belongs to release qualification |
| 3 | sing-box Core | Complete for pinned sing-box 1.14.2 / CHR 7.24.5 x86_64: imports/subscription LKG, groups/health/fallback, ordered rules/services/verified SRS, modern WireGuard, DNS/FakeIP, validator/supervisor and coordinated native activation/recovery; broader device/release acceptance remains in later phases |
| 4 | Backend/API | Complete for the pinned CHR profile: TLS/authenticated typed v1 API, durable drafts and verified single-use plans, production native owner, public policy/subscription workflows, safe application backup/restore, bounded logs and diagnostics; native TCP/UDP/HTTP3, SIGKILL recovery and exact-run packet evidence accepted |
| 5 | Web UI | Complete for the accepted backend profile: embedded TypeScript/Svelte SPA, ten pages, setup review, CAS drafts/reviewed plans, subscriptions and durable schedule, DHCP/source policies, fixed diagnostics and isolated real sing-box node samples, backup/restore; Chromium/WebKit HTTPS browser contracts accepted; Firefox launch on this host and wider browser/device matrix remain release qualification |
| 6 | RouterOS App | Complete for CHR 7.24.5 x86_64: amd64/arm64 packaging and custom store draft, protected Go provisioning, explicit HTTPS origin, stopped identity/privilege review, kernel/TUN preparation, production Go startup/default health, TCP/UDP/HTTP3, cached-alias restart and real immutable-image replacement/rollback; reviewed operator topology remains required, wider runtime/release matrix belongs to later phases |
| 7 | Hardening | Complete for CHR 7.24.5 x86_64 / sing-box 1.14.2 and the explicit lab profile: security/SSRF/secret review, immutable client admission, bounded private lease renewal, native FastTrack/IPv6/failure/three-reboot matrix, cached-flow resource smoke, actual image rollback and exact-run packet witnesses; broader hardware/browser/version acceptance remains release qualification |
| 8 | Release candidate | Local RC v0.1.0-rc.1 assembled for the exact Phase 7 accepted image: E2E report, install/upgrade/rollback guides, known limitations, two-platform OCI/import images, checksums and CycloneDX inventory. Binary distribution remains blocked pending complete corresponding-source/native dependency closure and license assessment; registry/catalog publication and wider hardware qualification are not complete |

Engineering milestones already recorded:

| Report number | Engineering scope |
| --- | --- |
| 0 | Research and architecture |
| 1 | Dataplane proof |
| 2 | Resilience and alternative dataplanes |
| 3 | Dynamic FakeIP publication |
| 4 | Real-target refresh |
| 5 | Generation admission |
| 6 | Boot, binding policy and native readiness lease |
| 7 | Append-only namespace and active/retired policies |
| 8 | Integrated policy activation and startup recovery |

Do not use the largest report number as a completion percentage. Product Phase 2
and Phases 3–4 are accepted on the pinned CHR profile. Phase 5 UI is accepted
against that backend boundary. Phase 6 RouterOS App is complete for the pinned profile.
A completed controller does not imply an installable application or accepted
release/device matrix.

The completed controller checklist and phase boundaries are documented in
[product Phase 2 acceptance](../reports/product-phase-2-controller-completion.md).
[HTTPS staging acceptance](../reports/product-phase-2-staged-controller.md) is the
earlier intermediate block; its open items are superseded by this completion report.

The first generalized core block is recorded in
[product Phase3 core foundation](../reports/product-phase-3-core-foundation.md).
The next block connects supervised admission and real endpoint observations:
[Phase3 supervised admission](../reports/product-phase-3-supervised-admission.md).

The completed core checklist, native lifecycle results and packet witnesses are in
[product Phase 3 acceptance](../reports/product-phase-3-core-completion.md).

The first authenticated backend block is documented in
[Phase 4 API foundation](../reports/product-phase-4-api-foundation.md).

[Phase 4 runtime host and resources](../reports/product-phase-4-runtime-resources.md)
records the next backend block and its native deployment boundary.

The completed backend checklist, native CLI results and packet witnesses are in
[product Phase 4 acceptance](../reports/product-phase-4-api-completion.md).
This completion report supersedes the open native/backup boundaries in the
earlier Phase 4 foundation and runtime-resource reports.

The complete UI checklist, browser contracts and build evidence are in
[product Phase 5 acceptance](../reports/product-phase-5-web-ui-completion.md).
Its preprovisioned setup review does not close the Phase 6 installation gate.

[Phase 6 packaging foundation](../reports/product-phase-6-packaging-foundation.md)
records local multi-platform images, protected startup and native App observations.
Its installation/update gates are superseded by the completion report below.

[Phase 6 management and installation review](../reports/product-phase-6-management-install-review.md)
records explicit HTTPS origin handling, read-only staging contracts, native browser
and restart evidence, and the unresolved App command parser/update gate.


[Phase 6 App completion](../reports/product-phase-6-app-completion.md) records
protected first installation, native kernel/default launcher and health admission,
exact-run TCP/UDP/HTTP3, cached-alias restart, genuine image replacement/rollback,
private state equality and complete build/capture validation. Phase 7 hardening completion below supersedes its open native gates;
physical arm64/RouterOS 7.22 and release publication remain separate gates.


[Phase 7 security foundation](../reports/product-phase-7-security-foundation.md)
records reproduced download/control transport defects, targeted fixes and regression
evidence. The completion report below supplies its later native gates; wider device qualification remains separate.

[Phase 7 IPv6 observation](../reports/product-phase-7-ipv6-observation.md)
records GET-only IPv6 metadata, explicit UI limits, native REST schema and missing
FastTrack/route flag handling. Later packet/reboot/failure evidence is in the completion report below.

[Phase 7 native hardening progress](../reports/product-phase-7-native-hardening-progress.md)
records the management review, historical rejected attempts, native matrix and
private lease correction. Its earlier open native/capture gates are superseded below.

[Phase 7 hardening completion](../reports/product-phase-7-hardening-completion.md)
closes the seven original deliverables for the pinned lab profile and supersedes
open gates in the preceding Phase 7 reports.

[Phase 8 E2E report](../reports/product-phase-8-e2e.md) and
[local RC delivery report](../reports/product-phase-8-release-candidate.md)
record the exact accepted images, source reproduction and artifact evidence.
The [local RC guide](../release.md) supplies build/verification commands.
The RC is local only; [source distribution](../legal/rc-source-distribution.md)
remains an explicit publication blocker, not a completed gate.
