# Product roadmap and engineering milestones

The canonical roadmap is Phase 0–8 in section 62 of
numbers after Phase 1 label additional engineering milestones; they do not mean
that the corresponding product phase is complete. In particular, engineering
Phase 8 activation/recovery is not product Phase 8 release candidate.

| Product phase | Scope | Current status |
| --- | --- | --- |
| 0 | Research | Research recorded for the pinned lab architecture; refresh before a release |
| 1 | Dataplane laboratory | Bounded CHR TCP/UDP/HTTP3 proof completed; device/version coverage remains limited |
| 2 | RouterOS Controller | Complete for CHR 7.24.5 x86_64: HTTPS discovery, desired model/planner, active/staged apply, placement-preserving rollback, reconcile/verify/cleanup, exact ownership and generated native Netwatch/startup guard; wider release/device acceptance belongs to hardening |
| 3 | sing-box Core | Complete for pinned sing-box 1.14.2 / CHR 7.24.5 x86_64: imports/subscription LKG, groups/health/fallback, ordered rules/services/verified SRS, modern WireGuard, DNS/FakeIP, validator/supervisor and coordinated native activation/recovery; broader device/release acceptance remains in later phases |
| 4 | Backend/API | Complete for the pinned CHR profile: TLS/authenticated typed v1 API, durable drafts and verified single-use plans, production native owner, public policy/subscription workflows, safe application backup/restore, bounded logs and diagnostics; native TCP/UDP/HTTP3, SIGKILL recovery and exact-run packet evidence accepted |
| 5 | Web UI | Complete for the accepted backend profile: embedded TypeScript/Svelte SPA, ten pages, setup review, CAS drafts/reviewed plans, subscriptions and durable schedule, DHCP/source policies, fixed diagnostics and isolated real sing-box node samples, backup/restore; Chromium/WebKit HTTPS browser contracts accepted; Firefox launch on this host and wider browser/device matrix remain hardening |
| 6 | RouterOS App | In progress: multiarch packaging, private launcher, explicit mapped HTTPS origin, native Chromium login and persistent state across App restarts, read-only stopped installation review; automatic LAN topology, native privilege/kernel admission and immutable-image update/rollback remain open |
| 7 | Hardening | Selected failure, boot, source-policy and FastTrack experiments exist; complete security/device acceptance remains open |
| 8 | Release candidate | Not started: release images, upgrade/rollback acceptance, SBOM and complete E2E delivery remain open |

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
against that backend boundary. Phase 6 RouterOS App is now in progress.
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
Full product installation and update acceptance remain open.

[Phase 6 management and installation review](../reports/product-phase-6-management-install-review.md)
records explicit HTTPS origin handling, read-only staging contracts, native browser
and restart evidence, and the unresolved App command parser/update gate.
