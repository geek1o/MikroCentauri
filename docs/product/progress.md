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
| 3 | sing-box Core | In progress: four-protocol parser, subscription LKG, v2 groups/rules/DNS generator, pinned validation and reusable supervisor; generalized transparent activation, real group health/fallback, complete rule model and WireGuard remain open |
| 4 | Backend/API | Production API, OpenAPI, authentication and backup remain open |
| 5 | Web UI | Not started |
| 6 | RouterOS App | Lab image builders and manifest draft exist; installable application remains open |
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
is accepted on the pinned CHR profile; Phase 3 remains in progress.
A completed controller does not imply an installable application or accepted
release/device matrix.

The completed controller checklist and phase boundaries are documented in
[product Phase 2 acceptance](../reports/product-phase-2-controller-completion.md).
[HTTPS staging acceptance](../reports/product-phase-2-staged-controller.md) is the
earlier intermediate block; its open items are superseded by this completion report.

The first generalized core block is recorded in
[product Phase3 core foundation](../reports/product-phase-3-core-foundation.md).
