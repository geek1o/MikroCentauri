# ADR-0008: One application container, RouterOS App target

Status: IMPLEMENTED for the pinned CHR profile; broader release/device acceptance
remains open. See [Phase 6 completion](../reports/product-phase-6-app-completion.md).

One Go controller/embedded UI plus sing-box child use private persistent `/data`.
The original RouterOS 7.22 App target remains conditional; pinned native proof is
7.24.5 x86_64. Full TUN privileges require explicit discovery, not assumptions.

The local builder verifies Alpine/sing-box pins and creates amd64/arm64 OCI
manifests, an index and Docker archives. No user configuration enters layers.
`app-run` loads protected operator files and bootstraps persistent auth without
resetting credentials. `app-health` verifies HTTPS liveness only. Existing native
readiness, Netwatch and SIGTERM ownership remain authoritative.

The App/catalog drafts contain an invalid registry placeholder. The renderer
requires the exact built multi-platform index digest. No registry/catalog is
published. Actual image construction does not prove hardware/runtime acceptance.

Native 7.24.5 admits unknown YAML fields. Generated containers ignored service
`privileged`/`cap_add`; `restart: unless-stopped` yielded policy `no`. Healthcheck
translation occurs after extraction. Generated secret mounts have mode 0444 and cannot
serve directly as private operator inputs. See [native observations](../research/product-phase-6-app-import.md).

Reviewed topology, exact privilege, protected Go provisioning, native startup/health,
restart and backup-backed image replacement are accepted on the pinned profile.
Unattended installation and wider recovery/device matrices remain gates. Image sizes are measured;
physical arm64 performance is not inferred from cross-builds.
See [packaging/installation](../install.md).
