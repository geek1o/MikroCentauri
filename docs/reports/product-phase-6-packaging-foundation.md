# Product Phase 6: packaging foundation

Date: 2026-10-06. Status: **in progress**, not a completed installable application.

This block packages the accepted backend/UI and native owner without introducing
user credentials, topology or lab defaults into image layers. Complete installation
and update/rollback remain gates; the canonical roadmap still has nine phases 0–8.

## Built artifacts and startup

The checksum-pinned Docker-free builder produces Alpine 3.24.2/sing-box 1.14.2
musl amd64/arm64 OCI manifests, a multi-platform index and RouterOS Docker archives.
Controller/UI and upstream/license notices are embedded. Separate Node/Python
server runtimes and first-boot package downloads are absent.

| Platform | Compressed layer bytes | Uncompressed layer bytes |
| --- | ---: | ---: |
| amd64 | 40,041,639 | 110,950,400 |
| arm64 | 37,256,064 | 104,407,040 |

Exact index: `sha256:19f5359d28fd1ea8ad92a8cb48483bea55cd4b88e19ba72f32fc29e0483e79b8`.
A second complete build produced the identical index and platform manifests.
These are local image sizes, not RAM or throughput measurements.

`app-run` strictly reads a protected operator settings file, preserves the `/data`
authentication/policy/cache/rule-set volume and initializes the password only once.
Removing the initial password file does not reset existing authentication.
The native profile and RouterOS connection must be provided together; the launcher
does not invent a TLS key, proxy, network, RouterOS password or privileges.

`app-health` verifies TLS 1.3/IP SAN and bounded actual API liveness, rejects
redirects/ambiguous JSON and uses no credentials or proxy environment. Readiness
remains separate. API-only management is live while authenticated readiness is 503.
SIGTERM follows the existing API owner and closes its server/runtime/children.

## Validation

`make check cross-build` passed: Go race/vet, pinned integration smokes, frontend
type/regression/reproducibility checks and Linux amd64/arm64 builds. All CLI race
tests also passed after the launcher was complete. Five packaging regressions cover
deterministic layers, path traversal/overrides, ELF architecture, immutable rendered
digest admission and synchronized catalog draft. Actual image verification checks
the full OCI graph, both Docker archives, binary hashes and secret-free layers.

The real HTTPS process regression starts twice, removes the password file between
starts, verifies unchanged auth, checks liveness 200/readiness 503 and graceful SIGTERM.
This is management process proof, not native packet-path reacceptance.

## RouterOS observations and remaining work

An isolated stopped-disk CHR 7.24.5 clone was used. Native `/app` accepts unknown
service properties; successful YAML admission therefore does not establish support.
Actual extracted containers ignored `privileged`/`cap_add`, while YAML
`restart: unless-stopped` yielded policy `no`. Healthcheck translation appears after
image extraction. A separate bounded shell fixture verifies good health, generated
secret file metadata 0444/root/32 bytes (no value reported), and a `/data` marker
preserved across explicit stop/start. The final image also executes actual
`app-run` using synthetic protected inputs and passes its own TLS 1.3 `app-health`
again after stop/start. This API-only listener is container-loopback-only, without
RouterOS connection/profile or packet steering. These fixture results do not establish
production application readiness or upgrade/rollback preservation.

App/catalog templates deliberately retain an invalid unpublished image reference.
The renderer requires the locally built index digest. No registry/catalog publication
or production-router mutation is implied by this block. Provisioning, actual App
management topology/TLS, explicit native privileges, restart/watchdog coordination,
production-volume image upgrade/rollback and resource measurements remain open.
RouterOS 7.22 compatibility and physical arm64 execution are not accepted here.

Evidence: [build hashes](product-phase-6-evidence/build.json),
[native result](product-phase-6-evidence/native-app.json),
[validation](product-phase-6-evidence/validation.txt),
[isolated fixture cleanup](product-phase-6-evidence/cleanup.json),
[native App research](../research/product-phase-6-app-import.md).
Operation: [installation guide](../install.md),
[ADR-0008](../adr/0008-packaging.md).

All clone-only App probes are disabled, the VM and fixture servers are stopped,
and cloned disks are retained. Original laboratory disks were not modified.
