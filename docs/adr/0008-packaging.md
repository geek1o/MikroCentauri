# ADR-0008: One application container, RouterOS App target

Status: PROPOSED; import/update/privilege mapping NOT RUN.

Target one Go controller + sing-box child process container, static UI later, persistent
volume. RouterOS 7.22 custom app YAML is the installation target; healthcheck needs
7.23 and privileged containers appeared 7.24. Current `/app` schema does not establish
`privileged`/`cap_add` support. Keep minimum floor conditional and probe real devices.

`packaging/routeros-app/app.yml` is intentionally a draft with an invalid image
placeholder. No registry/catalog URLs invented or images published. No complete
application container exists yet; local probe archive is for capability research only.
Need supervised startup, readiness, Netwatch coordination and graceful stop before
production packaging. Track compressed/unpacked size and idle/load RSS once runtime
exists; CLI cross-build size is not an application image or memory benchmark.
