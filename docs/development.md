# Development

Use Python 3.12 or newer and the pinned tools in `toolchain.lock.json`. Bootstrap
downloads verified tool archives into ignored `.cache`; Node is development
tooling for the embedded UI, not a deployed server dependency.

```sh
make bootstrap
make check
make cross-build
make app-image
make app-image-check
```

`make check` runs Go race tests/vet, integration checks and embedded UI checks.
Native CHR packet qualification is separate; a successful build does not prove
RouterOS privileges, readiness, or hardware support.

Multi-platform images are built without Docker from checksum-pinned assets in
`packaging/image-assets.lock.json`. Local outputs contain the OCI layout, amd64
and arm64 import archives and `build.json`. Never place private input files,
router backups, VM disks or packet captures in Git or image contexts.

`main` contains public source, packaging, documentation and GitHub automation.
`develop` retains the broader engineering workspace. Keep behavioral changes
small, add regression tests for meaningful failures, and requalify changed
images before relying on previous native results.

Binary distribution requires exact license notices and complete corresponding
source/build material for applicable components. A checksum inventory or SBOM
alone does not satisfy those obligations. See [third-party notices](../THIRD_PARTY_NOTICES.md).
