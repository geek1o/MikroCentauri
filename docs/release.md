# MikroCentauri v0.1.0-rc.1 — local release candidate

Product Phase 8 assembles a local RC for the exact Phase 7 accepted image.
Its scope is CHR RouterOS 7.24.5 x86_64, sing-box 1.14.2 and the synthetic
operator profile. It is not a generally qualified hardware release. The
[E2E report](reports/product-phase-8-e2e.md) records image identity, installation,
upgrade/rollback, browser and packet evidence with their individual boundaries.

## Build and verify

Commit source/documentation first and retain the exact accepted image directory
`.cache/app-image-phase7-complete`. Then:

```sh
make release-candidate
make release-candidate-check
cd .cache/releases/v0.1.0-rc.1
shasum -a 256 -c SHA256SUMS
```

An existing output directory is refused. To repeat a build use a new directory:
`make release-candidate RC_DIRECTORY=.cache/releases/rc-repeat`.
The RC assembler reproduces both controller binaries from the current committed
source and requires byte equality with the admitted images. A changed controller
is refused; rebuild and qualify that new image before issuing another candidate.
The release does not rebuild/retag the accepted image. Import archive metadata
retains the original local `mikrocentauri:phase6-<arch>` labels; SHA256/config
identity, rather than these historical tags, selects the accepted bytes.

The output contains:

| Artifact | Purpose |
| --- | --- |
| `images/oci/` | Exact two-platform OCI layout |
| `mikrocentauri-v0.1.0-rc.1-oci.tar.gz` | Deterministic transport of that same OCI graph |
| `images/mikrocentauri-amd64.tar`, `images/mikrocentauri-arm64.tar` | Original verified RouterOS container-import archives |
| `images/build.json` | Image index/manifests, binaries and input hashes |
| `release.json` | Source commit/tree, reproduction proof, qualified scope and distribution gate |
| `sbom.cdx.json` | CycloneDX 1.6 inventory from the shipped bytes |
| `mikrocentauri-v0.1.0-rc.1-source.tar.gz` | Committed MikroCentauri source and build scripts; excludes local/private inputs |
| `docs/`, `evidence/`, `licenses/` | Operational guides, retained acceptance and notices |
| `SHA256SUMS` | SHA256 of every payload file; extra/missing/modified files are rejected |

Checksums provide integrity, not publisher authentication. No signature or
registry upload is implied. RouterOS images, raw packet captures, deployment
credentials, TLS keys and installation state are excluded. The public test
certificate/key in the application source is an explicitly disposable fixture.

## Installation and operations

Follow [installation](install.md), [upgrade](upgrade.md), [rollback](rollback.md)
and [known limitations](known-limitations.md). Bootstrap/profile/TLS and native
privileges require the explicit operator procedure. The setup UI reviews an
existing installation; it does not provision a router automatically. For local
archive admission use the stopped import procedure documented in the accepted
[App import observations](research/product-phase-6-app-import.md); a registry
catalog cannot pull a local archive. Existing manifest/catalog templates retain
their invalid placeholder until actual publication has been verified.

## Distribution status

The candidate is **local only**. Complete corresponding source/build closure
for shipped GPL/native components and transitive license assessment remain open;
see [the source-distribution audit](legal/rc-source-distribution.md).
The MikroCentauri source archive is not complete corresponding source for the
third-party engine/OS. `--verify --distribution` explicitly rejects this RC.
No GitHub binary release, GHCR image or catalog URL has been published.

The current GitHub CLI token supports repository operations but lacks
`write:packages`; a future GHCR publisher also needs package upload permission.
Permission alone does not close the source/license gate. After both are closed,
verify uploaded manifests/configs/layers against the retained OCI graph, render
the catalog with the actual immutable index and verify native pull/install.
Publishing a tag without these checks does not qualify a new image/device.
