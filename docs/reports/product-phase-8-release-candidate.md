# Product Phase 8 — local release candidate delivery

Date: 2026-10-07. Version: **v0.1.0-rc.1**.
The local RC deliverables are assembled and verified. Binary distribution is
**not complete**: third-party corresponding-source/native build closure and
license assessment remain blocking gates. No registry image, catalog URL or
GitHub binary release is claimed.

## Delivered artifacts

| Original Phase 8 deliverable | Result |
| --- | --- |
| E2E test report | [Scoped E2E matrix](product-phase-8-e2e.md), bound to exact accepted Phase 7 run `1791398213085080000`; no new native execution during packaging |
| Install docs | [Protected installation](../install.md), stopped review, TLS/native privileges, operator boot setup |
| Upgrade docs | [Stopped image replacement](../upgrade.md), complete private snapshot, restore/hash/mode checks and fresh review |
| Rollback docs | [Exact previous image and snapshot recovery](../rollback.md), fresh admission and reviewed boot identity |
| Known limitations | [RC limits](../known-limitations.md), including strict DNS TTL/SERVFAIL, literal IPv6 bypass, browser/hardware scope and resource-smoke duration |
| Release images | Exact accepted amd64/arm64 OCI graph and original import archives in `.cache/releases/v0.1.0-rc.1`; local only |
| Checksums/SBOM | SHA256 for 310 payload files; CycloneDX 1.6 inventory with 395 components, observed Go/APK metadata and explicit unassessed licenses |

The [local RC guide](../release.md) describes construction, verification and
operations. The immutable source snapshot is commit
`9ace276a66e705a08231c179ed3e1fbb7726cba7`, tree
`b5fa3c5f80a6f709a223a080ddaeb869cb1bf3c3`. This report and retained artifact
metadata are subsequent Git evidence; they do not change the delivered bytes.

## Verification

The assembler rebuilds both controllers from that source and requires byte
equality against their accepted image binaries. Both match. It copies only the
six blobs reachable from the admitted two-platform OCI index, excluding stale
unreferenced cache images. The tar transport is independently compared to that
OCI graph. Original Docker archive SHA256 values are unchanged.

Fourteen regressions pass: five RC integrity tests, four SBOM tests and five
image tests. They cover modified/deleted/extra payload rejection, traversal and
symlink denial, deterministic tar metadata, unreferenced image exclusion,
corrupted descriptors, actual image inventory, native Go modules/replacements,
stale embedded UI versions and renderer/image safety. All 310 SHA256 entries
pass. The actual SBOM validates against the official CycloneDX 1.6 JSON schema.
`--verify --distribution` exits nonzero as expected; a local inventory cannot
authorize redistribution by itself.

The Phase 7 full Go race/vet/frontend/cross-build/browser/packet evidence is
retained and hash-verified, not represented as rerun here. This phase changes
packaging scripts/docs only; exact controller reproduction binds it to that
earlier implementation. No physical arm64 or RouterOS 7.22 acceptance is added.

| Local artifact | SHA256 |
| --- | --- |
| OCI transport, 77,215,852 bytes | `9d408faab08342b14cf29088fb09dd235492272399beef50cb589d326d9b13e3` |
| Source archive, 1,350,092 bytes | `22e2b0d2c7172482e314f65e378475547a0c4c69d662ca21480ad60e07b9cd8c` |
| amd64 import, 111,124,480 bytes | `651c3d93841ab8ca95a1ef14247eafd24e5936814366f4eb8b37ff4bb9d539af` |
| arm64 import, 104,611,840 bytes | `0e0d23d8d74602867e15c52d660d9fc93671a92f7091b698509ece87c15f8f86` |
| SBOM, 428,028 bytes | `8c690968ad9006cc210299c3f46298492c8c0db5ed8c8a24958d04058b29f0d0` |

Image index remains
`sha256:0ae1b54998cf60e48deec5b766a4c20d711b6f5c8db907b492e0af47f8a7a24f`.
Hashes identify local bytes; no publisher signature is implied. The candidate
contains no RouterOS disk, raw packet capture or private deployment state.

## Retained evidence and open publication gates

[Validation](evidence/phase-8-release/validation.json),
[release manifest](evidence/phase-8-release/release.json),
[checksums](evidence/phase-8-release/SHA256SUMS),
[SBOM](evidence/phase-8-release/sbom.cdx.json), build/verify/checksum/regression
logs and the expected distribution rejection are retained under
`docs/reports/evidence/phase-8-release`, with a separate SHA256 index.
Large image/source payloads remain in ignored local cache, reproducible from the
recorded committed source and accepted image inputs.

The [source-distribution audit](../legal/rc-source-distribution.md) identifies
the concrete blocker: official sing-box includes CGO and prebuilt Cronet/native
dependencies; its tag source alone is not established complete corresponding
source. Alpine GPL package source/build material and transitive license review
also remain open. A smaller audited engine rebuild would change image identity
and require new exact-image native qualification.

GHCR publication additionally requires package upload credentials: the current
GitHub CLI token lacks `write:packages`. This is not the cause of the source
gate, and supplying it does not close that gate. Once both are resolved, verify
uploaded blobs/manifests/index, render and host the actual immutable catalog,
and accept native registry pull/install. Until then Phase 8 is a **local RC
delivery with distribution pending**, rather than a published release.
