# RC source-distribution audit

Date: 2026-10-07. Status: **local candidate; binary distribution blocked**.
This is a component/source availability record, not a general legal opinion.
It implements the existing [distribution gate](license-audit.md#distribution-gate).

The accepted OCI images remain unchanged. Their controller source is reproduced
byte-for-byte from the RC source snapshot. Their engine is the official pinned
sing-box 1.14.2 musl binary, not an independently rebuilt minimal feature set.
The CycloneDX inventory is extracted from actual layers and Go build information;
it must not be described as full license clearance or corresponding source.

| Component | Available evidence | Open distribution material |
| --- | --- | --- |
| MikroCentauri | Committed source archive, MIT license, image/build scripts, Go 1.27.1 pin, exact controller reproduction | No third-party controller Go modules; toolchain/source notices still part of distribution review |
| Embedded UI | Svelte 5.57.1 runtime/Vite 8.3.3 helper notices, npm lock, generated bundle in source | Full per-component notice review; build-only npm packages are not claimed as shipped runtimes |
| sing-box | Binary hashes, GPL-3.0-or-later license, exact source revision `af6e64c3b69e6132ebaee0e1a3d24e93903f6709`, actual build tags and dependency module checksums | Exact engine source, patches, build instructions and complete transitive/native source closure |
| Native engine dependencies | Actual `CGO_ENABLED=1`, Cronet platform blob modules, OpenVPN/OpenConnect/cloudflared module references in SBOM | Sources and build materials behind prebuilt libraries, dependency copyright/license review; module archives alone may contain binaries |
| Alpine 3.24.2 rootfs | Installed APK names/versions/origins/aports commits and declared licenses from both actual platform layers | Exact corresponding sources, APKBUILD recipes, patches and build materials for GPL packages; applicable notices for other OS components |
| RouterOS/CHR | Local user-provided proprietary lab input | Never redistribute with MikroCentauri |

The observed sing-box tags include `with_naive_outbound`, `with_openvpn`,
`with_openconnect`, `with_cloudflared`, `with_tailscale` and other features beyond
the MVP parser. Disabling a feature in configuration does not remove its compiled
code or change the actual image inventory. The Cronet native modules are pinned
to commit `c10c03c318db` by binary build metadata; the Go wrapper is pinned to
`0d28acc44093`. Treat these as observed module refs, not evidence of complete
Chromium/Cronet preferred-form source. Go dependency licenses left unassessed
are explicit SBOM properties, not silently assigned MIT.

Before binary publication, collect and verify the immutable source/build closure
for every shipped component, retain notices and the archive SHA256 inventory,
and establish the required source availability mechanism. The relevant license
defines corresponding source to include material needed to generate/install/run
and modify the covered work, including controlling scripts; see
[GPLv3 sections 1 and 6](https://www.gnu.org/licenses/gpl-3.0.html).
A sing-box tag archive or an upstream moving link alone does not establish this
release's closure. Do not mark `distribution.ready=true` to bypass the gate.

An alternative is a smaller locally rebuilt engine with an audited feature/source
set and OS packaging. That produces a different image and requires new exact-image
native acceptance; it cannot inherit this RC's digests or Phase 7 run.
