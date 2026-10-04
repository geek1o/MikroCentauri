# License and provenance audit

Date: 2026-10-04 (Europe/Moscow). This is a source/provenance engineering inventory for the initial milestone, not a full transitive dependency audit or a claim of legal clearance. **No reference code or assets have been copied.** All references are pinned; release packaging must revisit the actual dependency graph and binaries shipped.

## Reference sources

| Component / inspected ref | File evidence | Finding | Current decision |
|---|---|---|---|
| Podkop `c0a2736bb95884c19fedf638345ed6148c5fd6af` | [package Makefile](https://github.com/itdoginfo/podkop/blob/c0a2736bb95884c19fedf638345ed6148c5fd6af/podkop/Makefile), root LICENSE | Backend package declares `GPL-2.0-or-later`; root has GPL v2 text | Read as reference; no copying |
| Podkop frontend at same ref | [package metadata](https://github.com/itdoginfo/podkop/blob/c0a2736bb95884c19fedf638345ed6148c5fd6af/fe-app-podkop/package.json) | Declares MIT, but no separate frontend LICENSE found; inherited source/file provenance must be checked | Do not assume entire tree is MIT |
| Tachyon `6c2f9a3a4a9c427c34c3572a82d2292ca5961a85` | [backend Makefile](https://github.com/Dushnilin/tachyon/blob/6c2f9a3a4a9c427c34c3572a82d2292ca5961a85/tachyon/Makefile), root LICENSE | `GPL-2.0-or-later`, GPL v2 license text | No copying; documented ancestry includes Forkop/Steer |
| Tachyon frontend at same ref | [package metadata](https://github.com/Dushnilin/tachyon/blob/6c2f9a3a4a9c427c34c3572a82d2292ca5961a85/fe-app-tachyon/package.json) | Declares MIT; no separate grant file found in frontend | No direct adoption; metadata alone does not settle inherited provenance |
| Forkop `dd483297be0ac4e52bb8f482e2640238b75af532` | [backend Makefile](https://github.com/ushan0v/forkop/blob/dd483297be0ac4e52bb8f482e2640238b75af532/forkop/Makefile), root LICENSE; frontend package metadata | Backend `GPL-2.0-or-later`; frontend metadata MIT | No copying; Podkop ancestry recorded by GitHub |
| Steer `fa24f0588b8375a7a46a927f78151ea6ea7798fa` | [README license section](https://github.com/splify2/steer/blob/fa24f0588b8375a7a46a927f78151ea6ea7798fa/README.md), root LICENSE | README says GPL-3.0 and root contains GPL v3 text; an `or-later` grant has not been established for every source file | Conservatively record GPL-3.0; no copying |
| sing-box v1.14.2 / `af6e64c3b69e6132ebaee0e1a3d24e93903f6709` | [exact LICENSE](https://github.com/SagerNet/sing-box/blob/af6e64c3b69e6132ebaee0e1a3d24e93903f6709/LICENSE) | Explicit GPL-3.0-or-later grant plus derivative naming/association restriction | Run official pinned binary as separate child process; package license/source obligations when distributed |

The sing-box LICENSE adds: “no derivative work may use the name or imply association”. MikroCentauri uses its own product name and factual engine attribution. This observation is not a blanket compatibility conclusion about combining code: do not embed/link GPL engine source into another license without reviewing the resulting combined work. Separately executing a child process does not remove the engine binary's distribution obligations.

## Branding

[Podkop TRADEMARK.md](https://github.com/itdoginfo/podkop/blob/c0a2736bb95884c19fedf638345ed6148c5fd6af/TRADEMARK.md) is a distinct policy dated 2026-05-28. It separates code rights from Podkop names/logos, rejects confusing derivatives/product names, and requires modified distributions to replace user-facing branding. Use factual acknowledgments and links only; do not use Podkop/Tachyon/Forkop/Steer logos or claim official affiliation.

No separate trademark policy file was found in inspected Tachyon, Forkop or Steer trees. Absence of such a file is not permission to use their names/logos or a trademark clearance. MikroCentauri was requested by the user; registration/name-conflict clearance has not been performed. Describe MikroTik/RouterOS compatibility factually without implying MikroTik endorsement.

## Assets, fonts and third-party code

- Forkop's [font license notice](https://github.com/ushan0v/forkop/blob/dd483297be0ac4e52bb8f482e2640238b75af532/luci-app-forkop/htdocs/luci-static/resources/view/forkop/fonts/LICENSE.md) attributes Twemoji Country Flags artwork to Twitter/contributors under CC BY 4.0. This is a separate asset license, not GPL/MIT code. Tachyon contains a same-named WOFF2 file; its attribution needs independent verification before reuse. Neither font is imported.
- Podkop frontend SVG renderers carry `lucide` classes and familiar paths, but the inspected local tree does not contain a separate Lucide notice. Their source/asset license cannot be inferred solely from CSS classes. Use original assets or an explicitly audited icon package when UI begins.
- Steer README identifies libyaml (MIT), wolfSSL (GPL-3.0) and ngtcp2 (MIT with patches), with fetch versions/checksums under `build/`. `src/third_party/libyaml/LICENSE` contains its MIT grant. This is source observation, not a full audit of those upstreams or every bundled file; none is imported into MikroCentauri.
- No third-party frontend is bundled in this milestone. Any future frontend dependency gets a pinned lockfile, full license inventory and asset attribution review.

## Rule sets and service catalogs

Podkop references `itdoginfo/allow-domains`; Tachyon references that source, `MetaCubeX/meta-rules-dat` and `ushan0v/sing-box-supercell-ruleset`. A parent project's GPL grant does not license all remote data. Licensing, upstream aggregation provenance and update behavior of these feeds are **TODO**; the initial milestone uses an original small `.test` domain fixture, not vendored community data.

Before including a service feed: identify exact repository/ref, inspect its data license and upstream sources, retain notices, record URL and immutable hash, bound downloads, validate format, preserve LKG and make provenance visible. Optional remote fetching also needs its terms/provenance reviewed; it is not automatically exempt from rights concerns.

## Distribution gate

1. Keep a component inventory with exact versions, source commits, dependency licenses and asset notices; generate an SBOM from the built image.
2. Include applicable licenses/copyright notices in release artifacts. For shipped GPL binaries, make complete corresponding source, patches and required build scripts available through a license-compliant mechanism; a link to a moving upstream branch alone is not the release source archive.
3. If reference code is later copied, record original file/ref/author, preserve notices and mark modifications; select a compatible license for the actual derived/combined work after per-file review.
4. Keep the application and engine clearly identified as different components. Do not rely on process boundaries as a universal legal exemption.
5. Do not redistribute RouterOS CHR images in Git or container layers. Lab automation accepts the user's official image; RouterOS licensing remains separate.

Current release status: **not a public release**. Reference reuse: **NONE**. Community data/branding reuse: **NONE**. sing-box binary source-distribution/SBOM packaging: required before publishing an image; initial local development does not establish release compliance.
