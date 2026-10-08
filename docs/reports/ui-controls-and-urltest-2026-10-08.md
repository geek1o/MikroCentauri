# Control layout and URLTest targets — 2026-10-08

Shared server search, order selection and check actions use equal 40-pixel
controls. Latency dots distinguish pending, fast (<150 ms), moderate (150–399 ms),
slow (>=400 ms) and failed measurements. These are visual thresholds, not a
provider health guarantee. Proxy management checks all active eligible nodes with
at most three workers; failed nodes retain individual results.

The overview contains route summaries linking to section or shared-group
management. Section-owned groups are managed inside Sections rather than being
repeated in the shared selector list. Backup restore controls have their own
spacing below the download action.

Navigation uses an optically adjusted vector mark retaining the complete star,
circular/elliptical orbits and two dots. Cropped padding and stronger strokes
improve small-size legibility. Desktop/mobile marks are 56/48 pixels; login keeps
the original large mark. Browser rendering compares 32, 40, 48 and 56 pixels.

New automatic groups and section-owned selectors offer four bounded HTTPS
URLTest targets: Google, Cloudflare, Apple and Mozilla. The public identifier is
validated and compiled into the actual sing-box outbound URL. Existing private
operator URLs remain private and are retained when no preset is chosen. The
configured target appears beside the automatic policy. Changing the target follows
the existing reviewed draft/plan/apply workflow.

Direct HTTPS HEAD checks from the development host returned 204 for Google and
Cloudflare and 200 for Apple and Mozilla. This does not establish reachability
through each user's provider. Existing per-node manual checks retain their own
fixed/operator probe targets and do not change routing.

Validation and publication results are recorded below after completion.

## Local acceptance

Frontend checking and all 14 unit tests passed; embedded output reproduced.
All 16 browser scenarios passed across Chromium and WebKit, including 1280/390
pixel layout, bulk active-node checks, backup spacing and URLTest target retention.
The complete Go race suite and vet passed before the independent direct-HTTPS
startup change. That change has its own command-package acceptance below.
The persistent preview retained 15 subscription endpoints and one live group.

## Published build

Main commit: 2806a5a405b94fd89b9e3a1e7a32ad2be06b6150.
Build and publish succeeded:
https://github.com/geek1o/MikroCentauri/actions/runs/37777037960

Release:
https://github.com/geek1o/MikroCentauri/releases/tag/build-2806a5a405b94fd89b9e3a1e7a32ad2be06b6150

The live App Store manifest and catalog matched the new immutable image:
ghcr.io/geek1o/mikrocentauri@sha256:4bc02b49bef820eb687778d219718aba95f3ab8d1f0d456c5d7d5ee0b8c77203

The receipt confirms anonymous image/source access. The retrieved manifest
includes direct HTTPS mode and explicit mapped port 8443. The release contains
both architecture import archives, OCI transport, corresponding sources,
checksums, SBOM and provenance. Startup failure visibility was additionally
checked against the built CLI: stdout/stderr include the sanitized reason and
the process retains exit status 1.
