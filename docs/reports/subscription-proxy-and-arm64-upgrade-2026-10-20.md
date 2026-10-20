# Subscription proxy transport and protected ARM64 management upgrade

## Outcome

The physical RouterOS 7.23.8 long-term ARM64 management App now runs the source
from public main commit `551076254ed5b7352ab6b9657b9d73fdc83110d8`.
Its verified multi-platform image is
`ghcr.io/geek1o/mikrocentauri@sha256:a7f49be9771453e769258a1efdcee58ead1e5aedec8e8630371932cef9b14b1b`.
The live controller SHA256 matches the ARM64 build manifest. GitHub build and
publication run `39380956846` succeeded; public corresponding sources, anonymous
image access and the exact App Store image reference were verified.

A configured private subscription, previously timing out on the direct network
path, now refreshes through one explicitly selected existing draft proxy. The
production API returned 17 supported nodes from 26 source records, with nine
reported unsupported records and no download failure. The saved source URL and
filters were preserved. Neither the URL, endpoint identities, credentials nor
raw downloaded content are published in this report.

## Transport ownership and isolation

Each source can select direct access or a single enabled endpoint from the
current editable model, including an exactly committed retained draft. The
transport-only API changes that choice without requiring or revealing the URL.
The saved selection is used by manual and unattended refresh. A missing,
disabled or stale selection fails without a direct retry or deleting cached
nodes. Draft/API model snapshots are taken before starting network work; source
startup does not retain the API mutation mutex.

The proxy path uses a bounded temporary sing-box process, a private 0600
configuration and an authenticated loopback listener. It has no TUN, native
owner, live engine cache or selector mutation. All destination addresses are
validated locally and passed as literal CONNECT targets. TLS/HTTP identity
continues to use the source hostname. Existing destination restrictions,
certificate verification, redirect checks, Referer stripping and body bounds
remain in force. Temporary children are stopped and reaped and their files
removed. A download does not become an endpoint health observation or routing
readiness proof.

Before upgrading production, an isolated ARM64 diagnostic used the same process,
tunnel and downloader on the actual router. It successfully parsed the same
26/17/9 counts in a temporary cache, without changing the live registry, cache,
draft or routing. That diagnostic cache and executable were removed afterwards.

## Protected App lifecycle observations

A fresh complete 13-file state archive was downloaded over certificate-verified
RouterOS HTTPS, checked for concurrent file changes, encrypted locally and
successfully decrypted for verification. No plaintext archive was saved locally.
The App was stopped before changing its image.

On this release, editing the custom App YAML removed its managed state and child
container but retained the old `container-command-lines` image selection. An
empty-array reset retained that value, and the generic unset command was refused.
An initially recreated child therefore referenced the previous image despite
updated YAML. It was stopped; that was not accepted as an upgrade.

The disabled custom App was recreated from the complete new immutable YAML with
its existing secret. The resulting name remained `mikrocentauri-2`, the child
remained `app-mikrocentauri-2`, and its management address remained unchanged. The
older builtin catalog entry remained disabled. No cleanup or enablement of that
stale entry was used as rollback.

The full validated archive was restored with a bounded file-based helper before
production startup. Hashes of all 13 original files matched before starting the
normal entrypoint. RouterOS omitted `contents` for the 6786-byte draft in a file
print response; its reported size alone was not accepted as content verification.
A private helper computed full SHA256 values instead. Dot-prefixed REST staging
paths were refused; ordinary temporary names succeeded and were removed.
No absent/unsupported container privilege property was introduced.

After startup, model, authentication, draft, RouterOS connection and TLS file
hashes still matched their original values. The production binary matched the
published ARM64 manifest, the original App password worked, and the preserved
read-only RouterOS connection returned a fresh authenticated resource snapshot.
The proxy transport was then saved through the new API and the source refreshed
successfully. A second complete encrypted archive preserves this accepted state.

## Acceptance and limits

Real Chromium logged into the physical App, observed the saved proxy and 17-node
cache, checked desktop/mobile layouts at widths 1280 and 390, and logged out.
The browser used the previously HTTPS-verified certificate's SPKI pin. Screenshots
were inspected; private images and receipts remain outside Git.

Local verification included the full Go race suite, vet, actual pinned sing-box
TLS/source-download tests, tunnel cancellation/bounds, private-address refusal
before CONNECT, failed-proxy last-known-good retention, API selection/privacy,
committed/stale draft handling and virtual-time unattended selection. Chromium
and WebKit passed the administrative/selection workflow. The WebKit screenshot
CSP rejection remains confined to the existing narrow test-tool exception; the
application CSP was not relaxed. GitHub repeated the build, controller tests,
source closure and image/package/publication checks.

The final App is healthy. Draft revision 3 and the 17-node/14-member group draft
were preserved and not applied. The subscription refresh schedule remains at its
original disabled value of zero. Native runtime remains disconnected and no LAN
steering was activated. The ARM64 packet-path qualification, native profile and
failure/recovery acceptance are still separate unfinished work. These management
and source-download results do not qualify transparent routing or URLTest group
failover on this hardware.
