# Product Phase 6: RouterOS App completion

Date: 2026-10-07. **Complete for CHR RouterOS 7.24.5 x86_64**, with local
amd64/arm64 packaging and an unpublished custom app store draft. This report
supersedes the open Phase 6 installation/kernel/update gates in the earlier
packaging and management reports. The canonical product roadmap has nine phases,
0–8; the next phase is hardening.

## Deliverables and native acceptance

| Phase 6 deliverable | Result |
| --- | --- |
| `app.yml` | One production container, HTTPS management, exact persistent `state:/data`, automatic updates disabled; immutable-image renderer accepted |
| Multiarch image | Checksum-pinned Alpine 3.24.2 / sing-box 1.14.2 musl, amd64/arm64 OCI manifests/index and import archives; embedded Go/UI; no private inputs in layers |
| Persistent volume | Full native startup/restart and real image replacement with an admitted FakeIP generation; original stopped-volume files equal before both replacement starts |
| Secrets | Bounded private Go archive provisioner, private TLS/settings/model/router/password inputs, durable auth; no credentials in manifests/environment/catalog/reports |
| Health | Image-default TLS `app-health` accepted independently from native readiness; production Go entrypoint and native observer lease accepted |
| Custom store draft | Local `app.yml`/YAML-array catalog and digest renderer; no public registry/catalog publication |

The default launcher validates the final model/profile and prepares the dedicated
Linux ingress/TUN namespace before auth initialization. It quarantines its policy
table, refuses foreign kernel state and enables forwarding only after quarantine.
The existing owner supplies core supervision, generation admission, finite native
authority and shutdown. Installation is explicit: discover App IP/Linux interface,
provision a protected bundle, remove temporary mounts/overrides, review the stopped
identity, apply its exact native privilege flag, then verify before enablement.
Every extra mount is refused, including executable shadowing.

Native App startup exposed `umask0000`: sing-box created a `0666` cache, and the
existing engine guard correctly held readiness closed. The Go launcher now sets
inherited `umask0077`; the guard was not relaxed. Fresh installation proved both
controller and engine masks `0077`, production health and native readiness.
See [regression evidence](evidence/phase-6-completion/umask-regression.json).

RouterOS prepopulates the image's empty bootstrap directory into `state`.
`app-provision` accepts only that sole real empty directory or an empty volume,
validates inputs before publication and publishes settings last. Native SFTP
uploads as `0644` despite preservation flags; a bounded stopped operator helper
repairs source/restored modes and is removed from admitted execution.

## Traffic, restart and image replacement

The separate network clone uses actual LAN/server Linux VMs and a real synthetic
VLESS endpoint. The final image started via native App-generated production
defaults, with no shell entrypoint, command override, extra mount or healthcheck
override. Authenticated readiness and the native UP lease were both observed
before packet tests.

Selected and unselected domains passed TCP, UDP echo and HTTP/3. TCP/HTTP3 server
peers distinguish proxy `10.77.0.10` from direct `10.77.0.1`. Stopping App withdrew
the native lease; a previously cached FakeIP worked through DIRECT. Restarting
preserved authentication/namespace and restored proxy routing for that same alias.

The native fixture then replaced the final image with the previous native binary
and restored the final image. Both are genuine different Go binaries/config
manifests. A private complete stopped-volume snapshot was retained unchanged.
After each exact-name App recreate, all original files—including namespace,
publisher, auth and nonempty engine cache—matched before startup. Fresh stopped
installation review/privilege verification preceded each default Go launch.
The same cached alias passed TCP and HTTP/3, UDP returned the same allocation,
auth survived and the actual image-default healthcheck/native readiness passed.
The previous native binary is tested with restored private cache; it is not an
accepted first-install image because it lacks the corrected process mask.

[Native results](evidence/phase-6-completion/native-app.json) and
[exact-run packet witnesses](evidence/phase-6-completion/packet-witnesses.json)
record four distinct UDP markers: selected/direct initial traffic and both native
image transitions. LAN UDP ingress and WAN VLESS/direct forwarding were matched
for each marker. Captures remain local; their SHA256 summaries are recorded.
This is not a packet-loss, throughput, IPv6 or long-duration proof.

A separate management clone additionally passed genuine old-image → new-image →
old-image rollback with byte-equal auth/model/edited draft/preferences/valid empty
BoltDB and real TLS login/UI. Those comparison stages use a disclosed hash + Go
healthcheck fixture; a further protected recreate independently accepted the
image-default healthcheck. Its cache is empty and is not the admitted-alias proof.
See [management update evidence](evidence/phase-6-completion/management-update.json).

Native YAML edits and App removal can clear managed state, including an edit only
to healthcheck metadata. `/app/update` and manual command-string replacement are
not admitted safe upgrades. The accepted operator procedure takes a complete
private stopped-volume backup, recreates the same name from immutable-image YAML,
restores contents/modes and verifies before enabling. Automatic updates remain
disabled. Details: [installation guide](../install.md),
[update research](../research/product-phase-6-app-update.md),
[provisioning/startup ADR](../adr/0022-protected-app-provisioning-and-kernel-startup.md).

## Build and verification

Exact final OCI index:
`sha256:d5a7b8b45efc1763e5139900c6992a0b0e9f38d09cf53cb6cdddf5b7e6ac7999`.

| Architecture | Compressed layer bytes | Uncompressed layer bytes |
| --- | ---: | ---: |
| amd64 | 40,108,628 | 111,104,000 |
| arm64 | 37,310,675 | 104,540,160 |

Use [image build evidence](evidence/phase-6-completion/image-build.json) for exact
platform/binary/input digests and measured sizes. A read-only native sample
recorded controller RSS 16,752 KiB and engine RSS 59,012 KiB (both without swap).
This is one sample during acceptance, not a sustained load or physical-device
capacity benchmark: [resource evidence](evidence/phase-6-completion/resources.json).

`make check cross-build` passed: Go race suite/vet, core and UI validation/build,
packaging checks, clean diff and Linux amd64/arm64 builds. OCI digests, ELF
architectures, archives and absence of image secrets passed independent verification.
Python fixture syntax and exact-run capture verification passed. A second complete
build produced identical full metadata/index/manifests; the tracked profile generator
matched the accepted native model/profile exactly. Validation output
is [retained locally in Git](evidence/phase-6-completion/validation.txt).

## Scope retained for later phases

RouterOS 7.22 and physical arm64 runtime are not inferred from this x86_64 CHR
acceptance or arm64 image construction. Phase 7 owns security/device/browser
coverage, sustained resources, IPv6/FastTrack/reboot/failure matrices. Installation
still needs a reviewed operator topology and protected inputs; mapped management
uses an explicit HTTPS origin and operator access rule. No unattended topology
installation or automatic rollback is claimed. Phase 8 owns release publication,
complete release E2E/SBOM/license-source delivery and the release upgrade matrix.

Both isolated Apps finished disabled; their owned test steering/management rules
were removed and private disks retained. The original CHR disks were not opened
for these tests. Temporary VM/switch/registry shutdown is recorded separately in
cleanup evidence. No real router, subscription or public catalog was changed.
