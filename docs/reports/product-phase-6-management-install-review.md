# Product Phase 6: App management and stopped installation review

Date: 2026-10-07. Product Phase 6 remains **in progress**.

The preceding [packaging foundation](product-phase-6-packaging-foundation.md)
records the initial images and App schema observations. This continuation fixes
management access through a mapped address and adds bounded installation staging.
It does not close complete installation, image replacement or native dataplane
admission under the App supervisor.

## Implemented contracts

- `public_origin` / `api-serve -public-origin` declares one actual HTTPS browser
  origin independently of the private listener. Exact Host/Origin, actual socket
  client CIDRs and TLS guards remain enforced; forwarded headers grant no trust.
- Canonicalization handles DNS case, IPv6, explicit/default ports and rejects
  credentials, paths, queries, fragments, wildcards and unspecified listeners.
- Startup checks the current certificate/key and listener/advertised SANs before
  authentication initialization. Internal liveness verifies the private endpoint
  and sends the advertised Host.
- `app-install-plan` hashes protected local intended inputs and the operator
  HTTPS connection/CA, reads four bounded native projections and emits a private
  ten-minute review. It checks disabled App/stopped container, exact image/config
  digest, production entrypoint, pending App command state, VETH and volume.
- `app-install-verify` rejects expiry, changed inputs or changed identity. Only
  the manually applied exact container privilege flag may differ. No automatic
  mutation, enablement, kernel preparation or FakeIP publication is authorized.

These installation CLI contracts passed TLS-backed integration tests with native
response projections. Full native plan/manual-action/verify acceptance on the
CHR clone is still open. Intended local input hashes do not verify installed
remote private bytes. Every staging result reports readiness false.

## Validation

`make check cross-build` passed: Go race suite, vet, integration/smoke tests,
embedded UI type/build and budget checks, and Linux amd64/arm64 builds. Additional
process tests passed for mapped-origin TLS login, liveness and restart/shutdown.
Both candidate OCI layouts passed digest, architecture, archive and secret-free
image verification. Exact build metadata is retained with the evidence.

The isolated App fixture uses synthetic credentials, real production Go/embedded
UI, and an API-only runtime. It bootstraps private files through a temporary shell
helper and executes `app-run`. This is separate from production installation.
The generated IP is checked against the fixture's observed first free VETH slot;
the TCG clone's clock is synchronized to UTC during TLS waits.

Native results are recorded in the accompanying evidence and research report.
The final image index is
`sha256:bf1d5f73cc225d8a4c554bc26d0ae5c66a583702723f53227548d65ee95bda94`.
Two complete builds produced identical metadata, layers and archives. Evidence:
[image build](evidence/phase-6-management/image-build.json),
[native management](evidence/phase-6-management/native-management.json),
[validation](evidence/phase-6-management/validation.json), and
[topology/parser research](../research/product-phase-6-app-management.md).

The final amd64 image passed real TLS 1.3 shell/login/protected API checks,
wrong Host/Origin rejection (403), unauthenticated rejection (401), actual
Chromium navigation/login and two App restarts with byte-identical persistent
auth/model/draft/preferences/cache. A temporary source-restricted WAN DNAT was
required by the slirp fixture; automatic LAN mapping is not admitted. The App
was disabled and the temporary rule removed, preserving its data. The clone VM
was then stopped with its disks retained.

An empty initialized sing-box BoltDB can prove byte retention across restarts;
it cannot prove admitted FakeIP namespace or cache migration. API liveness and
App health cannot prove selective routing: authenticated readiness stays 503.

## Open image replacement gate

On the pinned clone, modifying YAML preserves `container-command-lines`. The
manual REST setter accepts escaped image separators, but the generated container
can receive `remote-image=https` (or `https\`) instead of the full HTTPS digest
reference. Repeated escaping was not accepted as a working update procedure.
These are native 7.24.5 observations, not a claim about all RouterOS versions.

The installer checks pending command state and denies an unexpected override.
The experimental `--image-updates` fixture remains outside acceptance; no A/B/A
image replacement or schema migration is claimed. Its B image changes only OCI
config metadata and preserves the same binary/layer. The official
[App manual](https://manual.mikrotik.com/docs/containers/apps/) describes the
property but does not specify the observed setter/parser behavior; its current
version is not the pinned lab version.

Next gates: supported immutable-image replacement with state preservation;
native stopped installation review/manual privilege verification; protected
remote provisioning; Linux ingress/TUN/kernel preparation and actual native
owner/readiness/packet admission under App supervision; watchdog/reboot behavior;
resource and physical ARM64/version acceptance. No registry/catalog was published.
