# RouterOS App packaging and installation status

Phase 6 is **complete for CHR RouterOS 7.24.5 x86_64**. Local production images
exist for Linux amd64/arm64 with an OCI index, persistent volume and protected
startup. The pinned operator installation, native packets, restart and image
replacement are accepted. Registry/catalog publication, RouterOS 7.22 and
physical arm64 runtime remain later gates. See [App completion](reports/product-phase-6-app-completion.md)
and [native import observations](research/product-phase-6-app-import.md).

## Build locally

```sh
make app-image
make app-image-check
```

Python and Go run on the development host only. Every downloaded input is verified
against `packaging/image-assets.lock.json`. Outputs in `.cache/app-image`:

- `oci/`: OCI layout, two manifests, compressed layers and index.
- `mikrocentauri-amd64.tar`, `mikrocentauri-arm64.tar`: Docker archives for local
  RouterOS container import.
- `build.json`: exact digests, input pins and measured layer sizes.

The images contain Alpine 3.24.2, Go CLI/embedded UI, sing-box 1.14.2 musl, CA roots
and notices. They contain no Node/Python server, first-boot package installation,
password, TLS key, proxy, RouterOS connection or lab data. Go VCS/time metadata is
excluded for identical repeated builds with the same source/inputs/toolchain.
No registry/catalog is written. Distribution requires the complete license and
corresponding-source inventory; see [notices](../THIRD_PARTY_NOTICES.md).

## Protected bootstrap

Image entrypoint:

```text
/usr/bin/mikrocentauri app-run -config /data/bootstrap/app.json
```

Provision `/data` and `/data/bootstrap` with mode 0700 and private settings/model/key/password
files with mode 0400 or 0600. `/data` must be a persistent volume. Example API-only settings:

```json
{
  "schema_version": 1,
  "listen": "192.168.88.250:8443",
  "public_origin": "https://router.example:8443",
  "allow_clients": ["192.168.88.0/24"],
  "tls_cert": "/data/bootstrap/api.crt",
  "tls_key": "/data/bootstrap/api.key",
  "model": "/data/bootstrap/model.json",
  "password_file": "/data/bootstrap/password"
}
```

These addresses are examples. Use the discovered container IP and reviewed
management CIDRs. `public_origin` is the one URL the browser actually uses,
including its mapped port. Omit it for direct access at the listener's address.
Only HTTPS with no credentials, path, query or fragment is accepted. The
certificate must verify for both the literal listener IP and advertised hostname;
clients must trust its issuer. Existing TLS, exact Host/origin/client-network guards apply.
RouterOS reverse proxy headers do not bypass them. Broad WAN access is excluded.

Supply a valid v2 model with DNS cache beneath `/data`, e.g.
`/data/runtime/cache.db`. First startup creates protected `/data/api` authentication.
Subsequent starts preserve it after the initial password file is removed. Corrupt
state fails without resetting credentials. Drafts/policies/subscriptions/cache and
verified rule sets remain in the volume. Safe application backups omit credentials
and do not replace a protected installation-volume backup.

For native startup provide **both** `router_config` and `runtime_profile`, pointing
to private operator files. Runtime directory stays beneath `/data`; configured
rule-set directory must be `/data/rulesets`. Use the accepted preprovisioned
immutable profile. The launcher verifies the named Linux ingress interface and fixed TUN device,
quarantines its dedicated policy table, then enables IPv4 forwarding if needed.
It refuses foreign priorities/routes and leaves admission to the native owner.
It does not grant RouterOS privilege or infer a LAN profile.
API-only startup is live management with readiness false/503.

## Health and secrets

```text
/usr/bin/mikrocentauri app-health -config /data/bootstrap/app.json
```

This verifies bounded `/api/v1/health/live` JSON over TLS 1.3 with IP/certificate
verification. `tls_ca` optionally selects trust; otherwise `tls_cert` is used.
No redirects, proxy environment or password are used. Liveness is separate from
native Netwatch/readiness and FakeIP publication. SIGTERM uses the existing API
owner's server/runtime/child shutdown.
When `public_origin` is configured, liveness still dials and verifies the private
listener, and sends the advertised Host. `api-serve -public-origin` exposes the
same explicit operator setting.

The isolated 7.24.5 test generates App secret mounts with mode 0444. They are rejected
as private startup inputs. Use protected operator-provisioned files. A generated
secret cannot represent the user's existing RouterOS password. Do not put secrets
in environment, `default-credentials`, manifests, catalogs or image layers.

## Manifest and catalog drafts

`packaging/routeros-app/app.yml` and `catalog.yml` declare one management port,
`state:/data`, arm64/x86 and auto-update disabled. An invalid image placeholder
prevents accidental installation. Once an actual registry/repository is selected
and the image published, render with its locally built index digest:

```text
python3 scripts/render-app.py --image <registry>/<repository>@sha256:<built-index-digest>
```

Tags, mismatched digest or missing architecture fail. This writes local `app.yml`
and YAML-array `catalog.yml` drafts and publishes neither. Documented import is
`/app/add yaml=[/file/get mikrocentauri.yml contents]`; enablement remains behind
prepared-profile/TLS/capability installation acceptance. No catalog URL is hosted.

## Native boundary and later gates

RouterOS 7.24.5 ignored YAML `privileged`/`cap_add` and translated
`restart: unless-stopped` as policy `no`. Use the stopped native privilege review;
YAML alone is insufficient. The accepted launcher/kernel/readiness and image
replacement evidence supersedes the earlier management-only scope. The browser
uses an explicit HTTPS origin and reviewed management access rule; unattended LAN
topology setup, wider device/security/reboot/failure coverage and release publication
remain later gates. Neither RouterOS 7.22 nor physical arm64 runtime is accepted
here. See [App completion](reports/product-phase-6-app-completion.md).

## Stopped installation review

`app-install-plan` and `app-install-verify` are read-only staging commands for
RouterOS 7.24.5 x86_64. Prepare a private 0700 local bundle representing remote
`/data`, with protected settings/model/runtime/router/key inputs. Supply a native
profile and container RouterOS connection together, plus the operator's separate
HTTPS connection file. This validates the intended bundle, not the actual bytes
already on the router's disk.

```text
mikrocentauri app-install-plan \
  -router-config /private/operator-router.json \
  -settings-file /private/bundle/bootstrap/app.json \
  -bundle-directory /private/bundle \
  -app mikrocentauri \
  -image-ref <exact-immutable-remote-image> \
  -image-config-sha256 <OCI-config-digest> \
  -out /private/install-review.json
```

The config digest is the image configuration SHA256, distinct from the manifest
and multi-platform index digest. The plan requires an imported disabled App,
stopped generated container, matching image and certificate check, production
entrypoint without pending App command overrides, static private VETH and exact
persistent `state:/data` mount. It binds inputs and observed identity for ten
minutes. Settings API/DNS/readiness listeners must match the discovered App IP.

Under exclusive administrative control, keep the App disabled and apply only
the exact `/container set *ID privileged=yes` action printed in the review.
Then reread and verify:

```text
mikrocentauri app-install-verify \
  -router-config /private/operator-router.json \
  -settings-file /private/bundle/bootstrap/app.json \
  -bundle-directory /private/bundle \
  -review /private/install-review.json
```

Changed inputs, identities or expired reviews require a new plan. Privilege is
the only permitted identity change. Neither command enables an App, mutates
RouterOS or publishes FakeIP state. A verified privilege flag does not prove
Linux TUN/kernel ingress, installed private files or native runtime readiness.
Both commands explicitly return readiness false.


## First protected volume installation

Keep the generated App disabled and its container stopped. Prepare the reviewed
model, native profile, RouterOS HTTPS connection, TLS certificate/key and initial
password in a local `0700` bundle. The listener and watchdog host must use the
App's discovered IP. RouterOS exposes the actual Linux interface in
`variables-to-use-in-environment` as `[containerInterface]`; it can differ from
the longer RouterOS VETH name. Generate watchdog scripts from the final profile;
text substitution cannot update the encoded watchdog specification.

Transfer a private tar archive over SFTP, outside `state`. Use only regular
`bootstrap/<filename>` entries with mode `0600`: settings `app.json`, `model.json`,
optional paired `runtime.json` and `router.json`, certificate/key/CA inputs and
`password`. Entries are allowlisted; no directories, symlinks, PAX metadata,
duplicates or arbitrary paths are admitted. The archive is bounded to 9 MiB,
contents to 8 MiB and each file to 4 MiB. The settings must use `/data` and the
initial password path `/data/bootstrap/password`.

Run this production command once in the stopped generated container with a
short-lived operator mount for the archive:

```text
/usr/bin/mikrocentauri app-provision -archive /provision/install.tar -data /data
```

The source archive must be `0400` or `0600`. Native RouterOS SFTP on 7.24.5 accepts
permission-preservation flags but uploads files as `0644`. Repair the archive
mode with a bounded, reviewed operator helper before calling the Go provisioner;
the temporary source mount needs write access for that repair. Remove the mount,
helper and command/entrypoint overrides afterward. Do not relax private-file
checks or keep a shell wrapper as the application entrypoint.

The destination must be empty, apart from a sole real empty `bootstrap`
directory prepopulated from the image. Provisioning validates the complete
bundle privately before publication, preserves that directory's inode/owner,
creates `0700` directories and `0600` files, and publishes `app.json` last.
Existing state is never overwritten. This command initializes neither auth nor
readiness. Compare the installed files with the private source, then perform the
stopped installation plan/manual privilege/verify procedure above. Extra mounts
are rejected, even if they appear unrelated to `/data`.

Enable the App only after verification. Require the actual production image
healthcheck and authenticated native readiness, then test selected and direct
traffic. A healthy API alone is insufficient. The default Go launcher establishes inherited `umask0077` (native RouterOS
otherwise starts with `0000`), initializes auth only after kernel preparation and starts the existing runtime owner; shutdown
closes that owner before restoring initially disabled forwarding.

## Protected image replacement and rollback

On the pinned native release, updating YAML or deleting an App can recreate its
container and clear managed `state`. Do not rely on Docker-style volume retention,
manual editing of `container-command-lines`, or `/app/update` as a safe upgrade.
Use exclusive administrative control, stop the App and take a complete protected,
binary-safe SFTP backup outside the managed volume before removing anything.

Recreate the exact same App name using YAML with the intended immutable image.
Wait for the previous VETH to disappear before recreating it, restore snapshot
**contents** into the exact `state` directory and repair private directory/file
modes (`0700`/`0600`) with a bounded stopped-container helper. Clear its overrides
and verify image, IP, interface, mount and privilege before enabling. Keep the
original backup unchanged through the upgrade and rollback. Compare original
file bytes before startup and test authenticated state and cached-alias routing
after startup. See [native update research](research/product-phase-6-app-update.md)
for the observed parser and volume behavior. This is an explicit operator
procedure; automatic updates stay disabled.
