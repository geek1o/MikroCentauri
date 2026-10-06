# RouterOS App packaging and installation status

Phase 6 is **in progress**. Local production-code images exist for Linux amd64 and
arm64 with a two-platform OCI index, persistent volume and protected startup
inputs. A published/installable selective-routing release remains open.
Native observations: [App import research](research/product-phase-6-app-import.md).

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
  "allow_clients": ["192.168.88.0/24"],
  "tls_cert": "/data/bootstrap/api.crt",
  "tls_key": "/data/bootstrap/api.key",
  "model": "/data/bootstrap/model.json",
  "password_file": "/data/bootstrap/password"
}
```

These addresses are examples. Use the discovered container IP and reviewed
management CIDRs. The certificate must verify for that literal IP; clients must
trust its issuer. Existing TLS, exact Host/origin/client-network guards apply.
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
immutable profile. The launcher does not create arbitrary networking/privileges.
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

## Remaining gates

End-user provisioning, actual App management access/topology, explicit native
privilege handling, restart/watchdog coordination, production-volume image
upgrade/rollback and resource measurements remain open. On 7.24.5 YAML
`privileged`/`cap_add` were ignored and `restart: unless-stopped` yielded policy
`no`. YAML admission alone is insufficient. Fixture health/secrets/volume tests
are separate from full production installation. Neither 7.22 compatibility nor
physical arm64 runtime is accepted here.
