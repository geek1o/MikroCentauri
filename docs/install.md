# Installation

The tested native profile is CHR RouterOS 7.24.5 x86_64. Linux arm64 packages
are build-checked; physical ARM devices and other RouterOS releases need separate
qualification. Have an independent management path and a complete router backup.
Read the [limitations](limitations.md) and [security guidance](security.md).

## One-time GitHub publication settings

Builds publish through GitHub Actions using its scoped token; no personal registry
password belongs in the repository. Before exposing a catalog, corresponding
source downloads and the GHCR image must both be anonymously accessible.
For GitHub-hosted source assets this requires a public source repository/release.
New GHCR packages start private: open the account's Packages page, select
MikroCentauri, and change package visibility to Public after source access is ready.
In repository Settings → Pages select GitHub Actions as the deployment source.
Rerun the publication workflow after these one-time settings. It verifies public
source availability and exact public image manifests/blobs before deploying a catalog.

## Obtain an App

Use the immutable image reference and generated `catalog.yml`/`app.yml` from a
successful published build. The catalog is a RouterOS App Store YAML array; the
App file describes one application. Do not substitute a mutable image tag for
the recorded `@sha256:` index. Check download checksums against that build's
published manifest. Registry credentials may be required for a private package.

Add a verified, hosted catalog URL to RouterOS's App Store, select MikroCentauri,
and use its first-start management UI to review setup. First start generates a
private TLS identity and copies the RouterOS-provided bootstrap secret into
protected application state. The initial configuration is empty DIRECT with
native forwarding unavailable until its separate profile is provisioned. Trust
the generated certificate only after verifying its identity through your own
management path, then replace it with a trusted certificate for normal use.
For a reviewed local App YAML, import its contents with:

```routeros
/app/add yaml=[/file/get mikrocentauri.yml contents]
```

Catalog publication and image availability must be confirmed by the publisher's
successful build; repository templates alone are not installable artifacts.

## Prepare protected inputs

Mount the persistent `state` volume at `/data`. Use `0700` directories and
`0400`/`0600` private files. The production entrypoint reads:

```text
/usr/bin/mikrocentauri app-run -config /data/bootstrap/app.json
```

Automatic management bootstrap provides initial settings, an empty v2 model,
a generated certificate/key and a private copy of the initial App secret.
For an operator-provisioned installation, a bootstrap bundle contains settings,
a valid v2 model, TLS certificate/key and initial password. Native operation also requires a reviewed runtime profile and
RouterOS HTTPS connection file together. Keep runtime/cache state beneath
`/data`, and rule sets beneath `/data/rulesets`. RouterOS credentials must never
appear in catalogs, image layers, environment defaults or issues.

An API-only settings example is:

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

Replace every example address with the discovered App IP and reviewed management
network. The certificate must verify for the listener IP and advertised hostname;
clients must trust the issuer. API-only startup has native readiness false.
The [native runtime schema](api/runtime.md) describes the required operator profile.
For native startup add `router_config` and `runtime_profile` paths to the private
settings. Provision the topology explicitly; the application does not infer it.

Transfer a private tar containing only regular allowlisted
`bootstrap/<filename>` files. In the stopped generated container, use a temporary
operator mount to run:

```text
/usr/bin/mikrocentauri app-provision -archive /provision/install.tar -data /data
```

Use explicit provisioning on an empty volume before first-start bootstrap; it
never overwrites a bootstrapped or existing installation.

The archive must be `0400`/`0600`; native SFTP on the tested RouterOS release
uploads it as `0644`, requiring a reviewed permission repair first. Provisioning
refuses existing state and publishes settings last. Remove temporary mounts,
helpers and command overrides afterward. Keep the production entrypoint intact.

## Review the stopped installation

Prepare a protected local mirror of the intended `/data` bundle and an operator
RouterOS HTTPS connection file. The local mirror validates intended inputs; it
does not prove the bytes already installed on the router.

```sh
mikrocentauri app-install-plan \
  -router-config /private/operator-router.json \
  -settings-file /private/bundle/bootstrap/app.json \
  -bundle-directory /private/bundle \
  -app mikrocentauri \
  -image-ref REGISTRY/REPOSITORY@sha256:INDEX_DIGEST \
  -image-config-sha256 CONFIG_DIGEST \
  -out /private/install-review.json
```

Keep the App disabled and child stopped. Review the exact observed identity,
IP/interface, persistent mount and digest. Apply only the exact native privilege
action printed by that plan under exclusive administrative control; App YAML
alone does not grant the required privilege. Then re-read:

```sh
mikrocentauri app-install-verify \
  -router-config /private/operator-router.json \
  -settings-file /private/bundle/bootstrap/app.json \
  -bundle-directory /private/bundle \
  -review /private/install-review.json
```

Reviews expire and changed inputs require a new plan. These commands do not
enable the App or prove runtime readiness. Compare installed private bytes with
the source bundle before enabling. Require production TLS liveness,
authenticated native readiness, a fresh dynamic readiness lease, and selected
PROXY/unselected DIRECT packet tests from a LAN client.

## Configure repeated boot

On the tested release an enabled App did not reliably restart after repeated
reboots. Use the separate operator-reviewed helper, bound to the exact App,
generated container name and **OCI config** digest:

```sh
python3 scripts/render-app-boot.py \
  --app mikrocentauri \
  --container EXACT_GENERATED_CONTAINER \
  --config-sha256 CONFIG_DIGEST \
  --out /private/app-boot-scheduler.json
```

Review and install the rendered scheduler manually. It acts only on the enabled
App with the matching container/config; disabled Apps stay disabled. Keep the
independent controlled startup guard enabled: steering stays DIRECT until fresh
admission after boot. Test two actual successive reboots. Disable/update the
operator helper before image replacement, and remove it when uninstalling.

For native App/container behavior consult the official
[MikroTik App documentation](https://manual.mikrotik.com/docs/containers/apps/)
and [container documentation](https://manual.mikrotik.com/docs/containers/).
