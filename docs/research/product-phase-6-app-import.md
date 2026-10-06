# Phase 6: App YAML admission on RouterOS 7.24.5

Research and test date: 2026-10-06. The [current Apps manual](https://manual.mikrotik.com/docs/containers/apps/) advertises documentation version 7.26. Its field list is a source for candidate syntax, not proof that all properties execute identically on the project's pinned RouterOS 7.24.5.

## Isolated native fixture

The test runs a stopped-disk clone of the existing CHR 7.24.5 fixture. Both the 128 MiB boot disk and 4 GiB container storage disk were copied with macOS clone-on-write `cp -c` into `.cache/app-schema`. QEMU binds management only to localhost: SSH 22326, HTTP REST 18326, HTTPS 18426; the disconnected LAN socket is 19326. Existing fixture disks, containers and leases are not changed. Native `/system/resource` identifies `7.24.5 (stable)` and a CHR QEMU board.

The reproducible test is [chr_app_schema.py](../../tests/e2e/chr_app_schema.py):

```sh
python3 tests/e2e/chr_app_schema.py --port 18326
```

It admits seven **disabled** App records through native `/rest/app`, with no image pull or start. The image reference deliberately contains an unavailable digest. Each created record is removed by its returned ID; `/app cleanup` is never called. Safe results are saved to `.cache/app-schema/import-results.json`, excluding secrets, YAML and credentials.

## Observed admission and projection

| Probe | HTTP result | Native App projection |
| --- | --- | --- |
| Baseline metadata, environment, named volume, explicit TCP mapping and `restart: unless-stopped` | 201 | Internal default network; `required-mounts=state`; `firewall-redirects=9443:8443:tcp:api-secure` |
| `privileged: true` | 201 | Same disabled App projection as baseline |
| `cap_add: [NET_ADMIN]` | 201 | Same disabled App projection as baseline |
| Deliberately invented service property | 201 | Same disabled App projection as baseline |
| `devices: ["/dev/net/tun:/dev/net/tun"]` | 201 | `required-hw-devices=net/tun:none:default:/dev/net/tun` |
| Container `healthcheck` | 201 | Admitted; no command execution in this disabled probe |
| Named App secret and service secrets list | 201 | Admitted; no mounted-file or lifetime proof in this disabled probe |

The parser accepts an invented service property. Therefore admission **does not prove support** for `privileged`, `cap_add`, healthcheck execution, secret mounting, restart behavior or Linux TUN permissions. A product manifest must use an explicit supported-field allowlist and independently test generated container properties. Do not silently infer NET_ADMIN or broaden privileges from successful YAML import.

The device declaration becomes a required host-device selector. It does not prove Linux `/dev/net/tun` is passed through or can create a TUN interface. Keep the already accepted RouterOS 7.24 native dataplane capability probe and stable prepared profile as installation gates.

## Generated containers and bounded execution

The optional native mode executes these checks with the actual project image:

```sh
python3 tests/e2e/chr_app_schema.py \
  --runtime-oci .cache/app-image/oci \
  --output .cache/app-schema/final-runtime-results.json
```

The test serves only immutable amd64 manifest/config/layer blobs from a loopback TLS registry. CHR reaches the host at its QEMU user-network address `10.0.2.2`. A temporary fixture CA is imported into the cloned router; certificate verification remains enabled on generated containers. The final tested manifest is `sha256:4809dfd1bd991c86f9b55c355b9fbb9d220170663d1dcebd1a8fd2daa951fd27`.

On RouterOS 7.24.5, the current manual's App-level `check-certificate` property is rejected as an unknown parameter. Generated containers nevertheless use `check-certificate=true`. An HTTP registry URL also caused TLS negotiation on this pinned release; the reproducible fixture uses HTTPS rather than weakening certificate verification.

After complete image extraction, `privileged: true` and `cap_add: [NET_ADMIN]` still yield `privileged=false` in generated containers. `restart: unless-stopped` yielded container `restart-policy=no` in the earlier explicit-restart probe. These fields cannot be advertised as effective privilege or native container restart controls on this pinned release. The App's own supervisor is a separate mechanism; its complete failure-restart behavior is not established by this test.

The YAML healthcheck map is translated **after extraction**: `healthcheck-cmd=CMD,true`, interval 2 seconds, timeout 1 second, retries 1. The bounded `/bin/sh` fixture actually becomes `healthy=true` with a good healthcheck status. The image's default healthcheck command remains separately visible, so pre-extraction property inspection alone was insufficient to assess translation.

Named volume `state:/data` is translated into an App-storage directory bind mount. A public test marker written there survived explicit App disable/enable. App secrets are generated as a nonempty 32-byte file mounted under `/run/secrets/admin_password`; actual in-container `stat` observes mode **0444**, UID/GID 0. The test reads only file metadata and never reads, logs or reports secret contents. This file does not satisfy MikroCentauri's strict private-input mode check and must not be passed directly as a controller password file.

The final production image's default `app-run` entrypoint stops with a clear private-settings error when no bootstrap file is supplied. A second App fixture supplies a synthetic model, fresh TLS certificate/key and temporary login password through native config mounts, copies them into a 0700 state/bootstrap directory with 0600 files, and executes the actual `app-run`. Its own `app-health` command successfully verifies API liveness through certificate-validated **TLS 1.3**, including after explicit App disable/enable. This listener is on container loopback only and has no RouterOS connection or runtime profile: it proves production executable/container API startup, not dataplane readiness, external browser access or packet steering.

All runtime probe Apps are disabled afterward; their clone-only data remains for inspection. The isolated QEMU process was then stopped through its monitor, and all owned fixture HTTP/TLS servers and management ports were verified closed. No `/app cleanup` is used. No secret, TLS private key, bearer token or synthetic password is written to the result report.

## Packaging decisions and remaining acceptance

Use documented App metadata, immutable OCI image references, one explicitly named management port and a persistent state mount. Generated App networking must be discovered and checked against the accepted dataplane profile before activation. A disabled imported App is not an installed or ready selective-routing system.

The documentation distinguishes App web reachability from container healthcheck commands. MikroCentauri's application readiness and existing RouterOS Netwatch lease remain the dataplane authority; a visible login page cannot establish proxy readiness. The pinned 7.24.5 fixture accepts and executes the healthcheck command. Healthcheck compatibility with the older 7.22 minimum remains untested.

RouterOS-generated App secrets are suitable only after verifying file content, permissions and persistence. They cannot represent the user's existing RouterOS credential. Never publish a generated secret in `default-credentials`, image layers, environment previews, manifests or reports. A separately provisioned protected credential file remains the supported controller path until the installation flow explicitly handles it.

Still required for full product App installation acceptance: stable generated VETH/IP/network integration with the accepted dataplane, configured external management TLS/browser access, complete proxy readiness and lease lifecycle under App supervision, credential provisioning and rotation, safe image replacement/rollback and persistent state across image replacement. No RouterOS 7.22 execution or physical arm64 hardware acceptance is claimed by this experiment.
