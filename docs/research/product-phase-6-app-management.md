# Pinned App management and command parser observations

Tested on the preserved isolated CHR 7.24.5 x86_64 clone, 2026-10-07.
The original dataplane lab disks were not used for these experiments.

## Browser topology

The production API must distinguish its private listener from the browser's
advertised HTTPS origin. The accepted fixture uses private VETH port 8443 and
`public_origin=https://127.0.0.1:18443`. QEMU forwards that host port into the clone.
Real TLS verification covers both the VETH IP and loopback advertised address.
Chromium navigates normally, sends its natural Host/Origin, logs in and renders
Overview, Rules and System. Browser tooling permits the disposable self-signed
certificate; the independent Python client verifies it with TLS 1.3.

RouterOS generated a DNAT at the configured router LAN address. QEMU slirp's WAN
peer could not establish this LAN-address connection without a connected LAN
client. The fixture therefore uses an explicit, temporary DNAT from source
10.0.2.2/32 to WAN destination 10.0.2.15:8443 and the actual App IP:8443. This proves
the Go management boundary through real forwarding, not the automatic LAN UI-URL
or a physical production LAN topology. The temporary rule is removed afterward.

The first YAML includes a shell helper to copy synthetic inputs with private
permissions, initialize an empty engine cache, and exec the production launcher.
The first free address is computed from observed VETHs and checked after native
allocation. This clone convention is not an end-user IP provisioning mechanism.
The API-only App remains healthy across two disabled/enabled restarts. Private
auth/model/draft/preferences/cache hashes are compared locally and never exported.
Readiness remains false; the empty cache carries no admitted FakeIP aliases.

## YAML changes and pending commands

The App supervisor retains `container-command-lines` when YAML changes. A blank
cmd on the stopped container alone does not establish the next startup command.
The reviewed default READ representation is the complete string
`core:<generated-container-name>:<exact-image-reference>` with no command suffix.
Installation review requires this known representation and does not retain the
raw command field in its artifact.

The REST setter's apparent representation differs from READ. On disabled fixture
Apps, supplying `core:<HTTPS-image-reference>:<command>` accepts the value, but
startup can create a container with `remote-image=https` and the remaining URL
inside cmd. One level of colon escaping yields the expected READ value, yet
startup repeats the incorrect split. Two levels leave escaped separators in READ
and can generate `remote-image=https\`. Quoting the image and unsetting the
property did not establish a supported replacement procedure. These experiments
used only synthetic fixture Apps and stopped them after each failed admission.

The official [App documentation](https://manual.mikrotik.com/docs/containers/apps/)
describes the string property and automatic topology; it does not specify these
parser details. Its current version is newer than this pinned clone. Do not infer
compatibility or a vendor-wide bug from this bounded observation. A supported
immutable-image update/rollback remains a Phase 6 gate. The optional experimental
image-update fixture is deliberately outside accepted results.

Reproduce the accepted management/restart scope on a separate prepared clone:

```text
python3 tests/e2e/chr_app_install.py \
  --oci .cache/app-image-staging/oci \
  --public-origin https://127.0.0.1:18443 \
  --browser-node <Node-executable>
```

No proxy packets, native owner activation, production provisioning, schema
migration or physical ARM64 admission is implied by this command.
