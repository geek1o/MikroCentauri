# Native backend owner

`api-serve -runtime-profile` composes the authenticated API with one native
`Transition`/`Host`, DNS publication, immutable FakeIP mapping publisher, native
watchdog and current-process canary. The supported runtime profile is pinned to
Linux on CHR RouterOS 7.24.5 x86_64. This guide describes the backend composition;
App installation and the wider device matrix belong to later product phases.
Native acceptance results are in the
[Phase 4 completion report](../reports/product-phase-4-api-completion.md).

## Operator inputs

Use absolute, regular 0600 files for the model, router connection, runtime profile,
TLS private key and initialization password. State directories must be real 0700
directories without symlink components. Keep these inputs outside Git.

The model is the existing schema-v2 core model, with mode `hybrid`. The router
connection uses the controller's `base_url`, `username`, `password` and optional
`ca_file` fields. `base_url` must use HTTPS with verified system or supplied CA
trust. Neither the HTTP API nor native factory offers an insecure TLS override.

The runtime profile is schema 1 and contains:

| Field | Purpose |
| --- | --- |
| `directory` | Persistent, private namespace/publication/process/transition root |
| `dns_listen` | Literal private IPv4 address and port, binding both TCP and UDP |
| `readiness_listen` | Separate private IPv4 HTTP socket for the native observer |
| `observer_client` | Exact router source IPv4 allowed to read readiness |
| `ingress_interface` | Container interface controlled by the Linux barrier |
| `table`, `rule_priority`, `local_rule_priority` | Reviewed container routing profile |
| `lan_cidr`, `lan_interface` | Canonical private LAN and RouterOS ingress interface |
| `mapping_chain` | Dedicated `mc-<instance>-...` owned fallback NAT chain |
| `mapping_place_before` | Stable static RouterOS NAT object ID (for example `*7`) anchoring the reviewed permanent jump position |
| `capacity` | Finite namespace capacity, 1–4096 |
| `real_dns_address` | IPv4 resolver on port 53, matching model bootstrap |
| `canary_url`, `canary_peer_ip` | Operator-supplied active-process SOCKS canary |
| `watchdog` | Complete generated `WatchdogSpec`, including `lan_lease_cidr` |
| `ruleset_directory` | Optional existing verified rule-set store |

The generated observer must target the exact readiness socket and carry the
same instance and LAN lease CIDR. DNS and readiness bind the same private IP on
different ports. Internal allocator `127.0.0.1:5354` and SOCKS `127.0.0.1:2080`
ports are reserved. The native observer checks the actual socket peer; forwarded
headers do not authorize access. Readiness returns only a boolean.

Provision the native steering targets, generated observer/boot guard and
permanent fallback jump through the reviewed controller workflow first. Startup
checks their exact ownership and configuration; it refuses missing or conflicting
objects rather than constructing a guessed network topology. The fallback jump
remains enabled and is scoped to absence of the generated volatile LAN UP lease.
The native boot guard clears finite authority and disables steering targets.
Aliases keep their durable DIRECT mapping when the proxy becomes unavailable.

## Start

Initialize the application password once:

```sh
mikrocentauri api-auth-init \
  -state /absolute/private/api \
  -password-file /absolute/private/initial-password.txt
```

Run the composed backend inside the provisioned Linux container:

```sh
mikrocentauri api-serve \
  -state /absolute/private/api \
  -config /absolute/private/core.json \
  -router-config /absolute/private/router.json \
  -runtime-profile /absolute/private/runtime.json \
  -sing-box /absolute/bin/sing-box \
  -listen 192.168.88.2:8443 \
  -allow-clients 192.168.88.0/24 \
  -tls-cert /absolute/private/api.crt \
  -tls-key /absolute/private/api.key
```

The literal listen address determines the exact HTTPS Host/Origin accepted by the
admin API. Supply a certificate trusted by the client. API bearer sessions are
in memory and expire after 30 minutes. Without `-runtime-profile`, the same CLI
serves offline management/validation; readiness stays false and apply is denied.

`-subscription-refresh 1h` enables bounded periodic refresh; zero (the default)
disables scheduling. Cadence is constrained to one minute through 24 hours.
Refresh never imports nodes or changes active policy. Node selection enters a
private draft and follows the normal validate/plan/apply workflow.

## Ownership and recovery

One host owns core recovery, apply and periodic proof. DNS TCP/UDP and the native
readiness listener must bind before recovery can grant readiness. An unavailable
listener fails startup and releases resources. Do not run another lifecycle loop
or supervisor against the same persistent root.

A policy draft cannot change the operator's instance, mode, FakeIP pool or
bootstrap resolver. Validation and candidate generation also verify the native
profile. Apply delegates to the single transition owner, with generated candidate
fingerprint and namespace revision checks before quarantine. It verifies ledger,
core admission and the actual current-process canary before readiness becomes
true. Failed current proof withdraws admission; retained intent recovers forward.

Keep the entire persistent runtime root across restart. Do not copy a safe policy
backup over namespace journals, publication journals or the engine cache. These
preserve immutable aliases; the engine remains their sole allocator. Shutdown
cancels work, withdraws readiness and closes the owner.

Safe application backup schema 2 contains policy, redacted node/group metadata,
rule-set references, subscription IDs/filters and application preferences. It
excludes passwords, keys, source URLs, local paths and allocator state. Historical
schema 1 migrates by discarding its installation-specific cache path.

POST `/api/v1/backup/restore-preview` validates against existing local credentials
and generates a reviewable projection. POST `/backup/restore-draft` saves the
validated policy and safe settings together in a durable draft; it applies
nothing. Review the normal plan and submit `/config/apply`. Metadata/preferences
complete only after this exact draft commits. The retained draft journal permits
idempotent replay if a process exits between network commit and settings writes.
Missing local provider/endpoint/rule-set credentials deny restore. A fresh
installation needs explicit credential import. Encrypted full backup is a
reserved format and is rejected by the safe restore endpoints.
