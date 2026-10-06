# Web UI adapters (product phase 5)

All routes retain the existing TLS, exact Host/origin, actual socket CIDR,
expiring bearer session, strict JSON and mutation serialization requirements.
Credentials are write-only. Draft changes require the current `draft_revision`;
these routes do not apply network policy. The normal validate → plan → reviewed
one-use apply workflow remains required.

## Proxy edits

- `POST /api/v1/proxies/update`: `{draft_revision,id,name?,enabled?,uri?}`.
  Omitted values retain private fields. A replacement URI receives its canonical
  credential-derived ID; group memberships/selection, rules, source policies and
  the default outbound are rewritten atomically. Identity collisions are denied.
  WireGuard metadata can be renamed or toggled; URI replacement is unsupported.
- `POST /api/v1/proxies/delete`: `{draft_revision,id}`.
- Both return `{draft_revision,base_revision,id,model,policy}` with redacted
  projections. Disabling/deleting referenced nodes fails validation; edit their
  policy references first. The application never silently selects DIRECT.
- Endpoint previews now include `Enabled` alongside existing capitalized fields.

## Read-only environment

`GET /api/v1/routeros/network` uses fixed GET-only resources and returns selected
IPv4 addresses/interfaces, default routes, DHCP hostname/IP/MAC/status, literal
DNS servers, FastTrack counts, RAM and disk bytes. IPv6 interface addresses are
skipped because this dataplane handles IPv4. No DHCP options, comments, scripts,
DoH URLs, credentials or arbitrary raw RouterOS rows are returned. `available`
records resource presence; denied/malformed responses fail rather than invent
state. Network resources do not extend the RouterOS mutation allowlist.

`GET /api/v1/system/info` returns development application version, build revision
when embedded, expected pinned sing-box version, observed verified version when
a runtime owner is attached, and the private application filesystem capacity.
The API does not expose its directory. An offline API has no observed sing-box
version and does not claim a running core.

## Fixed diagnostics and node samples

`POST /api/v1/diagnostics/run`: `{kind}` where kind is `routeros`, `core`, `dns`,
`direct`, `proxy`, `routing` or `watchdog`. A completed sample returns
`{kind,success,code,scope,latency_ms,checked_at,revision}`. A failed probe returns
`success:false` without raw dependency errors. Missing adapters return 501.

- RouterOS: authenticated capabilities and ownership snapshot.
- Core: current model generation and pinned sing-box validation.
- DNS: first current selected domain through the configured TCP DNS gateway.
  Ordinary FakeIP publication proof still applies if an answer needs an alias.
- DIRECT: fresh direct HTTP connection to the configured literal-IP canary,
  with a valid peer response; there is no configured expected DIRECT peer.
- Proxy: existing configured canary with its expected proxy peer IP.
- Routing: read-only active owned Linux ingress rule/table/TUN/forwarding checks
  and immutable RouterOS mapping profile.
- Watchdog: exact generated watchdog/boot-guard and mapping profile. This does
  not simulate failure or replace the native fail-open acceptance evidence.

Runtime diagnostics serialize with policy transitions and health work; they do
not toggle readiness, reconcile leases or change steering. Arbitrary URLs,
names, ports, commands and filesystem paths are not accepted.

`POST /api/v1/proxies/probe`: `{id}` accepts only a current enabled endpoint,
including WireGuard. Newly imported draft-only or disabled IDs return 404.
It starts a bounded isolated socksify child for that single node, with random
loopback ports and a separate private temporary configuration/cache. It has no
TUN, native controller, FakeIP store or fallback group, and never accesses the
live engine cache. The fixed operator canary is requested over SOCKS5, and the
child is killed/reaped before the temporary directory is removed, including on
failure/cancellation. This does not alter the current selector or activation.

The response is `{node_id,success,code,scope,latency_ms,checked_at,revision}`.
Latency measures the HTTP sample and excludes child startup/checking. A sample
is evidence at its timestamp, not continuous node health or confirmation that
this node is selected by the live group. The browser must present that boundary.

The setup wizard reviews this discovered/preprovisioned environment and the
actual policy plan. Installing VETH, routing tables, firewall exceptions or
RouterOS App packaging belongs to product phase 6, not to these API adapters.

## Shared subscription schedule

`GET /api/v1/subscriptions/schedule` reports `{interval_seconds,running}`;
`running` identifies the serial refresh owner. A zero interval disables refresh
even if its owner is running. `POST` accepts only `{interval_seconds}`: zero or
60–86,400 seconds. The required integer rejects null, unknown/duplicate fields
and out-of-range values. The private atomic record survives restart and takes
precedence over `--subscription-refresh`, which supplies a startup default only.

The production listener always starts one scheduler. Enabling/changing the
interval waits a complete interval before the first attempt. Providers run
serially with bounded per-provider deadlines; disabling stops subsequent
attempts. It never imports cached nodes or applies configuration. Manual refresh
still works when scheduling is disabled. Safe application backups do not include
this installation-local scheduler setting; preserve it separately when migrating.
