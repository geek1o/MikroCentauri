# Versioned backend API foundation

Product Phase 4 is in progress. `internal/api` provides the HTTPS/authenticated
boundary and an adapter to the accepted core transition owner. Standalone
`api-serve` intentionally has no forwarding runtime: readiness is false and
apply returns `503 runtime_not_connected`. It can manage private drafts, run the
real validator, produce plans and export/preview backups. It now creates a
private subscription registry/cache and exposes configure/refresh/inspection.
`-router-config` connects read-only RouterOS capabilities and owned-object counts.
Absent optional RouterOS connections still return `501 adapter_not_connected`.
A composed application can pass `Host` as the runtime; the standalone CLI does
not construct a native forwarding profile and therefore still cannot apply.

## Start locally

Use absolute regular 0600 input/key files and a real 0700 state directory without
symlink components. Store the password outside Git; it must be 16–1024 bytes.
The password file may have one trailing newline. Initialize once; initialization
never overwrites existing credentials.

```sh
mikrocentauri api-auth-init -state /absolute/private/api -password-file /absolute/private/password.txt
mikrocentauri api-serve -state /absolute/private/api -config /absolute/private/core.json -sing-box /absolute/path/sing-box -tls-cert /absolute/private/server.crt -tls-key /absolute/private/server.key
mikrocentauri api-openapi -out /absolute/output/openapi.json
```

Default listener is `127.0.0.1:8443`. Only literal loopback/private LAN addresses
are accepted; LAN requires explicit `-allow-clients` CIDRs. Client checks use the
actual socket peer, not forwarded headers. Wildcard/public listeners are refused.
HTTPS is mandatory with TLS 1.3 minimum. Use a certificate trusted by the client;
there is no insecure startup mode. If the model references external rule sets,
provide the existing verified private `-ruleset-state` store.

POST `/api/v1/auth/login` with `{"password":"..."}` over HTTPS obtains an opaque
Bearer token for 30 minutes. All other routes require it except `/health/live`.
Tokens live only in memory, are indexed by SHA-256 and disappear on restart or
logout. No cookies or ambient browser credentials are used. Every request must
match the configured exact Host; a supplied Origin must match the HTTPS origin.
Cross-origin requests and all query parameters are refused; no CORS is enabled.
Passwords and tokens never belong in URLs. The client should retain tokens only
in memory. Login is limited globally to five attempts/minute, verification is
serialized, active sessions are capped at 32, concurrent HTTP requests at eight.
The global limiter resets on process restart; multi-instance/distributed login
limits are not claimed.

Password storage uses standard-library PBKDF2-HMAC-SHA256 with 600,000 iterations
and a random 32-byte salt. See [OWASP's password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
and [the Go PBKDF2 implementation](https://go.dev/pkg/crypto/pbkdf2/).
The private directory is locked against a second owner. A failed draft atomic
write denies further mutation until reopen, including uncertain post-rename
fsync outcomes. Sessions and plans are not persisted.

## Configuration workflow

1. POST `/api/v1/config/draft` with a complete schema-v2 model. Schema validation
   and private durable save do not activate the core. GET responses show projections.
2. POST `/config/validate` or `/config/plan` with `{"draft_revision":N}`. Validation
   calls the real pinned sing-box validator. With the connected core owner, it also previews
   the finite namespace without reserving a revision or stopping the active child.
3. Plan returns a random `plan_id`, base revision, candidate preview and a
   five-minute expiry. It binds the exact immutable draft/model digest and revision.
   A prepared runtime additionally binds the generated candidate, including
   resolved SRS artifact paths/hashes. Apply compares and pins that one artifact
   resolution under the core owner lock; changed sources return 409
   `candidate_changed` before quarantine or namespace reservation.
4. POST `/config/apply` with `{"plan_id":"..."}`. A connected runtime delegates
   solely to `Transition.Apply`; draft changes, namespace drift, pending recovery,
   expiry and replay fail. A plan is consumed before an actual apply attempt.
   Failure does not retry behind the caller's back or grant readiness.

The server serializes its configuration workflow. The transition owner's own
compare-and-swap still protects against concurrent non-API changes. API callbacks
must honor their context. In-process plans are invalid after restart; durable
drafts reopen but must be revalidated. GET `/config` is a preview, never a secret
model download. This first plan describes the core candidate; unified RouterOS
change preview/apply and resource editing remain Phase 4 integration work.

## Safe export and diagnostics

GET `/backup` exports schema 1 `mikrocentauri-safe`: rule/service/source policy,
DNS fields, groups with URLs removed and redacted endpoint/WireGuard metadata.
It excludes keys, passwords, UUIDs, group URLs and subscription/rule-set remote
URLs. POST `/backup/restore-preview` parses and validates against matching
existing private endpoint credentials, then returns a redacted preview. It never
saves or applies the backup. Mismatched endpoints/future schema fail; a fresh
installation needs separate credential import. This is a core policy export,
not yet an application-wide backup containing subscription metadata/preferences.
Encrypted full backup and migration are reserved for a subsequent block.

GET `/diagnostics` and `/logs` return explicit projections and a bounded 128-event
API history. Events contain timestamp, level, component, event, request ID and
config revision; raw engine output and exception text are never logged here.
Responses have `Cache-Control: no-store`, no-sniff and a restrictive CSP. Error
codes are stable and contain no user input or private dependency messages.

[OpenAPI](openapi.json) is generated from the route declarations and actual model
JSON field types. It includes bearer security, request schemas and disconnected
adapter error statuses. It is an initial contract; comprehensive typed resource
responses, unified RouterOS mutations and remaining provider-management schemas
remain in Phase 4.

## Runtime host and resource adapters

`NewHost(HostOptions)` accepts an existing `*coreactivation.Transition`, the
publisher's `Reconcile` and a fresh active-process canary `Check`. It implements
`Runtime`/`PreparedRuntime`; pass it in `api.Options.Runtime`. These are trusted
composition inputs, never supplied by HTTP request JSON. Bind DNS and the
separate private `host.ReadinessHandler()` before `host.Run(ctx)`. The native
observer must consume this boolean endpoint, not the authenticated admin route.

Run first holds the core, attempts durable recovery and periodically verifies
ledger mappings, core admission and the active canary. Readiness is false until
all proofs succeed; failures stop/hold the core under a fresh cleanup context.
Subsequent ticks recover the retained intent forward. Cancellation withdraws
readiness, cancels work and closes the owner once; Run waits for concurrent
shutdown. POST `/system/recover` provides authenticated explicit recovery.
One host owns the lifecycle; do not run the old lab loop or another supervisor
alongside it. Host tests use a deterministic CoreOwner; new native deployment
acceptance is not claimed by those tests.

The available mapping backend is still a lab-specific chain/lease profile.
A deployment factory must supply an accepted native mapping/placement/boot
profile; this block does not silently reuse `NewLabLeaseMappingBackend` as a
production backend. CLI-native runtime composition and that profile acceptance
remain open, as do unified RouterOS/core plans and application-wide restore.

GET `/routeros` uses verified HTTPS discovery and returns capabilities plus owned
counts/disabled counts by resource. No raw object fields, script bodies, router
password or connection URL are exposed. Capability availability does not prove
write permission, placement, TUN or native readiness. Add `-router-config` with
the existing private connection schema documented in the controller guide.
The endpoint performs GET only; RouterOS mutations stay behind controller plans.

POST `/subscriptions` accepts a private `{id,url,include?,exclude?}` specification
with HTTPS required. Saving does not download or change the active model. POST
`/subscriptions/refresh` with `{id}` invokes the existing bounded downloader.
The default denies private/special addresses, pins validated resolved addresses,
disables environment proxies, repeats checks across redirects and verifies TLS.
An operator can supply a separate trusted root pool through the Go library;
the pool is cloned and TLS verification remains enabled. The HTTP API and CLI
do not expose private-address or insecure-TLS overrides.

A failed refresh reports a fixed error plus redacted prior LKG status/nodes;
it never replaces a working core model. URL and node credentials remain private.
Registry ownership is locked, specifications are atomic 0600 files, at most
64 providers are accepted. List/refresh responses return at most 128 node
previews/provider with `node_count`, `offset` and `has_more`. POST
`/subscriptions/inspect` with `{id,offset,limit}` retrieves pages, limit 1–128.
The registry/cache reopen across restart. Adding imported nodes to a core remains
an explicit draft/validate/plan/apply operation, not an automatic network change.

GET `/diagnostics/bundle` downloads a fixed-name gzip/tar archive containing
runtime status, model preview, API events and optional redacted resource views.
Archive entries have mode 0600 and an 8 MiB aggregate JSON limit. It never walks
the filesystem or includes journals, cache databases, secret models, raw engine
output, script bodies or subscription URLs. A failed RouterOS read is recorded
as a fixed error; other serialization/resource failures deny the download.

Config, draft and plan responses include a `policy` projection for reviewing rules,
services, source policies, DNS membership and rule-set IDs/formats. It excludes
remote URLs and local artifact/cache paths; model previews exclude credentials.
