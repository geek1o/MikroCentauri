# Versioned backend API

The backend exposes `/api/v1` through mandatory HTTPS and expiring bearer
sessions. [OpenAPI](openapi.json) describes actual request and response types;
[the native runtime guide](runtime.md) describes composition and operator inputs.
Installation, the browser UI and wider device acceptance are separate phases.

## Start and authentication

Initialize a password once, then start the service with private input files:

```sh
mikrocentauri api-auth-init -state /absolute/private/api -password-file /absolute/private/password.txt
mikrocentauri api-serve -state /absolute/private/api -config /absolute/private/core.json -sing-box /absolute/bin/sing-box -tls-cert /absolute/private/server.crt -tls-key /absolute/private/server.key
mikrocentauri api-openapi -out /absolute/output/openapi.json
```

Password, model, RouterOS connection, runtime profile and key inputs are regular
0600 files; state directories are 0700 without symlink components. Initialization
refuses an existing credential. Passwords are 16–1024 bytes, stored with
PBKDF2-HMAC-SHA256, 600,000 iterations and a random 32-byte salt.

The default listener is `127.0.0.1:8443`; explicit private LAN listeners require
`-allow-clients` CIDRs. Wildcard/public listeners are refused. TLS 1.3 is required.
The actual socket peer determines client permission; forwarded headers do not.
Host must match the listener's exact HTTPS origin; a supplied Origin must match
as well. Query parameters are denied and there is no CORS or cookie authentication.

POST `/auth/login` with `{"password":"..."}` returns an opaque `access_token`,
Bearer type and a 30-minute lifetime. All other routes except `/health/live`
require it. Tokens are indexed by SHA-256, capped at 32 and discarded on restart
or `/auth/logout`. Login verification is serialized and limited globally to five
attempts/minute; the limiter resets on restart. HTTP concurrency is bounded at
eight requests and JSON bodies at 4 MiB. Ambiguous JSON and unknown fields fail.

Without `-runtime-profile`, the service manages and validates offline drafts;
readiness remains false and apply returns `runtime_not_connected`. With the
profile, `api-serve` starts one accepted transition owner, DNS publication,
immutable mapping publisher and health lifecycle. Native activation is pinned to
Linux on CHR 7.24.5 x86_64. The operator first provisions an exact controller
profile; backend startup and plans verify it. Arbitrary topology changes are not
inferred from policy edits.

## Configuration workflow

1. Save a complete schema-v2 model with POST `/config/draft`. Alternatively use
   `/config/draft/policy` to edit the redacted policy/groups while reusing existing
   private endpoint credentials, provider/rule-set sources and cache identity.
   Partial edits require the current `draft_revision` (zero starts an absent
   draft). Credentials are never downloaded just to change a rule.
2. POST `/config/validate` with `{"draft_revision":N}` runs actual pinned sing-box
   preflight and read-only namespace preview. Saving does not activate traffic.
3. POST `/config/plan` with the same revision returns a full redacted candidate,
   `changed_sections`, base revision, random `plan_id` and five-minute expiry.
   The plan binds the draft digest, namespace revision and generated candidate,
   including resolved rule-set artifacts. Native topology remains a fixed,
   verified operator profile; owned aliases are materialized by the publisher.
4. POST `/config/apply` with `{"plan_id":"..."}` consumes the plan once and delegates
   to the sole transition owner. Changed sources, pending recovery, expired plans,
   draft changes, revision drift and replay fail. Actual candidate comparison and
   artifact pinning occur under the owner lock before quarantine/reservation.
5. Success includes verified committed revision/readiness. Namespace, DNS,
   process, mappings and the current-process canary must pass before readiness
   becomes true. Failure holds admission and retains durable forward recovery.

`/config`, `/config/draft`, `/proxies`, `/groups`, `/rules`, `/devices` and `/dns`
return reviewable projections. Raw private models, source URLs, keys, passwords
and engine output are not resource responses. In-memory plans disappear on
restart; durable drafts must be revalidated. Persistence uncertainty blocks
further mutation until reopen. POST `/system/recover` explicitly retries retained
intent; the sole host also performs periodic proof/recovery.

## Subscriptions and manual import

POST `/subscriptions` saves `{id,url,include?,exclude?}` privately without download
or activation. HTTPS URLs and bounded regular-expression filters are required;
at most 64 providers are registered. POST `/subscriptions/refresh` with `{id}`
uses the bounded TLS downloader, address validation, pinned dialing and repeated
redirect checks. Private/special destinations and environment proxies are denied
by default. There is no HTTP insecure-TLS or private-network override.

Failed refresh retains LKG nodes and returns a fixed error plus a redacted view.
List/refresh responses contain at most 128 nodes/provider; `/subscriptions/inspect`
accepts `{id,offset,limit}` for bounded pages. `/subscriptions/import` selects
cached `node_ids` into a private draft using its revision. `/proxies/import`
parses explicitly supplied URIs into a draft. Both reuse stable IDs, validate the
candidate and return no credentials; neither applies the network.

POST `/subscriptions/delete` removes the registry entry, preserving active model
endpoints and the private LKG cache. `-subscription-refresh 1h` enables a single
bounded periodic refresher; zero disables scheduling. Refresh never imports or
applies automatically. Registry ownership is locked before reading its state.

## Backup, preferences and diagnostics

GET `/backup` exports `mikrocentauri-safe` schema 2: policy, redacted endpoint and
WireGuard metadata, groups, rule-set references, subscription metadata and
preferences. Passwords, keys, UUIDs, URLs, local paths, namespace/publication
journals and the engine-owned cache are excluded. Schema 1 migrates by dropping
its installation-specific cache path. Encrypted full export is a reserved future
format and is rejected by safe restore endpoints.

POST `/backup/restore-preview` parses, migrates and validates against matching
local credentials. `/backup/restore-draft` saves that validated model and settings
in one durable draft, without applying. The normal plan/apply workflow commits
it. Metadata/preferences complete only after exact revision/model proof; the
draft journal permits idempotent replay after interrupted settings writes.
A fresh installation requires explicit credential import. GET/POST `/preferences`
support validated language, theme and IANA time zone; scheduling/topology cannot
be changed by preferences or restored backups.

GET `/diagnostics` and `/logs` expose a bounded 128-event history combining API,
runtime health/apply/recovery and subscription refresh operations. Events contain
UTC timestamp, level, component, event, request ID and config revision. History
is volatile; persisted LKG failure state and configuration journals retain their
own recovery evidence. Raw dependency errors and engine output are excluded.

GET `/diagnostics/bundle` downloads a fixed-name gzip/tar archive of status, model
preview, events and optional redacted RouterOS/subscription views. Entries have
mode 0600 and an 8 MiB aggregate JSON bound. The bundle never walks disk or
includes secret files, script bodies or allocator state. GET `/routeros` uses
verified HTTPS capabilities/discovery and returns owned counts, not raw objects.
Readiness is separate from liveness and from the authenticated admin listener.

`routeros/network.ipv6` is read-only configuration evidence. `state` is
`configured_enabled`, `configured_disabled` or `unknown`; `forwarding: null` means
unobserved and differs from `false`. Address counts exclude explicitly disabled
or invalid rows; default-route counts include inactive/disabled routes and do not
prove reachability. Check `available["ipv6/address"]` and `available["ipv6/route"]`
before treating zero counters as an observation. Configuration state does not
prove effective IPv6 isolation. See [Phase 7 observation](../reports/product-phase-7-ipv6-observation.md).

`fasttrack_unknown` counts rules whose disabled flag was not returned; they are
not included in `fasttrack_enabled`. For IPv4 default routes, `disabled` is an
observation only if `disabled_known` is true. Missing native fields do not grant
mutation authority.
