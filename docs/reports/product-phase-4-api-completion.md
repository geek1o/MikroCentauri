# Product Phase 4: backend/API acceptance

Recorded 2026-10-06. **Product Phase 4 complete for the pinned CHR profile.**
Acceptance scope: RouterOS CHR 7.24.5 x86_64, pinned sing-box 1.14.2,
bounded IPv4 namespace, new connections and process failure.

## Backend deliverables

| Deliverable | Implementation and verification |
| --- | --- |
| `/api/v1` | Versioned HTTPS service, fixed host/origin and actual socket client CIDRs; bounded strict JSON requests and redacted responses |
| Authentication | Private salted PBKDF2 password state, opaque expiring sessions, login limits, logout/restart revocation; TLS 1.3 on the administrative listener |
| OpenAPI | Generated typed request/response/error schemas; HTTP contract tests and published schema equality |
| Configuration | Durable versioned drafts, Validate → Generate → Plan → Apply → Verify; single-use expiring plans bound to draft, namespace and immutable artifacts; unchanged topology preflight before replacing a healthy core |
| Editing resources | Redacted policy projection round trip, URI and cached subscription import into drafts, group/rule/DNS settings; post-commit draft editing with revision checks |
| Subscriptions | Private HTTPS provider credentials, filters, durable LKG, bounded optional periodic refresh, metadata deletion and redacted events; refresh does not automatically apply policy |
| Diagnostics/logs | Bounded API/runtime/subscription event history, RouterOS capabilities and owned counts, fixed-name bounded diagnostic archive without credentials or local state paths |
| Backup | Safe schema-2 application export, schema-1 migration, validated preview and draft restore, subscription metadata/preferences replay only after exact runtime commit; credential rehydration from existing private state |
| Native runtime | Production `api-serve` CLI composes accepted Transition, supervisor, DNS publication, namespace store, Linux ingress barrier and HTTPS RouterOS mapping/watchdog proof |

Safe backup deliberately omits endpoint secrets, provider URLs, private paths,
allocator state and engine cache. It restores settings within an existing private
installation; full encrypted credential transfer remains outside the MVP.
The lifecycle event ring is bounded and volatile, not a persistent audit journal.
Failed runtime verification identifies mapping, core or current canary through
fixed event codes; raw dependency errors do not cross the HTTP boundary.

## Native acceptance and provenance

The disposable CHR 7.24.5 x86_64 fixture uses production Go CLI as PID 1,
pinned sing-box 1.14.2, HTTPS RouterOS readback and a separate TLS 1.3 administrative
listener. Operator-provisioned native topology is immutable through the API;
RouterOS App installation and arbitrary topology migration belong to later phases.
The isolated `api4` namespace uses 198.19.128/17 and preserves older laboratory
roots, engine caches and immutable reservations. Real DNS fixture TTL is 30 seconds.

Every publication/profile proof reads a fresh bounded snapshot; collections are
shared only within that invocation. The CLI uses one reused physical RouterOS TLS
connection with HTTP/1.1, retaining context deadlines and certificate verification.
Cold capability/profile read transport failures are retried only within startup
quarantine and the existing bounded deadline. TLS trust, authorization, malformed
responses and ownership errors do not become retryable. No durable owner is
opened and no native mutation is issued before those reads succeed. Ledger
reconciliation proves and journals each starting reservation under the publication
lock, then yields between aliases so DNS callers can progress without bypassing
proof. Concurrent close/cancellation and interleaved publication are race-tested.

The lab switch now isolates malformed peers. Its regression test sends an invalid
frame size while two healthy peers continue forwarding/capturing a valid frame.
This fixes a fixture failure discovered during native acceptance.

The generated UP watchdog refreshes existing finite RAM counter/lease rows in
place. Removing an UP lease before re-adding it created a small DIRECT window
on each healthy probe; timeout updates were verified on actual dynamic CHR
entries. Foreign/static/duplicate authority still blocks readiness, and DOWN,
error and boot withdraw only exact owned dynamic rows.

The [completed production CLI run](product-phase-4-evidence/native-api.json)
retained aliases 198.19.128.2–198.19.128.4 and namespace revisions 6–8. It passed
Draft → Validate → Plan → Apply → Verify, domain retirement, single-use/stale
plan refusal, topology rejection without replacing the healthy child, safe
application backup restore, actual owner SIGKILL, cached DIRECT while DOWN and
forward recovery of the same policy/cache on restart. Foreign HTTP Host and
HTTP/3 SNI exercised binding-before-sniff in each cached matrix.

TLS 1.3 was negotiated against the actual API listener; unauthenticated reads
and revoked sessions returned 401. Live OpenAPI matched the committed generated
schema. The five-member diagnostics archive and safe backup omitted the fixture
endpoint credential, router password, bearer token and private runtime paths.
The healthy finite UP lease retained one row ID through four observations over
8.4 seconds, crossing multiple refresh cycles.

All **15 UDP workloads** have [exact-run WAN witnesses](product-phase-4-evidence/udp-witnesses.json):
proxy payloads traversed VLESS TCP to 10.77.0.10:8443 and DIRECT payloads reached
10.77.0.20:9000. [Capture digests](product-phase-4-evidence/captures.json) refer to
the stopped captures; raw PCAP remains local. Removing a required marker or using
another run ID is [explicitly rejected](product-phase-4-evidence/capture-negative-checks.json).

[Offline read-only inspection](product-phase-4-evidence/native-files.json)
confirmed the private 0700 directories, 0600 inputs/journals/cache, committed
revision 8 and three unchanged reservations. The actual container CLI SHA-256
is `19ad0498ea6c913a785bc555294c47b4ae4dc88114077b3ee7efe7eb2634078c`;
the actual sing-box hash matches the pinned Linux build. [Build metadata](product-phase-4-evidence/build.json)
records the rebuild image digest. The existing imported root was hotupdated with
that CLI, preserving state; this does not accept a release install/upgrade image.

[Cleanup](product-phase-4-evidence/cleanup.json) stopped all running containers,
withdrew finite authority, disabled the new observer/boot guard/steering, restored
original legacy DNS flags, TLS service and certificate inventory, and compared
existing static routes/NAT/observers/scheduler/services/certificates without
changes. The permanent scoped fallback jump, three mappings, all durable state
and older roots remain. Disposable VM/switch/file-server processes were then
terminated; no real router or subscription was used.

## Validation and remaining phases

`make check cross-build` passed: repository race tests, vet, actual pinned engine
schema/namespace/binding smoke tests and static Linux amd64/arm64 builds.
The lab switch integration regression and Python syntax checks also passed.

Phase 5 is the Web UI. Phase 6 supplies the installable RouterOS App; Phase 7
covers wider devices, versions and hardening; Phase 8 supplies release artifacts
and upgrade/rollback acceptance. The native profile remains bounded to CHR
7.24.5 x86_64 and IPv4 FakeIP with fresh connections and process failure.
