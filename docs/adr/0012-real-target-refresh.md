# ADR-0012: Refresh real targets without retiring FakeIP bindings

Status: accepted for the isolated IPv4 lab; production lifecycle remains OPEN.

## Decision

Keep stock sing-box as the allocator. Domain-to-FakeIP bindings never expire or
transfer within the publisher journal. The real IPv4 target has a separate DNS
lease. A bounded TCP stub resolver reads the positive TTL from the upstream wire
response, including the minimum TTL of the complete answer CNAME chain and
terminal A RRset. It accepts up to eight CNAME links, sorts and deduplicates A
addresses, and refuses incomplete chains, zero TTL, malformed or unsuccessful
responses. It does not validate DNSSEC or authenticate the upstream.

Initially select the numerically smallest usable IPv4 address. On refresh retain
the current target while it remains in the answer set; otherwise choose the
smallest candidate. This avoids unnecessary NAT changes when an RRset is reordered.
The publisher caps freshness at30s and returns only remaining whole seconds from
a monotonic deadline starting before resolution. Less than one full second of
remaining freshness blocks publication, including a1s answer consumed by latency.

Journalv2 writes an exact before/after target intent before a RouterOS mutation.
The mapping backend admits only the exact canonical before or after rule in the
dedicated chain, modifies only `to-addresses` on its existing object ID, and reads
back the after image. The publisher separately verifies and durably commits the
result before releasing a selected A answer. A lost write reply can be recovered
from the after image. An unrelated third target, missing rule, changed selector,
duplicate mapping or alias/domain transfer is a conflict, not overwrite authority.

Recovery finishes an existing intent before another DNS resolution can choose a
third target. Persisted wall-clock expiry never creates runtime freshness after
restart. Journalv1 migrates on its next write, retaining all alias reservations.
Reconciliation refreshes expired records even without new client DNS requests.
DNS failure preserves the committed fallback target and blocks publication and
readiness. A pending update preserves its durable intent and withholds an answer.

RouterOS REST PATCH has no atomic compare-and-swap in this implementation. The
lab requires one writer for its dedicated maps; concurrent external editing is
unsupported. Exact preflight/readback is not a distributed writer lock.

## Connection semantics and evidence boundary

The update leaves rule placement and native jump ownership unchanged. It never
flushes connection tracking. New connections use the changed target; established
connections can retain the previous NAT action. Cached FakeIP remains a domain
binding, not a guarantee that a departed real endpoint stays reachable.
See [RouterOS NAT](https://help.mikrotik.com/docs/spaces/ROS/pages/3211299/NAT)
and [REST PATCH](https://manual.mikrotik.com/docs/developer-guides/rest-api/).
DNS wire and TTL rules are documented in
[RFC1035](https://www.rfc-editor.org/rfc/rfc1035),
[RFC1034](https://www.rfc-editor.org/rfc/rfc1034) and
[RFC2181](https://www.rfc-editor.org/rfc/rfc2181).

The lab gate exposes bounded diagnostic categories and the last32 failures,
without arbitrary query names, packets, credentials or raw error strings. One
failed query remains SERVFAIL with zero answers; instrumentation is not a retry
or permission to release an unverified alias.

## Still open

Alias retirement/reuse, engine cache wrap/replacement, journal loss, capacity and
router identity migration require a separate generation lifecycle. The publication
barrier alone cannot prevent an engine from reassigning an old cached alias.
IPv6, power-loss/early-boot proof, multiple production routers/versions, authenticated
DNS and control, subscription updates and product activation remain unaccepted.
CNAME/multiple-A handling has protocol fixture evidence; native endpoint-churn
evidence covers two positive A targets and new TCP/UDP/HTTP3 connections only.
