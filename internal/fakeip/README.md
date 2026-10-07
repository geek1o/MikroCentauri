# Durable FakeIP publication barrier

This package is a laboratory foundation, not a production DNS service. It
publishes one immutable domain-to-FakeIP binding per canonical ASCII DNS host
name. Real targets are refreshed using DNS TTLs. The initial real A address is
the numerically smallest usable IPv4 answer; on refresh the current address is
retained while it is still a candidate. Otherwise the smallest usable address
replaces it. IPv6,
unspecified, multicast, and FakeIP addresses cannot become fallback targets.

`New(Config, Resolver, Backend)` opens a private directory and obtains a
nonblocking process lock. `Config.Capacity` is required and is bounded by 4096.
`Config.Prefix` defaults to `198.18.0.0/15`; a configured prefix must be a
canonical subnet of that range and have room for the configured capacity after
its first address.

`Publish(ctx, domain)` allocates successive aliases, starting at the prefix's
second address and skipping previously reserved aliases.
`PublishAlias(ctx, domain, alias)` instead reserves the exact alias issued by a
proxy engine. Neither operation changes an existing domain's alias. A failed reservation remains occupied after a backend error, lost reply,
or restart. Aliases are never recycled or reassigned to another domain.

Publication proceeds in this order:

1. Resolve and choose the real IPv4 target for a new domain.
2. Atomically write and synchronize the pending reservation and its directory.
3. Ensure the corresponding mapping exists on the backend.
4. Freshly verify that exact backend mapping.
5. Atomically write and synchronize its ready state.
6. Return the mapping and DNS TTL, provided the caller has not canceled.

Every later publication repeats Ensure and Verify, even when the journal marks
the record ready. A disconnected backend therefore causes an error and no DNS
answer. Uncertain journal writes poison that publisher instance; it must be
closed and reopened before any further allocation. The journal contains only
mapping metadata, TTLs, target transition intents, and observed expiry times,
never backend credentials.

`Mappings()` returns copies of all reservations, including pending ones.
`Reconcile(ctx)` recovers unfinished intents, refreshes expired DNS targets,
and freshly verifies every reservation, synchronizing ready transitions. Neither method proves a proxy engine still knows an
alias. The integration must separately compare each domain's current engine
alias to its pinned journal alias before marking that engine ready. This is
essential for engines whose TUN/UDP processing depends on their own FakeIP cache.

TTL is an integer number of seconds, capped at 30 seconds. Resolver TTLs below
one second, including zero, fail closed; they never acquire an invented lease.
A runtime deadline begins before resolution. Publication returns only the
remaining whole seconds after backend verification, so network latency does not
extend authoritative freshness. Freshness is intentionally renewed when less
than one whole second remains. `Config.Now` provides a deterministic test clock;
production uses `time.Now` and its monotonic component.

Journal version 2 stores an optional `previous_mapping` during target changes
and `expires_at` for inspection. Persisted wall-clock expiry is never accepted
as runtime freshness after reopening. Version 1 journals migrate on their next
write while retaining all alias bindings. After restart, each published domain
must resolve again; a future stored expiry cannot bypass this check.

A changed target requires the backend's optional `TargetUpdater.Update(ctx,
before, after)`. The publisher persists the exact before/after intent before
calling Update, freshly verifies the after mapping, and durably commits it
before releasing an answer. Update must accept only the exact canonical before
or after backend rule, rejecting unrelated state; an after rule permits safe
recovery from a lost reply. A pending transition is completed before any new
DNS resolution can select another target. Backends without this interface fail
closed on a target change.

Failed resolution retains the committed fallback target but returns an error
from publication and reconciliation. An interrupted update remains a durable
pending intent, without a positive DNS answer. No failure deletes a reservation.
Existing connections may continue using an older target through connection
tracking; this package neither flushes those connections nor proves their
continuity. New-flow delivery must be checked separately on the actual backend.

Aliases never expire, recycle, or release capacity. If an engine changes a
domain's alias or wraps and reassigns an occupied alias, publication fails
closed. This barrier does not prevent an engine itself from reusing its cache,
and does not establish cached-packet safety after such reuse. Journal loss,
capacity exhaustion, engine cache replacement, and administrative retirement
still require a separate lifecycle design.

The backend implementation owns exact RouterOS readback, ownership validation,
and safe routing transitions. This package cannot establish those properties
from a local journal alone.
