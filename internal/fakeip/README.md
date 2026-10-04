# Durable FakeIP publication barrier

This package is a laboratory foundation, not a production DNS service. It
publishes one immutable IPv4 mapping per canonical ASCII DNS host name. The
selected real A address is the numerically smallest usable IPv4 answer; IPv6,
unspecified, multicast, and FakeIP addresses cannot become fallback targets.

`New(Config, Resolver, Backend)` opens a private directory and obtains a
nonblocking process lock. `Config.Capacity` is required and is bounded by 4096.
`Config.Prefix` defaults to `198.18.0.0/15`; a configured prefix must be a
canonical subnet of that range and have room for the configured capacity after
its first address.

`Publish(ctx, domain)` allocates successive aliases, starting at the prefix's
second address and skipping previously reserved aliases.
`PublishAlias(ctx, domain, alias)` instead reserves the exact alias issued by a
proxy engine. Neither operation changes an existing domain's alias or real
target. A failed reservation remains occupied after a backend error, lost reply,
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
mapping metadata and TTLs, never backend credentials.

`Mappings()` returns copies of all reservations, including pending ones.
`Reconcile(ctx)` ensures and freshly verifies every reservation, synchronizing
new ready transitions. Neither method proves a proxy engine still knows an
alias. The integration must separately compare each domain's current engine
alias to its pinned journal alias before marking that engine ready. This is
essential for engines whose TUN/UDP processing depends on their own FakeIP cache.

TTL is an integer number of seconds, capped at 30 seconds. Nonpositive resolver
TTLs use 30 seconds and positive subsecond TTLs use one second. TTL controls the
client's answer lifetime only: this stage does not expire mappings, follow DNS
answer changes, implement garbage collection, or release capacity. If an engine
changes a domain's alias or wraps and reassigns an occupied alias, publication
fails closed. Recovery from DNS churn, journal loss, capacity exhaustion, and
engine cache replacement requires a separate lifecycle design.

The backend implementation owns exact RouterOS readback, ownership validation,
and safe routing transitions. This package cannot establish those properties
from a local journal alone.
