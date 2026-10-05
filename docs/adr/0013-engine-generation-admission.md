# ADR-0013: admit a finite engine namespace before forwarding

Status: accepted for the isolated three-domain IPv4 lab; production lifecycle OPEN.

A durable RouterOS map does not prove that a restarted engine still assigns the
same domain to that alias. Cached clients bypass DNS publication entirely. A
readiness check after exposing the TUN therefore leaves an unsafe interval.

The gateway installs an ingress blackhole before launching or replacing the
engine. It keeps the existing ingress policy rule in place and refuses conflicting
rules. It reads every configured alias through the private engine DNS listener,
compares the complete set with all durable reservations, then publishes and
verifies all native fallback maps. Only a complete admitted receipt permits the
TUN route and selected positive DNS answers. A mismatch kills the child while
retaining the blackhole and native DIRECT maps. Periodic validation revokes the
receipt and quarantines ingress on an observed mismatch.

The exact selected namespace is finite and immutable: selected.test, second.test
and third.test. The gate canonicalizes selected queries before engine exchange,
including case and terminal dot, and strips additional client sections. It refuses
allocation while admission is pending and links each operation to its generation
epoch. Revocation cancels the old epoch and prevents a late publication receipt
from escaping into a DNS answer. Internal DNS and the SOCKS canary listen only on
loopback; the latter cannot provide an alternative external ingress.

Strict preflight requires the bounded lab config, cache path, mode0700 parent and
mode0600 regular nonempty cache whenever any alias is reserved. Symlinks are
refused. A cache without a publisher ledger is also refused. Umask0077 precedes
engine creation. File metadata is a prerequisite, not an alias-integrity proof.

Stock sing-box v1.14.2 can reset FakeIP storage when cursor metadata is missing or
incompatible, or recreate a corrupt cache. Its metadata read consumes the saved
cursor; allocation saves it asynchronously and graceful close saves it again.
The runtime comparison is necessary even when the cache file exists. See the
pinned [store](https://github.com/SagerNet/sing-box/blob/v1.14.2/dns/transport/fakeip/store.go),
[FakeIP cache](https://github.com/SagerNet/sing-box/blob/v1.14.2/experimental/cachefile/fakeip.go),
[cache startup](https://github.com/SagerNet/sing-box/blob/v1.14.2/experimental/cachefile/cache.go)
and [question conversion](https://github.com/SagerNet/sing-box/blob/v1.14.2/dns/client_log.go).

No aliases are deleted, recycled or transferred. TTL expiry changes only real
target leases. Finite canonical preallocation prevents ordinary new-key pool wrap
under this closed configuration, but does not prove arbitrary online database
corruption, external writers or power-loss behavior. Before production activation
we still need kernel route ownership, early-boot ordering, a reviewed namespace
change/retirement protocol, device/version coverage and authenticated management.

The [Phase5 report](../reports/phase-5-generation-admission.md) records the exact
native scenarios and retained failures. HTTP Host sniffing can still change the
routing domain; DNS canonicalization alone does not normalize that separate input.
