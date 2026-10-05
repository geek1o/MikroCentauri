# Finite engine generation admission

This laboratory barrier binds an explicitly configured, finite list of exact
domains to stock engine aliases. It preserves configured allocation order and
preloads every alias before making a publication mutation. Duplicate aliases,
aliases outside the configured FakeIP prefix, changed durable bindings, and
ledger domains outside the configured namespace deny admission. Successful
admission requires durable publication and backend verification for every name,
through the existing `fakeip.Publisher`.

`Begin` guards the engine DNS exchange before it can allocate, requires an
admitted exact domain, and returns an epoch context cancelled on revocation.
The DNS gate must pass that context to its exchange and invoke its cleanup.
`Admission` implements the DNS gate publisher. Requests must match both an
admitted exact domain and its frozen alias. `Revoke` cancels operations and
invalidates their epoch immediately; even a dependency that returns a late
successful receipt cannot release it to DNS. A failed admission may leave
durable reservations. The barrier never deletes or rebinds those reservations.
`Snapshot` returns a copied receipt and bounded reason labels, never dependency
error text. `Validate` checks every engine alias and revokes on mismatch.

The caller must quarantine forwarding before starting or replacing an engine,
then admit before enabling ingress. An engine DNS read can itself allocate if
its cache has been lost. Periodic validation alone cannot protect cached traffic
between checks. The caller must also enforce a closed engine namespace and
verify durable engine-cache prerequisites before child startup; this package
cannot inspect an engine configuration or its filesystem. Selected namespace
expansion, alias garbage collection, expiry-based recycling, engine wraparound,
and arbitrary subscription domains remain unsupported. Fixed namespace
preallocation bounds allocation only when the caller enforces those conditions.
