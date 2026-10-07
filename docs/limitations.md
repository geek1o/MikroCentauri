# Known limitations

Native tests covered CHR RouterOS 7.24.5 x86_64 with sing-box 1.14.2 and a
synthetic IPv4 profile. Newly built images must be qualified in their own right;
prior packet evidence does not establish acceptance of every rebuilt artifact.
Physical ARM, other RouterOS versions, arbitrary providers and whole-network
capacity remain unqualified.

- Selective routing admits finite reviewed IPv4 domains. Wildcard/suffix FakeIP
  admission and complete IPv6 routing are unavailable. Literal IPv6 and alternate
  DNS/DoH/DoT can bypass policy; source policies are not whole-device proxying.
- Public DNS stays strict about verified publication and TTL. A query can return
  SERVFAIL at a proof boundary while native readiness remains true.
- Failure recovery converges within the reviewed profile; it does not guarantee
  zero delay/loss, established-session continuity or general power-loss durability.
  DIRECT fallback can expose traffic that was intended for a proxy.
- Installation requires protected bootstrap, TLS, prepared topology, native
  stopped privilege review and operator-controlled repeated boot configuration.
  A store entry alone does not prepare the router for native forwarding.
- App edits/removal can clear state. Upgrade/rollback require an unchanged full
  stopped-volume snapshot; UI exports exclude credentials, allocator and cache.
  No arbitrary schema downgrade is guaranteed.
- Resource tests were short bounded smoke tests, not production throughput,
  thermal/endurance sizing or long-term memory-leak qualification.
- Chromium and WebKit management contracts were tested; Firefox and wider
  browser/device combinations are unqualified.
- Native WireGuard provisioning, anti-DPI components, packet mangling, complete
  encrypted credential backup and durable audit event storage are not included.
- Community service lists, reference-project code/assets and logos are not
  bundled. Optional feeds require separate provenance and trust review.
