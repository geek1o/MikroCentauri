# Bounded lab engine preflight

`Validate(data, Config{Selected: selected})` accepts the exact finite DNS policy
used by the disposable gateway: selected canonical ASCII names receive IPv4
FakeIP; AAAA receives an empty successful answer; other DNS uses a literal real
bootstrap server. It requires the sole IPv4 pool `198.18.0.0/15`, durable engine
cache `/data/singbox-cache.db`, loopback DNS listener `127.0.0.1:5354`, and a DNS
hijack restricted to `dns-in`. Unknown DNS predicates, additional servers,
predefined addresses, rule sets, resolver overrides, and reset APIs are rejected.
Other accepted settings deliberately match the restricted lab configuration,
not the complete sing-box option schema. Configuration validation is a startup
precondition and must run before launching the engine.
The explicit SOCKS canary must listen only on127.0.0.1:2080; an external listener
would bypass forwarding quarantine during admission.

`CheckCache(path, required)` examines filesystem metadata without opening or
modifying the database. Set `required` whenever the publisher journal contains
any reserved alias, including pending records. A missing cache is accepted only
before the first reservation. Existing cache files must be nonempty, regular,
mode 0600, beneath a mode 0700 immediate parent; symlink components are refused.
The gateway must set umask 0077 before engine creation: stock cache creation
requests mode 0666. This metadata check cannot prove database integrity,
ownership of the stored aliases, or persistence of an allocation cursor.

The gate must send canonical lower-case questions to the internal engine.
Configuration exact matching alone does not establish a finite storage key
namespace: stock `FqdnToDomain` strips a trailing dot without converting case.
A selected domain therefore has one canonical cache key only after gate
normalization. The configured namespace is immutable for a running generation;
changing it needs a separate reviewed generation lifecycle. This package does
not expire, remove, recycle, import, or rewrite aliases.

## Pinned stock behavior and limitations

These findings refer to sing-box **v1.14.2**, not a compatibility guarantee for
other releases:

* [FakeIP store](https://github.com/SagerNet/sing-box/blob/v1.14.2/dns/transport/fakeip/store.go): existing domain keys return their stored alias. New allocations increment the cursor and wrap at the pool boundary. A bounded canonical namespace below pool capacity avoids ordinary wrap; TTL does not recycle these keys. Missing or mismatched metadata resets storage on startup. Storage write failures are logged while the created alias can still be returned.
* [FakeIP cache](https://github.com/SagerNet/sing-box/blob/v1.14.2/experimental/cachefile/fakeip.go): writing a reused address removes the old domain key. Reading metadata consumes its database entry; the cursor is saved asynchronously following allocation and synchronously on store close. Abrupt engine death can therefore leave missing cursor metadata, even with a present file.
* [Cache startup and repair](https://github.com/SagerNet/sing-box/blob/v1.14.2/experimental/cachefile/cache.go): cache creation requests mode 0666; corrupt cache files can be deleted and recreated automatically. Checking path and mode alone does not prevent a stock reset.
* [Question-to-domain conversion](https://github.com/SagerNet/sing-box/blob/v1.14.2/dns/client_log.go) and [FakeIP exchange](https://github.com/SagerNet/sing-box/blob/v1.14.2/dns/transport/fakeip/fakeip.go) preserve domain case in the store key.

After startup and before exposing the TUN/public DNS or asserting readiness, the
gateway must compare every reserved publisher binding with the internal engine.
Any mismatch must stop the engine and retain native direct fallback. A successful
check covers observed bindings at that moment. It cannot establish safety after
unobserved in-process cache corruption/reset; this remains a production gate.
Do not describe this policy as safe alias recycling or arbitrary crash recovery.
