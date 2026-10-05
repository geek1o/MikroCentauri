# Bounded lab engine preflight

`Validate(data, Config{Selected: selected})` accepts the exact finite DNS policy
used by the disposable gateway: known canonical ASCII names receive IPv4
FakeIP; AAAA receives an empty successful answer; other DNS uses a literal real
bootstrap server. It requires the sole IPv4 pool `198.18.0.0/15`, durable engine
cache `/data/singbox-cache.db`, loopback DNS listener `127.0.0.1:5354`, and a DNS
hijack restricted to `dns-in`. Unknown DNS predicates, additional servers,
predefined addresses, rule sets, resolver overrides, and reset APIs are rejected.
Other accepted settings deliberately match the restricted lab configuration,
not the complete sing-box option schema. Configuration validation is a startup
precondition and must run before launching the engine.
The explicit SOCKS canary must listen only on 127.0.0.1:2080; an external listener
would bypass forwarding quarantine during admission.

For the historical all-active policy, the six traffic rules must retain this order: internal DNS hijack, device
192.168.88.30 DIRECT, device 192.168.88.20 PROXY, selected-domain PROXY, sniff,
and selected-domain PROXY again. The first domain rule binds the stored FakeIP
name before HTTP Host or TLS/QUIC SNI can change domain matching. A terminal
route stops rule evaluation, so selected aliases never reach sniff. Source
choices take priority over that binding. The final domain rule retains sniffed
selection for traffic addressed to a real IP. This fixture has no reverse DNS
mapping option; adding one requires a policy review.

Pinned [router metadata preparation and terminal routing](https://github.com/SagerNet/sing-box/blob/v1.14.2/route/route.go)
restore an alias to its stored destination domain before matching rules.
[Domain matching](https://github.com/SagerNet/sing-box/blob/v1.14.2/route/rule/rule_item_domain.go)
prefers the sniffed domain whenever present; this caused the previous Host/SNI
policy escape. [Destination CIDR matching](https://github.com/SagerNet/sing-box/blob/v1.14.2/route/rule/rule_item_cidr.go)
checks the rewritten destination or resolved addresses, not the saved original
alias. A pool CIDR rule therefore cannot establish this binding after the
engine has restored its domain.

`tests/integration/binding_policy.py` exercises real stock engine processes,
compares VLESS server connection logs, and reproduces the old Host/SNI escape.
It adapts listeners, source fixtures, target ports and cache paths to loopback;
it does not establish RouterOS, native TUN, QUIC or reboot behavior.

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
normalization. The known allocator namespace remains immutable. `Config.Selected` retains
that complete namespace for compatibility. `Config.Active == nil` selects all
known names; a nonnil slice selects an explicit canonical subset, including an
empty slice for all retired. Duplicates and names outside the known namespace
are rejected. The ordered route policy places an active PROXY domain rule and
a retired DIRECT domain rule before sniff, then active PROXY after sniff. Empty
domain rules are omitted. Retired aliases therefore cannot regain PROXY by
sniffing an active Host/SNI; source overrides still take precedence. DNS allocator
rules continue to contain every known name so admission can verify historical
bindings without allocating from a new namespace. This is a generation-specific
policy preflight; it does not activate a transition or revoke an old generation. This package does
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
