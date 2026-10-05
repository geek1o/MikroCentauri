# ADR-0011: Verify router backup maps before publishing engine FakeIP

Status: LAB IMPLEMENTED; native results in Phase-3 report; production acceptance OPEN.

## Decision

Retain sing-box1.14.2 as the owner of the FakeIP cache. Put its typed DNS listener
on loopback5354, behind a bounded publication gate on5353. For selected exact IN A
questions, ask the internal allocator for an alias, resolve the real IPv4 via an
independent bootstrap, durably reserve the domain/alias/real binding, ensure and
read back the exact RouterOS backup mapping, fsync local ready state, then return
one A answer. Gate errors produce SERVFAIL with zero answers. Existing published
bindings repeat router verification before each new gated answer. Client DNS
caches can still reuse previously verified answers without contacting the gate.

The publisher records pending intent before RouterOS writes. Lost replies are
reconciled by exact map readback, never interpreted as successful publication
merely because a local journal says ready. Reservations survive restart and are
never recycled, including failed attempts. Domain-to-alias and alias-to-domain
bindings are immutable. The real target is pinned to the smallest usable IPv4 A
in the initial resolution; real-address churn, expiry and garbage collection are
not implemented. Journal capacity is bounded4096; the isolated gateway uses32.
Local files use0700/0600 and a process lock, atomic rename and file/directory fsync.

Startup/health reconciliation verifies all persisted maps, then queries every
record through the gate to compare the engine's current alias with the journal.
Changed engine aliases keep readiness DOWN; there is no supported cache-injection
API or direct database editing. The internal DNS listener cannot be queried directly
from LAN. The explicit SOCKS and management fixtures remain isolated lab services.

## Independent native fallback

Keep immutable enabled `dst-nat` rules in dedicated `mc-dynamic-backup`, with exact
alias/target/source selectors and instance comments. Native Netwatch changes only
one scoped `dstnat` jump: enabled during DOWN, disabled during UP. Thus adding a
map does not race a watchdog loop enabling/disabling a changing set of map rules.
DOWN stops DNS interception, enables the validated jump and removes FakeIP steering.
UP restores steering, disables the jump and restores DNS. Prior static fallback
stays disabled. Router map writes never change the native mode switch.

The lab backend rejects duplicate/conflicting aliases, changed targets, unexpected
selectors and noncanonical rules inside its dedicated chain. Existing chain/jump
placement against arbitrary customer NAT remains a production capability gate.
Router readback is configuration acknowledgement; power-loss persistence and early
boot ordering are separate tests, not consequences of REST HTTP success.

## Why not an independent allocator at ingress

Stock sing-box checks its FakeIP cache before routing rules. An external alias
inside its FakeIP range without a cache record is rejected. `override_address`
is documented, but native FakeIP supplies a distinct UDP translation wrapper;
override schema acceptance alone does not establish generic UDP/HTTP3 delivery.
Therefore the package's standalone allocator is a protocol test fixture, not the
gateway's active address owner. The gateway uses `PublishAlias` for engine aliases.
References: [official route actions](https://sing-box.sagernet.org/configuration/route/rule_action/),
[pinned routing source](https://raw.githubusercontent.com/SagerNet/sing-box/v1.14.2/route/route.go),
[pinned cache API](https://raw.githubusercontent.com/SagerNet/sing-box/v1.14.2/experimental/clashapi/cache.go).

## Remaining policy

Historical Phase-3 scope below. [ADR-0012](0012-real-target-refresh.md) adds wire
TTL/CNAME handling and journaled real-target refresh, preserving alias bindings.

Selected AAAA returns empty NOERROR; other selected RR types fail closed. Exact
ASCII names only; no wildcard/service/subscription UI. Unselected answers cannot
carry aliases in answer, authority or additional sections. DNS frames are capped
at4096 bytes and requests at128 concurrent slots. This is not a full validating
DNS resolver: CNAME, DNSSEC, EDNS policy and authoritative TTL handling need design.
The lab real resolver uses its controlled upstream's known5s TTL; the protocol
accepts resolver-provided TTL and caps it at30s, without using TTL as a reuse proof.

Existing conntrack may keep DIRECT paths after UP; no global flush. General
IPv6 enforcement, router identity/ledger migration, capacity behavior under engine
cache wrap, endpoint changes, reboot/power-cut evidence and production auth/TLS
remain open. Deleting the private ledger or reusing a persisted root against another
router is not a supported recovery path.
