# ADR-0010: Router-owned backup translation for cached FakeIP destinations

Status: TESTED FOR ONE STATIC CHR MAPPING; production acceptance remains OPEN.
Native import, failure/recovery and malformed-map refusal are recorded in the
[Phase-2 report](../reports/phase-2-resilience.md).

## Problem and decision

Phase 1 proved that disabling DNS interception and the FakeIP route restores fresh
real-address connections, but a client with cached `198.18.0.2` still times out.
The failed container cannot translate that destination. Test whether RouterOS can
retain a small, independent backup mapping and apply destination NAT when the
existing native readiness watchdog enters DOWN.

The disposable fixture pins `selected.test` to synthetic `198.18.0.2` and real
`10.77.0.20`. Install exactly one owned `dstnat` rule for LAN ingress
`bridge-lan`, source `192.168.88.0/24`, and destination `198.18.0.2`. Translate to
`10.77.0.20`, retaining the transport protocol and destination port. Ordinary WAN
masquerade remains responsible for native egress. Reverse conntrack translation
should present the original synthetic peer to the client. The rule is disabled
while healthy; its persisted configuration remains independent of the container.
No additional DNS allocator or competing Netwatch instance is introduced.

[Lab script](../../lab/chr/cached-fallback.rsc) replaces only the source of the
existing `mc-lab-down` and `mc-lab-up` scripts and reuses the existing boot scheduler
and readiness Netwatch entry. All exact names/comments are fixture ownership keys.
Missing or duplicate watchdog objects abort before installation. UP validates
unique route, DNS rules, and mapping with explicit expected properties before any
steering activation. A malformed mapping keeps DNS interception and FakeIP steering
disabled; the script must not enable an arbitrary translation target.

DOWN stops DNS interception, verifies and enables the backup translation, then
disables the FakeIP route. This order prevents newly issued synthetic answers and
allows new mapped flows to be routed natively. UP restores the gateway route,
disables backup translation, then restores DNS interception. A startup scheduler
runs the same DOWN script without needing any live gateway. Installation first
pauses the existing Netwatch and leaves ordinary DNS/steering disabled; a partially
failed import needs operator repair and is not a transactional production installer.

## Permissions and packet semantics

The primary [MikroTik manual](https://manual.mikrotik.com/llms-full.txt), sections
Netwatch, Scripting, and NAT, specifies that Netwatch scripts execute as `*sys`
and are restricted to `read,write,test,reboot`. Both scripts and the scheduler
use `read,write,test`, with permission checks retained. There are no cross-user
global variables, stored credentials, file writes, or permission bypasses.

The same manual specifies that NAT matches the first packet and conntrack retains
the result. Consequently a new connection to a saved synthetic address is a
separate acceptance case from an already established connection. A preexisting
untranslated TCP/UDP entry can remain broken after DOWN; an established backup
DNAT entry can remain DIRECT after UP. This experiment deliberately does not clear
the global conntrack table, which would interrupt unrelated sessions. A production
strategy needs exact-instance attribution and an explicit reconnect policy, or a
proven bounded expiration strategy. FastTrack, mark-routing, and other NAT-rule
ordering can change results; the fixture must capture its rule order and counters.

## Required native evidence

Measure new TCP, UDP, and TLS-verified QUIC connections to the saved `198.18.0.2`
after killing only sing-box and after stopping the entire container. The target
must report the RouterOS DIRECT peer, with successful reply translation, and the
backup DNAT counter must increase. Compare fresh selected DNS, unrelated DIRECT,
healthy selected PROXY, and recovery. Save native DOWN/UP states and timings.

Corrupt or duplicate the mapping and attempt UP: route/DNS interception must stay
disabled and the unexpected mapping must not be enabled. Test reboot with the
container stopped and persisted selected steering: the mapping must be enabled
by native startup logic. A successful request at uptime twelve seconds alone does
not establish guard-before-first-forwarded-packet ordering. Capture that early
boot interval explicitly before claiming an outage bound.

## Production blockers

This static map bypasses the unsolved DNS-to-router publication protocol. A dynamic
allocator must never release a synthetic DNS answer until its exact mapping is
committed durably on the router and the router has acknowledged the active
mapping generation. Sing-box's internal FakeIP cache alone is insufficient. Restart,
write failure, and control-link failure must not expose an uncommitted alias.

Real-address selection must define multiple A records, real-IP churn, authoritative
TTL, DNS re-resolution, upstream failures, and affinity for an alias while clients
and conntrack still retain it. The map must not reuse a FakeIP for a different
domain during that lifetime. Arbitrarily short DNS TTLs cannot prove cache expiry.
An HTTPS service's TLS name remains the original domain, but endpoint reachability,
CDN behavior, application cookies, and HTTP redirects still require tests.

Large rule-set memory use, lookup latency, update time, write wear, router reboot
persistence, and capacity limits are unmeasured. IPv6/AAAA needs a separate design;
IPv4 NAT is not NAT64. Address-based or bind-address policies need preserved
source identity and an explicit definition of DIRECT behavior for each source.
A static LAN-wide fallback can intentionally bypass source PROXY during failure,
but this must be an approved policy contract. Source routing marks and forced
full-device steering must be withdrawn independently or can defeat native routing
of the translated real destination.

The rule shape check covers the fixture's key selectors and translation fields,
not every optional RouterOS match property. A production reconciler must verify a
canonical full allowlist including unsupported match fields, exact rule order,
map cardinality and ownership. Unrelated or broad earlier NAT rules must not shadow
backup translation. No dynamic allocator, durable acknowledgment protocol, complete
conntrack handoff, measured boot bound, or production capacity claim is implemented
by this experiment.


Phase 3 implements the initial dynamic publication barrier with enabled immutable
maps in a dedicated chain and a single native mode jump; see
[ADR-0011](0011-dynamic-dns-publication.md). The static experiment and its production
blockers remain historical evidence; complete lifecycle/boot acceptance is still open.
