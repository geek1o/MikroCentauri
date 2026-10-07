# Security status

Product Phase 7 is complete for the explicit synthetic CHR 7.24.5 profile.
Phases 2–7 have bounded acceptance on CHR 7.24.5
x86_64 and the pinned sing-box 1.14.2 profile; this does not establish security
acceptance across RouterOS versions, physical devices or arbitrary topologies.
See [the roadmap](product/progress.md) and
[Phase 7 hardening completion](reports/product-phase-7-hardening-completion.md)
and [management review](reports/phase7-management-security-review.md).

## Management and secrets

The production API requires HTTPS and authentication, exact configured Host/Origin
and an allowed socket peer. It has expiring bearer sessions, password hashing and
login rate limits. Drafts use version checks; reviewed plans are single-use and
runtime readiness requires current verified admission. Proxy credentials and
subscription URLs remain in private state rather than ordinary API projections.
Application backups omit credentials; diagnostics use bounded, fixed projections.
A full encrypted credential backup is not implemented.

Protected state directories/files require 0700/0600 and refuse unsafe paths.
The production Go App launcher sets umask 0077 before starting the engine.
Images contain executables and public trust roots, not deployment credentials.
Operators supply protected bootstrap inputs, a reviewed topology and RouterOS
credentials. RouterOS permissions cannot enforce application ownership tags;
network restriction and a scoped account remain necessary deployment boundaries.
The production CLI RouterOS transport uses verified TLS and explicitly disables
inherited HTTP proxy settings. RouterOS redirects are refused. Callers supplying
a custom transport to the lower-level client are responsible for that transport.

## Remote downloads

Subscription and rule-set downloads have bounded time, size, headers and redirects.
Every destination is checked; dialing uses checked IP literals after validating
resolved addresses. Default policy refuses private/local and selected special-use
addresses; an explicit operator CIDR override grants access to matching addresses.
There is no environment proxy. Redirects omit Referer so credential-bearing source
paths and query strings are not disclosed to the next destination. Managers copy
operator CIDRs and TLS trust stores at construction, preventing later caller
mutation from expanding authority.

Rule sets and production API subscription imports require HTTPS. The lower-level
subscription manager retains explicit HTTP compatibility; those callers do not
receive transport confidentiality on an HTTP hop. TLS certificate verification
remains enabled for HTTPS. Invalid downloads/compilation preserve the last known
good artifact. These controls do not make arbitrary remote content trustworthy or
prevent an intentionally granted operator override from reaching private services.

## Packet path and recovery

Managed DNS A responses require verified FakeIP publication. Managed AAAA returns
an empty answer; unsupported managed query types, including SVCB/HTTPS, fail closed
instead of forwarding to the allocator. This is an IPv4 selective-routing boundary,
not proof against IPv6 bypass: cached/literal IPv6, alternate resolvers and client
DoH/DoT require a reviewed network policy. Read-only IPv6 configuration detection and setup/DNS notices are implemented;
configured-disabled and missing settings do not prove isolation. The scoped DNS/literal-bypass/operator-guard
matrix is accepted; general IPv6 isolation remains unsupported. See [IPv6 observation](reports/product-phase-7-ipv6-observation.md).

Owned firewall placement, quarantine and readiness guards coordinate activation
and recovery. Native Phase 6 tests cover selected TCP/UDP/HTTP3, cached aliases,
engine restart and image replacement/rollback on the pinned CHR profile. Existing
FastTrack and unrelated rules are preserved; the pinned FastTrack/IPv6/reboot/failure matrix and a one-minute cached-flow
resource smoke have native capture acceptance. Physical hardware capacity, broader
versions/browsers and long-term resource behavior remain release qualification.
Private readiness proofs renew an expired verification lease once from a fresh
authoritative origin; repeated expiry and other errors still quarantine. Public
DNS remains strict and may return SERVFAIL at a TTL boundary while readiness
remains true. No zero-loss or continuous existing-session guarantee is established.

## Laboratory boundary

Disposable CHR fixtures may use explicit lab-only HTTP constructors, synthetic
credentials and unauthenticated probes. They are not production management or
readiness endpoints. Keep those fixtures and generated listener configurations
inside their isolated lab networks. No real router or subscription is needed for
the Phase 7 security foundation regressions.
