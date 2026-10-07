# Product Phase 7: IPv6 observation and deployment boundary

Historical intermediate status; superseded by [Phase 7 completion](product-phase-7-hardening-completion.md) for its pinned native profile.

Date: 2026-10-07. Status: read-only capability/UI block complete; **Phase 7 remains
in progress**. This follows [security foundation](product-phase-7-security-foundation.md).

## Result

Authenticated `GET /api/v1/routeros/network` now projects `/ipv6/settings`,
`/ipv6/address` and `/ipv6/route`. Only configuration state, forwarding and counts
escape; raw IPv6 addresses, gateways, comments and other fields do not. Settings
state is `configured_enabled`, `configured_disabled` or `unknown`; missing settings
are not treated as disabled. A null forwarding field means it was not observed.
The existing `available` map marks each independently missing resource. OpenAPI
boolean pointers explicitly allow null; the [contract regression](evidence/phase-7-ipv6/schema-regression.txt)
distinguishes unknown forwarding from false/true and checks the published schema.

The setup network step and DNS page display the observation and the IPv4 routing
boundary. They explain that managed AAAA suppression does not cover saved IPv6
addresses or alternate DNS, and settings alone do not prove packet isolation.
A disabled setting retains the same warning. The UI has no automatic IPv6 mutation.

[Official MikroTik IP Settings documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/103841817/IP%2BSettings)
defines `disable-ipv6` and `forward`, and warns that changing settings does not
remove old SLAAC state dynamically and can require reboot. That documentation
site is frozen; native schema verification below uses the accepted RouterOS build.
We do not infer effective isolation from the configured flag.

## Native schema evidence

A dedicated clone of the stopped Phase 6 lab disks booted with fresh loopback
management ports. The [tracked GET-only observer](../../tests/e2e/ipv6_observation/main.go)
uses an explicit lab HTTP constructor, synthetic disposable admin credentials and
no proxy. It refuses non-GET requests. No production credentials or real router
were used. QEMU opened only the copied disks, with no external test WAN/client
switch attached; this is a schema observation rather than native App admission or
an IPv6 forwarding experiment.

[Observation](evidence/phase-7-ipv6/native-observation.json) records CHR
7.24.5 x86_64, configured IPv6 enabled, forwarding true, four valid/non-disabled
addresses and zero observed IPv6 default routes. Counts include loopback/link-local
addresses; they do not establish Internet reachability. Default-route counts include
all observed defaults, regardless of enabled/active state.

This experiment exposed native rows that omit `disabled`: dynamic IPv6 routes,
a dynamic IPv4 default and an existing FastTrack rule. IPv6 route parsing accepts
absent flags, checks them when provided and counts configured defaults. IPv4 routes
add `disabled_known`; a false `disabled` is meaningful only when that is true.
FastTrack adds `fasttrack_unknown` and counts enabled only when `disabled=false`
was explicitly observed. The UI distinguishes unknown rules instead of presenting
a false enabled count or rejecting the whole network projection. These are read
observations, not authorization to modify such rules.

The dedicated VM was stopped and all four listeners confirmed closed:
[cleanup evidence](evidence/phase-7-ipv6/cleanup.json). Original lab disks were
not opened by QEMU; no IPv6/firewall setting was changed by the observer.

## Validation and remaining work

[Network regressions](evidence/phase-7-ipv6/regression.txt) cover enabled/disabled
settings, missing resources, false forwarding, strict flags and singleton cardinality,
malformed/duplicate JSON, IPv4 or mapped addresses in IPv6 rows, dynamic routes
without flags, explicit redaction and rejection of POST/PATCH/DELETE on every new
path. The independent GET allowlist does not widen mutation authority.

Browser contracts cover the notice in setup and DNS, enabled/disabled/unknown
settings, unavailable network data and hidden counters for missing resources.
These tests use an authenticated HTTPS backend with a simulated router provider;
the separate native observer verifies actual REST parsing.

[Chromium/WebKit output](evidence/phase-7-ipv6/browser.txt) records four passing
contracts. Updated amd64/arm64 App images pass independent OCI/archive/ELF and
secret-free packaging checks: [verification](evidence/phase-7-ipv6/image-verification.txt)
and [build metadata](evidence/phase-7-ipv6/image-build.json). These images have not
received native packet or admission acceptance in this block.

`make check cross-build` passed after contract regeneration: full Go race/vet,
integration and sing-box smoke checks, frontend checks/build, clean diff and Linux
amd64/arm64 cross-builds. [Output](evidence/phase-7-ipv6/validation.txt) is retained.

Automatic observation and visible deployment limits are now implemented. Controlled
IPv6 bypass experiments, the full FastTrack matrix, native updated-image reboot
and failure injection, sustained resources and physical/version/browser coverage
remain open. No proof of IPv6 leak prevention or Phase 7 completion is claimed.
