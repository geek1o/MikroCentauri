# RC known limitations

The Release Candidate is qualified for **CHR RouterOS 7.24.5 x86_64,
sing-box 1.14.2, Alpine 3.24.2 and the disclosed synthetic IPv4 lab profile**.
The [E2E report](reports/product-phase-8-e2e.md) distinguishes native packet
proof, UI contracts and image construction.

| Boundary | Practical consequence |
| --- | --- |
| Device/version coverage | Physical ARM devices, RouterOS 7.22 and arbitrary topology/provider matrices have no native acceptance. The arm64 image's ELF/hash verification is packaging proof only. |
| IPv6 | Managed AAAA is suppressed and managed HTTPS/SVCB fails closed, but literal IPv6 bypass is demonstrated. No complete IPv6 selective routing, source-policy parity, alternate-resolver/DoH/DoT enforcement or proxy isolation is provided. The scoped lab guard is an operator experiment, not automatic whole-network protection. |
| DNS admission | Finite reviewed IPv4 domains are supported; suffix/wildcard FakeIP admission is unavailable. A selected query can return SERVFAIL when a publication proof crosses its authoritative TTL floor even while native readiness remains true. Private verification renews that specific expired proof once; public DNS does not extend TTL or bypass proof. |
| Source policies | PROXY/DIRECT tests cover admitted IPv4 aliases entering the prepared engine path. They do not establish whole-device proxy routing for arbitrary real-IP destinations. |
| Cutover and faults | Failures withdraw finite authority and permit reviewed DIRECT fallback. Convergence is observed with bounded waiting; no atomic/zero-delay/zero-loss cutover, established-session migration or general power-loss durability is established. Existing client/service behavior can differ from the fresh-connection probes. |
| Capacity | The accepted resource smoke lasts 68.12 seconds, with eleven 64 KiB cached-alias/real-IP pairs. It proves neither production throughput nor long-term leak absence, packet-loss bounds, thermal/storage endurance or hardware sizing. |
| Watchdog profile | Native acceptance uses 10 s interval, 3 s timeout, two successes and a 23 s finite RAM lease. Earlier shorter-lease attempts were rejected. These values are a disclosed fixture, not a universal capacity/fault-latency recommendation. |
| Installation and boot | Protected inputs, native stopped privilege review, prepared Linux/TUN ingress, TLS trust, time and exclusive operator control are required. App YAML alone does not grant native privilege. On 7.24.5 repeated boot needs the reviewed config-digest-bound operator scheduler plus independent startup guard. No unattended topology installer is supplied. |
| Upgrade/rollback | Native App edits/removal can clear state. Use a complete protected stopped-volume snapshot and exact-name recreate/restore; automatic updates stay disabled. Only the documented tested image pair is accepted, not arbitrary schema downgrades. |
| Backup/auth | UI exports omit credentials, allocator state and engine cache. Full encrypted credential backup is unsupported. Bearer sessions are memory-only and invalidated on restart; event history is bounded/volatile, not a durable audit journal. |
| Browser coverage | Chromium and WebKit HTTPS contracts pass. Firefox did not reach application navigation on the test Mac; it is not accepted. The browser fixture simulates runtime/router/subscription transports and is not native dataplane proof. |
| Security authority | Another RouterOS administrator is outside the ownership boundary. Tags/comments are not an authorization barrier. Independent penetration testing and general deployment hardening are not established by regression tests. |
| Protocol/engine scope | Protocol parsers reject unsupported transports; native WireGuard provisioning is a future adapter. Zapret, ByeDPI, NFQWS and packet mangling are outside the MVP. |
| Upstream data/branding | Community service feeds, reference project code/assets and logos are not bundled. Optional operator-selected subscriptions/rule sets require their own provenance/trust review. No MikroTik or reference-project endorsement is implied. |

Publication status and artifact/source coverage must be read from the generated
release manifest and current release report. Image construction alone does not
prove registry upload, catalog hosting, source-distribution completeness or
native runtime qualification. Historical reports retain their original scope;
the Phase 7 completion report supersedes earlier open hardening observations.

### Site-list scope

Downloaded lists expand into domain-suffix policy rules. SOCKS requests and
already admitted native DNS names can match those suffixes. Native DNS admission
still uses a finite reviewed namespace: list import admits the literal domain
roots, not every possible subdomain. Add required subdomains explicitly. Domain snapshots do not cover IP-only destinations. Separate IPv4 snapshots
create CIDR policy rules; their RouterOS interception requires native acceptance.
Alternate DNS and IPv6 remain outside this catalog coverage. The catalog UI does not imply
complete Podkop/Forkop packet-path equivalence.

The upstream broad Block list contains a top-level suffix (`.ua`) outside the
current domain model. It is excluded from the ready catalog; parsing does not
silently discard this rule. Service lists and GeoBlock are supported.

### IPv4 catalog and live selectors

CDN/service IPv4 snapshots now produce destination-CIDR rules. Their native
RouterOS interception is not established by host-side SOCKS tests. The current
catalog contains 27 verified text sources; it does not import every binary SRS,
adblock dataset, country list or top-level suffix supported by Forkop.

An enabled loopback Clash API permits immediate selection of a committed manual
group member. This changes new connections without a policy apply; existing
connections continue on their original outbound. HTTPS delay checks are actual
requests through endpoints, not ICMP ping or continuous availability guarantees.
The local preview runs a real SOCKS engine while RouterOS remains simulated.

Sections retain finite literal DNS admission and require review/apply for policy
changes. Their domain/CDN matches classify traffic entering sing-box; native
interception is not implied. Global device policies and advanced negative-priority
rules can precede sections. See [sections](product/sections.md).
