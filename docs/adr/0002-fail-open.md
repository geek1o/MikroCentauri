# ADR-0002: Router-owned fail-open

Status: NATIVE LAB MECHANISM TESTED; COMPLETE FAILURE CONTRACT OPEN.

Controller inside the failed container cannot repair the router. Use native
Netwatch against a dedicated container port returning 200 at `/` only when the
validated applied generation, sing-box, DNS and dataplane are healthy; otherwise
503. Current schema has no `http-path`. `/api/v1/health/ready` may expose the same
state later, but Netwatch must not be pointed to a nonexistent URL-path property.

DOWN disables exact-instance-owned steering and DNS interception; UP restores only
a verified generation. Netwatch remains enabled independently of gateway process.
Route/NAT install starts disabled. Persisted enabled rules during router boot need
a tested early-boot guard; startup-delay must be explicit. Debounce/hysteresis must
be implemented and measured; a bare interval is not an N-consecutive-failure policy.

The failure envelope distinguishes: ordinary real-IP DIRECT traffic, selected
real-IP traffic, cached FakeIP traffic and existing proxy connections. Cached
198.18/15 addresses are not publicly routable. DNS fallback and a 30s authoritative
TTL do not guarantee clients expire caches, and established flows need reconnect.
Never assert bounded restoration of *all* traffic from this design alone. Consider
real-IP RouterOS DNS/address-list selection as an alternative in ADR-0001.

Acceptance: kill backend, kill sing-box only, block DNS, isolate VETH, reboot CHR
with active state, restore process; capture native DOWN/UP transitions, unrelated
rules and actual client success times. Lab Netwatch/startup scripts are implemented and exercised on CHR 7.24.5.
See [measured failures](../reports/phase-1-dataplane.md). Single-run timings include
1s settling/polling overhead; debounce/hysteresis and worst-case bounds remain TODO.
Remote VLESS outage left local readiness200: proxy health remains a separate gate.
The observed startup repair at uptime12s does not prove guard-before-packet order.
