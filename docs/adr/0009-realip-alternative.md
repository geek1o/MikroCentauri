# ADR-0009: Real-IP fallback comparison

Status: **EXPERIMENT TESTED; NOT ACCEPTED FOR GENERAL DOMAIN POLICY**.
Experiment: 2026-10-04 UTC / 2026-10-05 Moscow.

FakeIP/TUN preserves source and domain for TCP, arbitrary UDP and QUIC, but
cached synthetic destinations remain unreachable during gateway failure after
native watchdog disables its route. This was reproduced on CHR 7.24.5, rather
than inferred solely from documentation.

The comparison keeps RouterOS DNS at the DHCP-advertised router address. A static
FWD entry populates a dynamic destination list; only listed LAN destinations
receive the managed routing mark toward TUN. Locally generated gateway sockets
retain the main table. DOWN disables the exact mangle rule and table route while
native DNS continues. UP validates those two object shapes before activation.

TESTED: real selected IPv4 + HTTP Host sniff → VLESS; unselected cohost at the
same address → TUN DIRECT; source .30 priority → DIRECT; selected QUIC after DNS
refresh → VLESS; saved real address → native DIRECT after engine death;
restore → selected VLESS. Dedicated native watchdog and independently executed
startup guard were observed. See [evidence](../reports/phase-1-dataplane.md).

LIMITATIONS: unrelated cohost IPs still enter the gateway; the HTTP/QUIC examples
have visible names. The selected generic UDP marker was captured with native .1 egress after fresh
DNS resolution: this candidate failed that selection case. Generic UDP cannot
reliably recover a selected domain from a real IP; DNS-list TTL expiry can bypass policy for client-cached real addresses.
ECH, CNAME, HTTPS/SVCB, IPv6 and complex device-domain policies are not accepted.
Inferring domain solely from a shared IP cannot restore per-name isolation.
Adding a blanket proxy rule fixes ambiguous selected UDP by overselecting cohosts;
that is not evidence of faithful domain routing.

Decision: retain real-IP mode as a measured fallback candidate, not silently
replace FakeIP or advertise complete fail-open/domain parity. Hybrid TUN remains
the proven ingress mechanism. The next architecture work must resolve cached
FakeIP fallback and health semantics, or define a measured real-IP policy with
its loss of precision explicitly reflected in the product contract. No frontend
acceptance or production activation follows from this experiment.
