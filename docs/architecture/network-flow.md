# Candidate network flow

A: LAN DNS → RouterOS-scoped DNAT → sing-box DNS; selected A → FakeIP;
LAN selected packet → RouterOS routing → VETH → Linux TUN → sing-box → VLESS.
Unselected real-IP packet → RouterOS main → WAN. Gateway outbound packets must be
excluded from steering to prevent loops. Preserve original LAN source for device rules.

B: RouterOS selects LAN internet → VETH/TUN; sing-box decides proxy versus DIRECT.
C: RouterOS Socksify selected TCP → explicit SOCKS inbound → proxy. No UDP parity.

These are candidates, not measured RouterOS paths. Current preview route/NAT objects
are disabled, and generated TUN auto_route is false. Linux ingress routing, source
preservation, outbound exclusions and FastTrack exceptions require explicit proof.
