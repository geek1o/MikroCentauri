# Candidate network flow

A: LAN DNS → RouterOS-scoped DNAT → sing-box DNS; selected A → FakeIP;
LAN selected packet → RouterOS routing → VETH → Linux TUN → sing-box → VLESS.
Unselected real-IP packet → RouterOS main → WAN. Gateway outbound packets must be
excluded from steering to prevent loops. Preserve original LAN source for device rules.

B: RouterOS selects LAN internet → VETH/TUN; sing-box decides proxy versus DIRECT.
C: RouterOS Socksify selected TCP → explicit SOCKS inbound → proxy. No UDP parity.

A is measured on CHR 7.24.5 for TCP/UDP/QUIC and source priority. B is measured
for all fixture destinations; broad internet exclusions are not yet accepted.
C has a measured TCP original-destination relay, with RouterOS as upstream peer.
Native failure/recovery and managed FastTrack exceptions are exercised. Complete
fail-open acceptance remains open; see the Phase-1 report and ADR-0009.

Generated TUN auto_route remains false. The lab installs iif=mc-probe → table100
at priority10000 (after RouterOS container local priority200), and table100's
default routes to mc-tun. Locally originated proxy/DNS sockets stay in main.
Production CLI preview route/NAT objects still start disabled; no production
activation command is exposed.
