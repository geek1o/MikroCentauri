# Modern WireGuard endpoint

This package builds the `endpoints` WireGuard object supported since sing-box
1.11. It emits `system: false` for an isolated userspace implementation, not the
removed legacy WireGuard outbound or a privileged host network interface.
`Endpoint.Normalize` validates and computes a SHA-256 ID. IDs include key
material, addresses and peer configuration, while names and enabled state do
not change identity. `Preview` omits all key material.

Private interface addresses, canonical prefixes, strict base64 32-byte keys,
X25519 peer validity, unique peers and non-overlapping allowed routes are
required. Collection bounds are eight interface addresses, 32 peers and 128
allowed prefixes per peer. MTU is 1280–9000 (default 1408); keepalive is 0–600
seconds. A peer may omit its address and port together for a passive listener.
Disabled endpoints cannot build an active configuration.

`NativeRouterOSWireGuardAdapter` reserves the future native adapter boundary.
There is no native RouterOS installer in this package. A sing-box endpoint does
not authorize modifying RouterOS interfaces or global routing.

The real pinned integration fixture uses two local UDP endpoints and proves
TCP/UDP application data, correct pre-shared-key operation and denial with a
wrong peer public key or pre-shared key. The tunnel canary destination is a
reserved documentation IP that the server rewrites to a loopback fixture.
This avoids gVisor's rejection of loopback-addressed packets inside a tunnel;
it sends no packets to external systems.

Official schema: https://sing-box.sagernet.org/configuration/endpoint/wireguard/
The schema's `on_demand` option requires 1.15 and is intentionally absent from
the pinned 1.14.2 model.
