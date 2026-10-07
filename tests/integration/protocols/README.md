# Local pinned protocol acceptance

Run with `SING_BOX_BINARY=/absolute/path/to/sing-box go test -race
./tests/integration/protocols`. Version checks require sing-box 1.14.2. Fixtures
create ephemeral keys/certificates and private configuration files, use only
local listeners and clean up process groups. Certificate trust is injected into
test-only client configurations; production URI import never disables TLS
verification.

Coverage:

- VLESS TLS and Vision: TCP and SOCKS UDP application data, wrong UUID,
  untrusted certificate and wrong certificate name.
- Trojan TLS: TCP/UDP data, wrong password, untrusted certificate and wrong name.
- Hysteria2: actual QUIC transport with TCP and UDP payloads, wrong password,
  untrusted certificate and wrong name.
- VLESS Reality: TCP/UDP data, wrong Reality public key, short ID and UUID.
  Its TLS handshake target is a local HTTP/2 TLS 1.3 fixture with X25519.
- Shadowsocks: additional UDP payload coverage beyond existing TCP tests.
- Modern userspace WireGuard: two UDP peers, actual TCP/UDP application payloads,
  matching PSK and refusal with wrong public key or PSK.

WireGuard uses a reserved documentation destination rewritten to loopback by
its server fixture because gVisor refuses tunneled loopback destinations. This
is a local transport proof, not a RouterOS TUN or production Internet proof.

Primary schemas:
https://sing-box.sagernet.org/configuration/inbound/vless/
https://sing-box.sagernet.org/configuration/inbound/trojan/
https://sing-box.sagernet.org/configuration/inbound/hysteria2/
https://sing-box.sagernet.org/configuration/shared/tls/
https://sing-box.sagernet.org/configuration/endpoint/wireguard/
