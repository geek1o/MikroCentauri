# ARM64 pinned canary and subscription failure diagnostics

## Verified scope

On the existing RouterOS 7.23.8 long-term ARM64 hAP ax^2 management installation,
read-only inspection confirmed the running App, Linux aarch64 namespace, TUN
clone device and effective NET_ADMIN capability. The namespace has the expected
local-table policy rule at priority 200. No routing table or policy rule was
installed or changed by these observations.

The previous named Cloudflare observation was converted to a resolver-independent
canary: a current public IPv4 answer for `www.cloudflare.com` was reviewed and
used as the literal HTTPS destination, with the original verified TLS name and
HTTP Host. A newly compiled ARM64 diagnostic tool was transferred over trusted
RouterOS HTTPS and its SHA256 checked before execution. This was an isolated
operator executable, not an in-place production binary replacement.

The same address/name pair passed both directly and through one previously
verified draft proxy. The proxied observation reported a different external IP
from direct egress, with a fresh HTTP sample of 1007 ms. A deliberately incorrect
TLS name failed. Raw external IPs, endpoint IDs, source URLs and credentials are
retained only in ignored private receipts. No dedicated canary VPS was needed
for these diagnostic observations.

The test proves an available literal-IP HTTPS canary path on this network. It
does not prove native RouterOS forwarding, automatic group failover, ingress
quarantine, UDP/QUIC forwarding, or restart/reboot recovery on ARM64. The running
production App still uses its previous immutable image and remains management
only. Its authenticated final state was healthy, draft revision 3 and
`runtime_connected: false`; the prior 17-node draft and 14-member auto group were
not applied. Temporary diagnostic files were removed and the diagnostic session
was logged out.

## Code changes

The optional operator `canary_server_name` is accepted only for a literal HTTPS
canary. It supplies certificate hostname verification, TLS SNI and HTTP Host;
the dial destination stays literal. Native profiles still reject named canary
URLs. Direct diagnostics and isolated-node diagnostics now honor the same
profile format and TLS name as native readiness.

A reviewed `canary_peer_ips` set supports multiple known proxy egress addresses
without treating a change to another reviewed group member as a direct fallback.
The set is bounded to 32 distinct addresses, mutually exclusive with the legacy
single address, normalized and copied before use. The direct egress must be
excluded. Membership is not automatically expanded from discovery or drafts.
Regression tests reject an unexpected direct egress, wrong TLS name, duplicate
peer identity and caller mutation. The CHR-only native activation and stopped
installation gates remain unchanged; this code does not qualify ARM64 by itself.

## Subscription path remains a separate issue

A fresh direct container download of the configured source again timed out.
It did not produce an HTTP error, certificate diagnostic or DNS failure in that
bounded observation. A workstation download through its system tunnel is not
evidence that the source is directly reachable from the container. The timeout
alone does not attribute responsibility to the provider, ISP or firewall.

Downloads now retain fixed redacted stage codes in private state and expose only
allowlisted codes in API/CLI views. The UI distinguishes DNS, destination policy,
connection, timeout, certificate, redirect, HTTP and body failures, and an empty
cache from a last-known-good list. Old state remains readable. A failed refresh
retains the last good nodes and timestamp; success clears failure state. Neither
TLS checks nor destination restrictions were relaxed.

This change improves diagnosis; it does not implement downloading through a
chosen proxy. Automatic source refresh remains unresolved on the current direct
network path. The one-time draft import is not presented as an updated cache.

## Validation and remaining admission

The full Go race suite and vet passed with the pinned sing-box executable.
Targeted TLS tests performed a real handshake through a SOCKS fixture and a real
isolated Shadowsocks child, including wrong-name and wrong-egress failures.
Frontend type checks, unit tests and bundle budget passed. Chromium and WebKit
passed the administrative workflow and failure-display scenarios at desktop and
mobile widths; screenshots were inspected for wrapping and readable status.

ARM64 production admission still requires a reviewed platform qualification
path, a prepared operator profile with a canary policy rule and least-privilege
native owner, and separately approved packet-path tests on a scoped test client.
A rollback timer, preserved state, direct/proxy controls, readiness withdrawal
and restoration must precede any wider LAN activation. No such device mutation
or traffic activation was performed in this increment.
