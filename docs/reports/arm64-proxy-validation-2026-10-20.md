# ARM64 subscription and isolated proxy validation

## Scope and evidence

The active management installation remains the custom `mikrocentauri-2` App on
RouterOS 7.23.8 long-term ARM64, at its original management URL. This work changed
only private draft policy and temporary diagnostic files. No RouterOS services,
firewall, routes or DNS configuration were changed, and no native runtime was
activated. The observer account remains read-only.

The configured subscription could not be downloaded from the container. The same
private URL returned HTTP 200 on the workstation, whose resolver returned a
benchmark-range address and whose system tunnel handled that destination. This
is not evidence that the provider is reachable directly from RouterOS. The
response was retained in RAM; the source URL and raw links are absent from this
report and Git.

The downloaded response contained 26 non-comment records. Initially 15 distinct
proxy nodes parsed successfully. Two otherwise valid Trojan gRPC records
contained an empty `authority=` parameter, which the parser incorrectly rejected
as an unsupported key. The fix preserves an empty authority as a semantic no-op,
keeps canonical identity unchanged, and still rejects nonempty or duplicate
authorities. It adds those two nodes, giving 17 supported proxy nodes. The other
nine records are two unsupported XHTTP entries and seven application deep links
(`vpn`, `tg`, `incy`), rather than supported engine endpoints. XHTTP was not
silently translated into a different transport.

Supported raw links were imported through the authenticated existing proxy-draft
API. The empty gRPC authority was removed from the two links for compatibility
with the currently installed parser. This does not disable TLS verification or
change credentials. This is a one-time snapshot import into the draft: the
subscription's failed URL refresh and empty downloaded cache remain visible.
Automatic subscription refresh through the router is not fixed by that import.

## Isolated test method

The new operator `mc-node-check` tool reads an existing private mode-0600 draft
under a mode-0700 directory. It uses the accepted isolated `grouphealth` prober
and the installed pinned sing-box binary, loopback-only authenticated mixed
listeners, independent temporary configurations and no TUN or RouterOS client.
It does not apply the draft or share production engine state.

The ARM64 diagnostic executable was transferred through certificate-verified
RouterOS HTTPS and its SHA256 verified before execution. Execution used bounded
foreground calls, normally with one selected endpoint per call. An initial
background attempt was terminated by the RouterOS execution boundary despite
`nohup`; later foreground calls completed and reaped their children. Three
initial defunct processes remain adopted by the container's PID 1; they have no
live address space. No live probe child remains. Temporary executables,
configurations, copied draft and logs were removed after testing.

A synthetic, loopback-only Shadowsocks server was a positive control. It passed
the same HTTPS test through the same installed engine and prober, demonstrating
that the diagnostic path itself works on this ARM64 container.

## Results and target sensitivity

An initial HTTPS test to Google's generate-204 endpoint failed through all 17
nodes. This was not sufficient evidence that those nodes were unusable.
The Cloudflare named HTTPS trace succeeded directly and provided the observed
peer address. Through the actual proxy endpoints, 14 of 17 trace checks succeeded,
and all 14 observed peer addresses differed from the verified direct egress.
No raw peer addresses or canonical real node IDs are published here.

| Protocol | Imported | Successful Cloudflare trace |
| --- | ---: | ---: |
| VLESS | 6 | 4 |
| Shadowsocks | 2 | 2 |
| VMess | 2 | 2 |
| TUIC | 2 | 2 |
| Hysteria2 | 3 | 2 |
| Trojan gRPC | 2 | 2 |

The three failed samples reported certificate verification failure, a handshake
failure category and a timeout. These are bounded diagnostic observations, not
a claim that every failure originates at the remote server. Certificate checks
were retained. Changing only the isolated model's bootstrap resolver from
1.1.1.1 to 8.8.8.8 did not fix the sampled failure; both DNS controls answered.

A paired test used the same successful node and the same 12-second timeout.
Google generate-204 failed; Cloudflare generate-204 succeeded in 767 ms. The
fastest successful trace sample was 754 ms. These are single fresh HTTP samples,
not ICMP RTT, steady-state health or an engine selection guarantee.

The draft now contains 17 endpoints and an unbound `auto` URLTest group containing
only the 14 successful nodes. Its target is
`https://cp.cloudflare.com/generate_204`, interval 3 minutes, tolerance 50 ms.
The draft plan validates and reports changed endpoints/groups with
`apply_available: false`. The default DIRECT policy remains in place. The group
will not run periodic checks until a native engine is actually connected.

## Public egress observation and remaining admission work

The implementation supports the existing controlled `remote_ip` JSON response
and an optional HTTPS Cloudflare trace format. The latter bounds the response,
requires exactly one valid peer field, rejects zones/ambiguous data, verifies TLS
and still requires the reviewed expected peer IP for native readiness. Unit and
real local proxy/TLS tests reject a wrong egress address; diagnostics never count
that mismatch as success. This provides an alternative to deploying a dedicated
VPS, subject to endpoint availability and the native profile's address rules.

The literal 1.1.1.1 and 1.0.0.1 HTTPS trace attempts did not succeed on this
network, while the named Cloudflare endpoint did. Native profiles still require
a literal independent canary address. The successful named diagnostic must not
be mistaken for an already provisioned native readiness profile.

Native admission remains incomplete: the production runtime and stopped-install
review still accept only their pinned CHR 7.24.5 x86_64 reference platform. These
gates were not removed to make ARM64 appear ready. A reviewed ARM64 qualification
path, canary/profile provisioning and a LAN packet-path test remain necessary.
Management health and isolated proxy egress do not establish native steering.

Local verification includes the full Go race suite, targeted race tests with the
pinned actual sing-box binary, TLS/peer-format boundary tests, gRPC identity and
rejection regressions, diagnostic redaction and vet. Detailed receipts and the
full protected state backup remain under ignored private local storage.
