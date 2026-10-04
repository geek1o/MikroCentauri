# ADR-0003: DNS selection spike

Status: DNS/TUN LAB PATH TESTED; FAIL-OPEN/DNS POLICY ACCEPTANCE OPEN.

Pin sing-box 1.14.2 typed UDP bootstrap and typed FakeIP DNS server. Selected exact
A domains use FakeIP 198.18/15 with TTL 30; selected exact AAAA gets NOERROR/empty.
Other names keep real upstream responses. Preserve FakeIP cache in private persistent
storage. Config validates the spike range and local addresses; collision discovery
against complete router state is still required.

Container upstream uses explicit bootstrap resolver, not intercepted RouterOS DNS.
DNAT must preserve source identity and cover TCP/UDP53; interception is scoped to
LAN/router DNS only. No source masquerade or DoH MITM. Client custom DoH/DoT is outside
this DNS policy. AAAA suppression is a mitigation, not complete IPv6 policy enforcement.

Device DIRECT priority is applied before full-proxy then selected domain rules.
FakeIP mappings must recover domains at ingress before source/destination policy
can be relied on; macOS explicit proxy tests do not establish TUN behavior.
Socksify comparison uses real DNS because it lacks domain restoration.

Failure semantics and potential real-IP alternative are governed by ADR-0002.

CHR 7.24.5 now proves transparent selected A over LAN RouterOS DNS and FakeIP
domain restoration at TUN ingress for TCP/UDP/QUIC. DIRECT source .30 wins over
selected-domain policy. Cached synthetic addresses fail during engine/container
absence; real-IP RouterOS FWD alternative is measured in ADR-0009. IPv6 enforcement,
complex source-domain DNS policies and existing conntrack sessions remain gates.


Phase 3 retains the engine allocator behind a loopback DNS listener and gates
selected A publication on durable router-map verification. Native fallback now
handles three pinned aliases after container loss; the earlier failure above is
Phase-1 history. See [ADR-0011](0011-dynamic-dns-publication.md) and
[Phase-3 report](../reports/phase-3-publication.md). General cache lifecycle remains open.
