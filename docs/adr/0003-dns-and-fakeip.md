# ADR-0003: DNS selection spike

Status: PROPOSED; local DNS behavior TESTED, RouterOS DNS path NOT RUN.

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
