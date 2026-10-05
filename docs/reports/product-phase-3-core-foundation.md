# Product Phase 3: core foundation

This is the first generalized core block after the accepted Phase2 controller.
It does not close product Phase3 or replace the earlier bounded CHR evidence.

| Deliverable | Implemented evidence | Remaining acceptance |
| --- | --- | --- |
| Endpoint parser | Four strict MVP URI protocols, stable credential-derived IDs, rename independence, redacted preview, serialized integrity checks | Broader transport variants and modern WireGuard adapter |
| Subscription manager | URI-list/base64 adapters, manual/periodic refresh, include/exclude, private atomic LKG, timestamps/count/failure; bounded DNS-pinned SSRF policy | Backend scheduling and user-facing import workflow |
| Groups | Selector/URLTest generation; fallback selection from fresh observations; validated immutable selection changes | Real health observation and automatic supervised fallback adapter |
| Rules | Deterministic exact/suffix/CIDR/port/network matching, source DIRECT precedence and source PROXY groups | Full rule metadata, remote rule sets and service lists |
| DNS/FakeIP | Typed bootstrap/FakeIP generation, selected AAAA suppression, terminal bound-domain routing before sniff | Generalized integration with finite namespace admission and DNS release gate |
| Generator/validator | Strict schema v2, bounded references/cycles, all four protocols and three modes checked by pinned sing-box1.14.2 | Transparent runtime acceptance for generalized policies |
| Supervisor/LKG | Private revisions, controlled restart, readiness hooks, rollback, backoff and crash-loop detection | Integration with the transparent controller and authenticated diagnostics |

The v1 dataplane generator and existing CHR runtime remain independently
tested. Schema v2 does not expose engine DNS to the LAN or automatically install
TUN routes. Wildcard FakeIP selection is refused until finite admission can
prove it. The existing sing-box cache stays owned by the allocator.

`TestPinnedMixedRuntimeRoutes` exercises two actual sing-box processes and
local HTTP targets. A DIRECT service rule reaches its target without touching
the encrypted endpoint; the default selector reaches another target through
a real Shadowsocks server, counted at a TCP relay. This proves explicit TCP
routing, not generalized RouterOS TUN/UDP/QUIC or public subscription validity.

Subscription tests prove empty/invalid updates retain LKG, rename preserves ID,
private downloads are rejected before connection, size/time/redirect limits
apply, unsafe state files and duplicate keys fail. CLI tests require private
files and reject malformed input without echoing credentials.

`TestPinnedSupervisorLifecycle` runs the actual pinned executable. An invalid
native candidate preserves the active PID and revision. A check-valid candidate
whose socket is occupied fails readiness and restores the working revision.
A valid replacement restarts under a new revision; close/reopen starts the
durable LKG and proves a local HTTP request again. Release observes a committed
journal, and stop closes the fixture gate. Other supervisor tests cover failed
release, crash-loop/backoff, exclusive ownership, private state, revision
integrity/retention and pending startup recovery. These hook fixtures do not
substitute for RouterOS activation proof.

Reproduce with `make check cross-build`. Tests that need the actual binary use
`SING_BOX_BINARY`, supplied by the Makefile. See [the core guide](../core.md)
for private CLI usage and the remaining Phase3 acceptance work.

This intermediate report is superseded by [product Phase 3 completion](product-phase-3-core-completion.md)
for current acceptance status; its earlier open items describe that block only.
