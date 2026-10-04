# Native watchdog experiment plan

Date: 2026-10-04. Status: **PARTIALLY EXECUTED**. This is the original experiment plan; measured
engine/container failure, recovery, eventual boot guard and real-IP comparison are
in [the Phase-1 report](phase-1-dataplane.md). Remaining rows are NOT RUN, and the
scripts are lab recipes rather than a production installer.

## Preconditions and exact RouterOS syntax

Use only the disposable CHR 7.24.5 VM. Save route, NAT, mangle, filter, scheduler
and Netwatch snapshots first. Keep a serial console available. Install the
instance `lab` FakeIP route and two DNS NAT rules disabled; comments must be
`mikrocentauri:lab:route:fakeip`, `mikrocentauri:lab:nat:dns-tcp` and
`mikrocentauri:lab:nat:dns-udp`. Their destination interface/address must match
the lab LAN, not arbitrary client DNS. No source/full-device steering is covered
by this three-object allowlist: add its exact objects before testing that mode.

The probe uses `type=http-get host=172.30.0.2 port=9099 http-codes=200`.
The CLI schema has `http-codes`, not `http-code-min` or `http-path`. Listen on `/`
on the dedicated internal port. Configure `interval=2s timeout=1s
thr-http-time=1s start-delay=1s startup-delay=10s ignore-initial-up=no
ignore-initial-down=no`. The ordinary API port is unsuitable if it survives
engine death. The readiness service must return 503 until the applied generation,
sing-box, DNS listener and forwarding checks pass; false 200 after engine death
is a failed test. An HTTP toggle proves Netwatch mechanics only.

Official references, checked against the supplied local manual snapshot:
[Netwatch CLI](https://manual.mikrotik.com/docs/cli-reference/tool/netwatch/),
[Netwatch behavior and permissions](https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/netwatch/),
[Scheduler CLI](https://manual.mikrotik.com/docs/cli-reference/system/scheduler/).
Netwatch runs as `*sys` with `read,write,test,reboot` ceiling; scripts here request
only `read,write,test`, without disabling permission checks or cross-user globals.

## Router-owned transitions

Import `lab/chr/watchdog.rsc` once. It rejects existing watchdog objects, forces
DIRECT immediately, installs a network-independent startup guard and arms the
HTTP probe. DOWN disables DNS interception before FakeIP steering. UP checks
three unique comments and the expected destination/gateway/DNS generation shape,
then enables steering before interception. Comments and checks are a lab
allowlist, not a cryptographic generation identity or full reconciler.

Use these exact inspection/repair commands on the serial console:

```routeros
/tool/netwatch/print detail where comment="mikrocentauri:lab:netwatch:readiness"
/system/script/print detail where name="mc-lab-down"
/system/script/print detail where name="mc-lab-up"
/system/scheduler/print detail where name="mc-lab-boot-direct"
/ip/route/print detail where comment="mikrocentauri:lab:route:fakeip"
/ip/firewall/nat/print detail where comment="mikrocentauri:lab:nat:dns-tcp"
/ip/firewall/nat/print detail where comment="mikrocentauri:lab:nat:dns-udp"
/tool/netwatch/disable [find where comment="mikrocentauri:lab:netwatch:readiness"]
/system/script/run mc-lab-down
```

For repair, stop Netwatch before forcing DIRECT, so an UP event cannot re-enable
rules. Disable the guard only during documented teardown. Do not flush all
conntrack, change user FastTrack rules, disable WAN NAT or remove unowned rules.

`start-time=startup interval=0s` runs the guard once on each boot. The manual says
startup scripts run early, before interfaces are up; that alone does not prove
ordering against packet forwarding on this CHR. Delay the initial Netwatch probe
to 10s so a ready container does not race the guard. Capture an entire reboot
with previously enabled rules and a stopped container. Record the first rule
disable and first client packet; any interval of selected blackhole before the
guard is a boot failure envelope, not a zero-loss claim. No N-consecutive-failure
hysteresis is implemented in this spike. Configured detection estimate is
interval + timeout + script/scheduling time; report measured maxima under load.

## Measured failure matrix

Run repeated requests with new sockets, plus one preexisting long connection.
For each injection record wall clock and monotonic timestamps, HTTP code/status,
Netwatch status and `since`, owned disabled flags, DNS answer/TTL, client result,
egress/source packet captures and unrelated configuration diff. Keep captures
on the client and WAN/VETH sides running across the transition.

| Injection | Native expected transition | Client observations required |
| --- | --- | --- |
| Readiness returns 503 with process alive | DOWN, three objects disabled | Fresh DNS and real-IP DIRECT continue; synthetic cache tracked separately |
| Stop entire container | DOWN independent of container | Ordinary/direct client survives; fresh selected DNS becomes real |
| Kill sing-box, keep API running | Readiness 503 then DOWN | Reject false readiness; no persistent selected route blackhole |
| Block DNS upstream/listener | Readiness 503 then DOWN | Separate DNS request timeout from routing recovery |
| Disconnect container VETH | HTTP timeout then DOWN | Record failed probe duration and first successful new direct connection |
| Restart container and engine | 503 until validated, then UP | Source retention and selected egress restored; unrelated DIRECT unchanged |
| Reboot CHR with rules enabled and container stopped | Guard DIRECT, initial DOWN executes | Record boot ordering and first reachable LAN/WAN packet |
| Remove or duplicate an expected owned object | UP refused, DIRECT maintained | No partial DNS interception or unintended object activation |
| Repeated 200/503 flaps and CPU load | Repeated native events | Measured maximum outage, scheduler delay and rule consistency |

DNS DNAT applies to the first packet in a connection. Existing tracked UDP/TCP
DNS sessions can retain an old translation after the NAT rule is disabled.
Test both the same client source port and a fresh port. Capture persistence until
natural expiration; a targeted lab connection removal is a separate experiment,
not evidence that toggling rules alone fixes existing sessions.

## Cached FakeIP is a separate, expected limitation

Prime `selected.test` through the gateway; save the synthetic answer and TTL.
Connect once, crash the engine, then retry both (a) the saved synthetic address
without resolution and (b) the domain after obtaining a fresh real DNS answer.
Repeat before and after TTL expiry, including a client that deliberately retains
the answer. The first case remains unroutable when FakeIP steering is removed.
A router DNS cache flush cannot invalidate client/application caches. Existing
proxy connections need reconnect. Persistent sing-box mappings help engine
restart, not direct recovery while the engine is dead.

An independent translator with a retained FakeIP-to-domain map and real DNS could
potentially forward cached synthetic flows while the proxy is dead, but it is an
additional surviving dataplane requiring own routing/NAT/state and readiness
proof. Do not describe the current Netwatch design as such a translator.

## Real-IP alternative experiment

RouterOS can return real DNS answers and create a dynamic destination list from
a static FWD entry. Example lab recipe, **TESTED for selected IPv4 HTTP/QUIC**, with no `forward-to` means
normal router DNS servers are used:

```routeros
/ip/dns/static/add name=selected.test type=FWD address-list=mc-lab-domains match-subdomain=no comment="mikrocentauri:lab:dns:selected"
```

Configure a real lab upstream containing `selected.test`; do not rely on a public
resolver for this private name. Inspect `/ip/firewall/address-list/print detail
where list="mc-lab-domains"` and query UDP/TCP A/AAAA. Steer the list through a
dedicated policy table or explicit mangle rule with exact owned comments; disable
that steering on DOWN, retain ordinary router DNS and WAN forwarding. Keep LAN,
router, proxy endpoint and gateway sources explicitly excluded before steering.
The watchdog above must be extended to the new exact route/mangle allowlist first.

Because cached addresses are real, new sockets can use WAN after routing marks
are removed; verify this on packets instead of assuming it. Shared CDN IPs can
overselect unrelated names. DNS bypass, CNAME chains, HTTPS/SVCB additional
records, list TTL expiry, DNS caching, source-specific policy and IPv6 remain
separate gates. Named forwarder groups round-robin and do not skip unhealthy
servers: adding a second resolver is not evidence of failover. Compare cached
selected recovery and unselected cohost traffic against FakeIP before choosing
an architecture. See [DNS static CLI](https://manual.mikrotik.com/docs/cli-reference/ip/dns/static/)
and [DNS forwarders CLI](https://manual.mikrotik.com/docs/cli-reference/ip/dns/forwarders/).

Acceptance requires real CHR captures, measured timing, and no unowned mutation.
Do not promote this document from NOT RUN based on a successful import alone.
