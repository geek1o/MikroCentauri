# Phase 1: RouterOS transparent dataplane experiments

Executed 2026-10-04 UTC / 2026-10-05 Moscow. Functional lab complete for the
scopes below; **production dataplane/fail-open acceptance remains OPEN**.
The results are actual CHR traffic, not sing-box schema checks or mock results.

## Environment and evidence

Official CHR 7.24.5, separate container package, x86 QEMU TCG on macOS arm64.
CHR: 512MiB / 2 emulated CPUs, free license. Each Alpine 3.24.2 client/server VM:
512MiB / 1 emulated CPU, Linux 6.18.52-0-virt, independent Ethernet NICs.
sing-box 1.14.2 Linux amd64 **musl static** binary; ordinary Linux amd64 release
requires a dynamic glibc loader and is unsuitable for this Alpine rootfs.
Go 1.27.1; isolated HTTP/3 module quic-go 0.63.0. Asset hashes live in
`lab/linux/assets.lock.json`; dependency sums live in `lab/quic/go.sum`.

Management/control forwards bind localhost. No production router, user
subscription or external proxy was used. Public UUID/password/certificate fixtures
are intentionally disposable. TEST-NET address 203.0.113.20 stays inside the lab.
All image, package, PCAP, and downloaded binaries stay in ignored `.cache`.

Client 192.168.88.10 → CHR LAN192.168.88.1 → gatewayVETH172.30.0.2/TUNmc-tun.
Proxy server10.77.0.10:8443 and target/DNS10.77.0.20 share one Linux VM, separate
from client and CHR. Their mutual .10 → .20 delivery is local to that VM and is
not visible on its Ethernet capture. WAN captures instead show the VLESS transport;
HTTP/3 and HTTP targets explicitly report the final observed peer address.
Target returns observed peer IP. Native DIRECT uses CHR WAN10.77.0.1; VLESS target
connections originate from10.77.0.10. Additional client aliases .20 and .30 verify
source-based policy. LAN and WAN switch captures accompany engine source logs.

Small sanitized results: [evidence directory](dataplane-evidence/).
[Capture summaries/hashes](dataplane-evidence/captures.json) reference retained
local PCAP, not redistributed packet payloads. Engine path excerpts accompany them.
Initial tested gateway archive SHA256:
`ca460d9a601aafdac93e71e1df6c94daaf14dc6e433387571f39cfe98165bcdb`.
Reproducible rebuilt image uses `-buildvcs=false`, with SHA256
`b75227480c3d6e5d97ba5c3d5f190474805997e8e1b1456e3dd9b33c4d03e8b2`;
this rebuilt archive was not independently imported as a new container generation.

## Packet-path results

| Experiment | Actual observation | Scope |
| --- | --- | --- |
| A hybrid DIRECT | unselected.test resolves real10.77.0.20; target peer10.77.0.1 | Native RouterOS path |
| A selected TCP | selected.test resolves198.18.0.2; target peer10.77.0.10 | Transparent TUN → VLESS |
| A selected UDP | Payload echo succeeds; marker appears in WAN VLESS TCP8443 | UDP over VLESS |
| A selected QUIC | HTTP/3.0, verified fixture TLS name, peer10.77.0.10 | No HTTP/1 or HTTP/2 fallback |
| Native QUIC | HTTP/3.0, peer10.77.0.1 | DIRECT comparison |
| Source retention | TUN logs source192.168.88.10 and192.168.88.20 | No source masquerade before ingress |
| Source PROXY | unselected destination from .20 → peer10.77.0.10 | Fixture destination steered to TUN |
| Source DIRECT priority | selected FakeIP from .30 → peer10.77.0.1 | DIRECT beats selected-domain policy |
| B full gateway | Unselected target enters TUN then DIRECT; selected target uses VLESS | All fixture destinations, not arbitrary LAN internet |
| C native Socksify | Original203.0.113.20:8080 → SOCKS → VLESS peer10.77.0.10 | TCP only; gateway peer is router172.30.0.1 |
| FastTrack | Selected conn marked, fasttrack=false; unselected native conn fasttrack=true | Managed exception precedes enabled user fixture |
| RouterOS DNS | LAN keeps DNS192.168.88.1; managed UDP/TCP redirected to5353 | Exact selected A and AAAA behavior |
| Outbound isolation | Gateway-originated VLESS/DNS sockets use main; completed captured requests | No loop observed in these cases; not exhaustive proof |

Source .20 steering is deliberately limited to the test destination. This does
not establish a complete full-device internet tunnel, IPv6 enforcement, device-domain
matrix, or broad routing exclusions. C cannot retain sing-box source identity and
has no proven native UDP/QUIC ingress. Its RFC1918 destination restriction required
a locally connected TEST-NET target for a fair TCP comparison.

## Native failure and recovery

The gateway readiness listener checks child/config startup, TUN, ingress setup,
and an actual selected DNS query. Native Netwatch probes HTTP root9099 every2s,
timeout1s. It runs read/write/test scripts independent of the container. UP validates
unique comments and route/NAT shapes; DOWN disables exactly three owned objects.
These are lab generations, not a persistent transactional controller.

| Injection | Observed transition including 1s settling allowance | Client outcome |
| --- | --- | --- |
| Kill sing-box, keep gateway HTTP alive | DOWN2.779s | Fresh selected DNS and ordinary DIRECT succeed |
| Restart sing-box | UP2.886s | Selected VLESS restored |
| Stop whole container | DOWN1.982s | Fresh selected DNS and ordinary DIRECT succeed |
| Restart container | UP4.965s | Selected VLESS restored |
| Saved FakeIP after either stop | TCP timeout about5s | **Cached synthetic destination fails** |
| Real-IP alternative engine stop | DOWN3.013s | Saved real destination and fresh DNS DIRECT succeed |
| Real-IP alternative engine restart | UP2.045s | Selected HTTP VLESS restored |
| Stop external VLESS service | Gateway ready=true; Netwatch staysUP | Selected request fails with EOF |

These are single-run observations, with REST polling overhead and explicit1s
settling allowance. They are not a worst-case outage bound, hysteresis, or measured
first-client-success clock. Existing NAT/conntrack sessions and application DNS
caches can outlive rule changes. Unrelated filter/mangle configuration remained
unchanged during the failure run. Remote-proxy availability still needs independent
health/fallback semantics; local DNS/process readiness does not establish it.

Reboot test deliberately persisted enabled real-IP route/mangle with stopped
gateway and **Netwatch disabled**, isolating the startup guard. First successful
REST observation at uptime12s showed both disabled; native selected DNS/HTTP then
worked DIRECT. It took5039ms for that first client request. Logs confirm both
startup scripts ran. This establishes eventual boot repair, **not guard-before-first-
forwarded-packet or zero-loss reboot ordering**. See `reboot.json` for the boundary.

## Real-IP alternative

A RouterOS static FWD record populated a dynamic destination list from native
DNS. Listed addresses entered the TUN; HTTP Host/QUIC sniffing recovered selected
names. The shared-IP HTTP cohost remained DIRECT inside the gateway, but still
entered it. Source .30 DIRECT priority held. Engine stop restored even the cached
real address. These are material improvements to the cached-destination failure.

The selected generic UDP marker was captured as native10.77.0.1 → target9000,
not proxy-server10.77.0.10 → target, despite fresh DNS selection. This demonstrates
a policy miss in the real-IP candidate, not merely a speculative limitation.
They do not establish equivalent policy: generic UDP has no reliable selected name,
client caches can outlive the router's dynamic address list, and shared CDN IPs/ECH
complicate selection. A QUIC request made after list expiry bypassed proxy; immediate
DNS refresh restored proxy. No architecture is silently switched on that evidence.
See [ADR-0009](../adr/0009-realip-alternative.md).

## Transfer diagnostics

Three fully read256KiB HTTP transfers per mode, after one warmup. Time includes
DNS, connection setup and response consumption; all received-byte counts checked.

| Mode | Median total ms | Median end-to-end Mbit/s |
| --- | ---: | ---: |
| Native DIRECT | 2193 | 0.956 |
| Hybrid DIRECT | 2195 | 0.955 |
| Hybrid PROXY | 2393 | 0.876 |
| Full fixture DIRECT | 2286 | 0.917 |
| Full fixture PROXY | 2350 | 0.892 |

The CHR license was live-verified as `level=free`; MikroTik documents a1Mbit/s
upload limit per interface. [Official CHR licensing](https://help.mikrotik.com/docs/spaces/ROS/pages/18350234/Cloud+Hosted+Router+CHR).
TCG emulation and that ceiling dominate these numbers. They cannot rank hardware
throughput or justify a production performance claim. Pre-transfer CPU snapshots
and free memory are recorded, not peak CPU/RSS or sustained-load measurements.
An initial1MiB run hit the12s client deadline on one proxy transfer; it was not
counted as a successful benchmark. No packet-loss benchmark was performed.

## Practical findings

Container root with **privileged=no** created TUN and programmed ingress routes.
RouterOS preserves VETH name mc-probe inside the container. Local table has priority
200, not conventional Linux0; ingress priority100 incorrectly caught local packets.
The lab now uses priority10000, after local and before main2147483646. Its deletion
matches priority + iif + table, so it does not broadly delete an unrelated rule.

TUNSETOFFLOAD returned EINVAL, while functional TCP/UDP/QUIC succeeded. It remains
a performance/capability note, not a reason to enable privileged mode. QEMU socket
NICs need a listening switch before launch; both runners now check it. Fresh RAM-
root VMs need virtio-rng for timely cryptographic startup; control-NIC IPv6 is
disabled to prevent a QEMU RA default route from bypassing the test LAN. The runtime stack showed
vgetrandom during entropy starvation. File replacement via RouterOS fetch discarded
execute permission; updated images use fresh roots rather than overwriting binaries.
RouterOS stops containers asynchronously. Dynamic DHCP DNS was explicitly disabled
so private fixture names never queried an unintended resolver.

## Decision and next work

Choose hybrid source-preserving TUN as the **proven transport hypothesis** for
continued controller work. Do not accept the complete FakeIP fail-open product
contract yet. Full gateway increases the failure/performance surface; Socksify
remains a limited TCP alternative. Real-IP selection remains an explicit comparison.

Next: resolve cached-address fallback, proxy health and debounce; implement durable
controller/generation reconciliation and supervisor/LKG; expand reboot-ordering,
DNS/conntrack, IPv6, per-device policies and ARM64/version acceptance. Frontend polish,
release packaging and production activation remain gated. User resources will help
later with real TLS/Reality subscriptions and native/ARM64 benchmarks; they were not
needed to establish this lab result.
