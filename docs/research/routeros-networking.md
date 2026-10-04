# RouterOS networking research

Research date: 2026-10-04. Product: MikroCentauri. Evidence labels: **CONFIRMED** means official documentation or release notes; **TESTED** requires a local execution artifact; **ASSUMED** is a design inference; **TODO** requires a RouterOS lab. This document contains no claim that a RouterOS dataplane was executed.

## Version and capability boundaries

**CONFIRMED:** the official [stable changelog index](https://mikrotik.com/download/changelogs?channelFilter=stable) lists RouterOS **7.24.5**, released 2026-10-01, as latest stable at research time. Custom `/app` begins at 7.22. Keep the requested 7.22 minimum as an installation target, but discover actual capabilities instead of assuming the current manual describes every older release.

| Capability | Official evidence | Consequence |
| --- | --- | --- |
| Custom app YAML | [Apps](https://manual.mikrotik.com/docs/containers/apps/) says 7.22 | Minimum packaging target 7.22 |
| Container healthcheck | [Container](https://manual.mikrotik.com/docs/containers/) says introduced 7.23 | Fail-open on 7.22 must use RouterOS Netwatch, not container healthcheck |
| `/dev/net/tun` | Current Container manual lists it among active `/dev` nodes | TUN is a real candidate; saying RouterOS has no TUN is incorrect |
| TUN permissions changed | [Official 7.23 announcement](https://forum.mikrotik.com/t/v7-23-stable-is-released/270721) includes updated `/dev/net/tun` permissions | Probe 7.22 separately; do not assume identical behavior |
| `privileged` container setting | [Official 7.24 announcement](https://forum.mikrotik.com/t/7-24-stable-is-released/272381), plus [Container CLI](https://manual.mikrotik.com/docs/cli-reference/container/) | Added 7.24; no demonstrated need to enable it for this product |

The release announcement is an official vendor changelog posted by MikroTik staff, rather than a community workaround. The human-readable Container property table and `/app` service schema do not describe `privileged` semantics or a `cap_add: NET_ADMIN` field. Neither listing the TUN node nor setting `user=0:0` proves `TUNSETIFF`, route changes, forwarding, or packet interception will succeed. **TODO:** inspect effective capabilities and execute a TUN creation probe without privileges first; only test privileged mode as a separate 7.24+ experiment. Do not default a network controller with RouterOS credentials to privileged execution.

## Dataplane candidates

### A: VETH gateway plus TUN

**ASSUMED, not proven:** RouterOS marks selected LAN packets, resolves a managed table's default route through a dedicated VETH-connected container, and the container uses sing-box TUN to consume forwarded IP packets. Unselected packets stay in RouterOS `main`. RouterOS sees the real LAN source IP at the selection point; preserving it into TUN would enable source-IP routing within sing-box.

The VETH itself is an Ethernet endpoint, not a transparent proxy. Merely adding a route to a sing-box container does not feed packets into a socket-based inbound. The prototype must prove the container route to TUN, required forwarding/sysctls, outbound exclusions, and reply path. `auto_route` and a Linux privileged Docker test do not prove RouterOS behavior. Avoid a blanket default route that sends sing-box's own outbound sockets back into its ingress.

### B: RouterOS Socksify plus sing-box SOCKS

**CONFIRMED:** [Socksify](https://manual.mikrotik.com/docs/network-management/socks/socksify/) implements firewall NAT `action=socksify`, relaying original destinations to an upstream SOCKS5 server. [CLI](https://manual.mikrotik.com/docs/cli-reference/ip/socksify/) documents a local **TCP** service port (default 952) and an IPv4 SOCKS server (default upstream port 1080). This offers a candidate TCP ingress without a container TUN or Linux interception firewall.

Required constraints:

- Scope the NAT selector to managed LAN clients/destinations and `dst-address-type=!local`; exclude local networks, router management, proxy endpoints, and the container.
- The intercepted connection arrives at the RouterOS input service. An appropriate narrowly scoped input accept rule is necessary; a forward rule alone is insufficient.
- The service rejects RFC1918 original destinations. The upstream address must be IPv4; this does not establish IPv6 client support.
- New Socksify records start disabled; changed properties take effect after disable/enable.
- SOCKS credentials are documented as plaintext in detail output. Redact them regardless of RouterOS sensitive-policy expectations.
- The official interface supplies no original-client identity field. **ASSUMED:** sing-box observes RouterOS as SOCKS peer, so per-client selection must happen before Socksify. Separate listeners/services can convey policy groups, but per-client sing-box `source_ip_cidr` must not be promised.
- **TODO:** verify TCP SOCKS CONNECT and actual original destination in packet captures. UDP ASSOCIATE/QUIC is not documented for Socksify and is outside this candidate's demonstrated scope.

Socksify cannot honestly satisfy a complete UDP/full-device tunnel MVP unless a second proven path is added. Its use as a bounded TCP prototype is valuable even if A ultimately wins.

### C: container-side REDIRECT/TPROXY

**TODO:** requires available Linux netfilter modules, capabilities, and policy routing. RouterOS destination-NAT to a sing-box redirect listener does not by itself preserve the original destination in the container's conntrack namespace. Do not mistake the router's NAT metadata for Linux `SO_ORIGINAL_DST` inside a different host/netns. A sidecar using kernel interception is not an OpenWrt emulator, but adds a second firewall and is less attractive than proven TUN or native Socksify.

## VETH and routing

**CONFIRMED:** [VETH](https://manual.mikrotik.com/docs/containers/veth/) applies `address`, `gateway`, and DHCP inside the container; router gateway addressing is separate. The interface is not running until its container starts. Use an isolated subnet and a stable explicit address for the dataplane prototype. Apps automatically create VETH and network configuration; their inferred addresses must be discovered rather than hardcoded.

**CONFIRMED:** [Policy routing](https://manual.mikrotik.com/docs/user-guides/routing-and-networking-protocols/policy-routing/) requires creation of a named `/routing/table` before use; custom next hops can resolve with `gateway=<address>@main`. Mangle normally has precedence over routing rules. `lookup-only-in-table` prevents fallback; `lookup` permits fallback when lookup fails. However, a running VETH and reachable container IP do not prove sing-box health, so gateway checking alone cannot guarantee fail-open.

**ASSUMED:** own one table, a small owned mangle chain and a parent hook restricted to LAN ingress. Exclude router-local, connected/private destinations, VETH ingress, and controller/proxy egress before selection. Do not overwrite existing user connection marks or default routes. Reject or report conflicting pre-existing policy routing instead of silently replacing it.

## FastTrack, NAT, and established connections

**CONFIRMED:** [Packet flow / FastTrack](https://manual.mikrotik.com/docs/firewall-and-quality-of-service/packet-flow-in-routeros/#fasttrack) says FastTrack only processes the main routing table and bypasses firewall/VRF assignment and other facilities. Selected connections must not match existing FastTrack rules. Existing DIRECT connections may already be fasttracked when a destination policy changes.

**ASSUMED:** prefer an owned accept rule for established/related managed connections before user FastTrack, scoped to the owned connection mark and optionally container interface. This preserves DIRECT FastTrack, but needs semantic review of the user's filter chain. Adding a rule after an existing broad FastTrack is ineffective. Do not blindly disable every FastTrack rule or rely on mangle observing every fasttracked packet.

**CONFIRMED:** [NAT](https://manual.mikrotik.com/docs/firewall-and-quality-of-service/firewall/nat/) selects the action on the first packet, then connection tracking retains it. Disabling NAT does not migrate already intercepted TCP streams to DIRECT. **ASSUMED:** the watchdog may remove only owned marked conntrack entries, if ownership and permissions are validated, to make applications reconnect through DIRECT. Never globally clear connection tracking on a live user router. Fail-open means new/retried real-IP connections recover within a measured interval; continuity of an established proxy stream is not achievable by changing routing alone.

## DNS selection and fail-open

**CONFIRMED:** [DNS](https://manual.mikrotik.com/docs/network-management/dns/) supports static `type=FWD`, `match-subdomain=yes`, and `address-list`. An FWD record without `forward-to` uses normal upstream DNS; answered addresses enter the named dynamic firewall list until answer TTL plus `address-list-extra-time`. The current manual notes router-originated `:resolve` does not populate this list. This is a useful native real-IP selection primitive:

```routeros
/ip/dns/static/add name=selected.example type=FWD match-subdomain=yes address-list=mc-selected comment="mc:<installation>:dns:<rule>"
```

This illustrative command is not installation-tested. It leaves DNS resolution on RouterOS and avoids making the application's DNS necessary for ordinary internet access.

**ASSUMED limitations:** shared CDN IPs cause collateral routing; encrypted DNS and externally cached answers bypass learning; IP literals have no domain identity. Scope lists by policy/device when necessary, but a shared IP still cannot distinguish two names on the same address. RouterOS FWD-to-container loses the original DNS client identity. Do not advertise exact per-device domain enforcement from DNS address lists alone.

**CONFIRMED:** current named DNS forwarders round-robin and do not skip an unhealthy server; DoH does not fall back to plain `servers` when it fails. Therefore adding a fallback server to a list is not sufficient evidence of DNS fail-open.

**ASSUMED:** start with real DNS answers for the first fail-open prototype. FakeIP (`198.18.0.0/15`) cached by clients cannot reach a real internet destination after application death; disabling interception does not repair those cached synthetic addresses. DNS fail-open must explicitly address router and client caches and established connections. Container DNS upstream must not point into an interception rule that loops queries back to itself.

## Netwatch watchdog

**CONFIRMED:** [Netwatch](https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/netwatch/) executes on RouterOS independently of the container and supports TCP and HTTP probes. It runs as `*sys` and allows only `read,write,test,reboot` script policies; globals do not form shared state with user/scheduler scripts. Do not disable permission checks as a workaround.

**CONFIRMED:** [Netwatch CLI](https://manual.mikrotik.com/docs/cli-reference/tool/netwatch/) defaults `startup-delay` to **5m**, `start-delay` to 3s, `interval` to 10s, timeout to 3s, and accepts HTTP codes 100–299. The current schema has no `http-path` parameter. A `/ready` endpoint cannot be selected by an invented property. Expose a dedicated watchdog port whose root returns 200 only when the applied generation and dataplane are ready, and 503 otherwise; accept only 200. TCP liveness alone misses a dead sing-box under a healthy API.

**ASSUMED desired sequence:** boot in DIRECT, arm RouterOS watchdog before enabling selection, install staged generation, validate sing-box, enable steering only after readiness, and on probe failure disable owned steering/DNS interception. Keep Netwatch enabled during death of the entire container. Explicitly configure startup delay and initial-down behavior. Measure worst-case detection as interval + timeout + script execution/scheduling under load, rather than claiming a guarantee from configured seconds alone. Test both API death and sing-box death, plus reboot with persisted enabled rules.

## REST and ownership

**CONFIRMED:** [REST API](https://manual.mikrotik.com/docs/developer-guides/rest-api/) is an authenticated CLI wrapper. The current manual requires both **`api` and `rest-api`** policies plus `read`/`write` for reconciliation. Use a dedicated user; add `test` only if needed. Do not default to the broad built-in `full` group. RouterOS permissions are coarse; a comment namespace is controller discipline, not a RouterOS authorization boundary.

Verify HTTPS certificates; restrict the user's source address and service/firewall access to the control subnet. Never expose REST to WAN or put its credentials in frontend state. Current docs use `available-from` and `/ip/service/webserver rest-plain=no`; 7.24 release notes say service `address` was renamed to `available-from`. Discover the correct version syntax for 7.22 rather than copying current onboarding commands.

RouterOS REST has string-valued scalars, list and singleton responses, `.id` identities, and POST console commands. Persist installation ID and use exact ownership comments such as `mikrocentauri:<installation>:<kind>:<key>`. Never fuzzy-match `comment~"mikrocentauri"`. Apply with an explicit operation journal and rollback snapshots: the documentation does not promise a transaction spanning multiple requests. Concurrent user edits and rule order must be detected before destructive updates.

**CONFIRMED version caution:** the [documentation changelog](https://manual.mikrotik.com/changelog/) says the REST page was rewritten and examples verified on **7.25** on 2026-09-28. Current behavior documented for singleton `POST .../set`, a 60-second request limit, one concurrent request per user, and a 10-minute login cache therefore needs compatibility tests on stable 7.24.5 and minimum 7.22. Requests should always send `Content-Type: application/json`; avoid long streaming commands in reconciliation and do not assume a revoked account instantly invalidates a cached login.

## Hardware, storage, and lab gates

**CONFIRMED:** Apps requires container package and device-mode container enablement (physical confirmation), arm64/x86 support, and sufficient external storage/RAM. Container and Apps manuals have broader architecture lists in some schemas/examples; product support remains linux/arm64 and linux/amd64, mapped to RouterOS arm64 and x86. Do not assume every MikroTik model supports containers; Apps specifically excludes EN7562CT devices.

**TODO before release:** CHR 7.24.5 and a 7.22 compatibility instance; isolated LAN client, direct egress and controlled proxy egress; VETH capture; TUN creation/capability results; TCP/UDP/QUIC checks; FastTrack counter checks; controller/sing-box crash tests; DNS cache behavior; reboot recovery; owned cleanup with unrelated sentinel rules; actual hardware tests for arm64. CHR results establish functionality, not hardware throughput.

Primary aggregate consulted: [RouterOS full manual](https://manual.mikrotik.com/llms-full.txt), fetched locally during research. The live manual has no historical snapshot guarantee; release-specific claims above are separated accordingly.
