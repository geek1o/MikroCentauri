# sing-box research for MikroCentauri

Baseline date: 2026-10-04. Research is pinned to **sing-box 1.14.2**, not to the moving documentation website.

Status vocabulary: **CONFIRMED** = version-pinned official documentation/source; **TESTED** = experiment performed here; **ASSUMED** = proposed behavior awaiting the target lab; **TODO** = required experiment or implementation.

## Version and provenance

**CONFIRMED**: GitHub `releases/latest` returned `v1.14.2`, published 2026-09-24T11:47:08Z. Its tag points directly to commit `af6e64c3b69e6132ebaee0e1a3d24e93903f6709`. The macOS ARM64 release archive advertises SHA-256 `925c5382eca8492b0150f868a6db20b18290a38700e621724b3703fd453e032d`; the downloaded bytes matched it. Its executable reports the same version and revision.

Sources: [release](https://github.com/SagerNet/sing-box/releases/tag/v1.14.2), [latest API](https://api.github.com/repos/SagerNet/sing-box/releases/latest), [tag API](https://api.github.com/repos/SagerNet/sing-box/git/ref/tags/v1.14.2).

The public configuration pages already describe future 1.15 changes. In particular, do not generate `auto_redirect_tproxy_mark`, `multi_queue`, or future stack behavior from the moving site. Use the [version-pinned docs tree](https://github.com/SagerNet/sing-box/tree/v1.14.2/docs/configuration) and test with the exact packaged executable. The macOS binary tested here is not evidence for Linux container kernel features.

## Critical dataplane boundary

A container VETH receives Ethernet frames carrying the original remote destination. An ordinary application TCP/UDP listener cannot consume arbitrary forwarded traffic solely because RouterOS routes it to the VETH. There must be an ingress mechanism that converts original destination traffic into sing-box connection metadata.

| Candidate | Requirements and behavior | Decision |
|---|---|---|
| TUN | An available TUN device and permission to open/configure it; routing into it; `auto_route` and `auto_redirect` additionally modify Linux routes/netfilter | **TODO**: capability probe on RouterOS; never assume from an image containing sing-box |
| `redirect` | TCP only; local OS original-destination lookup after local interception | **CONFIRMED** source; RouterOS remote DNAT alone is unsuitable |
| `tproxy` | Linux transparent sockets, policy routing/local route, interception rules, and original-destination metadata; handles TCP and UDP | **TODO**: prove supported inside RouterOS container; configuring listener alone is insufficient |
| Explicit SOCKS/HTTP | Client supplies original destination; normal sockets | Useful executable smoke test, but not transparent LAN routing |
| AF_PACKET userspace gateway | Raw packet socket privileges, ARP/Ethernet handling, IP/TCP/UDP stack, original source/destination preservation, connection and UDP mapping integration | **ASSUMED** separate gateway/fork; not an existing stock sing-box inbound |

**CONFIRMED**: stock [inbound documentation](https://github.com/SagerNet/sing-box/tree/v1.14.2/docs/configuration/inbound) does not expose AF_PACKET/Ethernet/VETH ingress. `stack: gvisor` selects the TCP/IP implementation behind the TUN interface; it does not turn VETH into a TUN device or remove the TUN boundary. A custom userspace gateway is real additional engineering, not a JSON generator feature.

**CONFIRMED**: [redirect implementation](https://github.com/SagerNet/sing-box/blob/v1.14.2/protocol/redirect/redirect.go) opens TCP only and obtains destination through [SO_ORIGINAL_DST](https://github.com/SagerNet/sing-box/blob/v1.14.2/common/redir/redir_linux.go). **Inference from source**: original destination stored in RouterOS conntrack is not exported into container Linux conntrack. Remote DNAT into a redirect listener therefore cannot reconstruct arbitrary original destinations; TLS sniffing cannot recover destination ports or support arbitrary non-TLS protocols reliably.

**CONFIRMED**: [TPROXY socket implementation](https://github.com/SagerNet/sing-box/blob/v1.14.2/common/redir/tproxy_linux.go) requests `IP_TRANSPARENT`, and UDP requests original-destination ancillary data. [The inbound](https://github.com/SagerNet/sing-box/blob/v1.14.2/protocol/redirect/tproxy.go) uses local socket address for TCP destination and ancillary metadata for UDP. These socket settings plus interception/policy-routing must work in the actual container. No RouterOS runtime capability was tested by this research.

**CONFIRMED**: TUN `auto_redirect` uses Linux nftables and `auto_route`; pre-match additionally requires kernel NFQueue support. [Pinned TUN docs](https://github.com/SagerNet/sing-box/blob/v1.14.2/docs/configuration/inbound/tun.md). RouterOS owns its firewall independently; do not transplant nftables/fw4 assumptions.

Recommended ADR candidate: keep transparent ingress capability-gated. Prototype stock TUN/TPROXY only after probing the real RouterOS environment. Keep a packet-preserving userspace adapter as a separately scoped research candidate. Do not advertise transparent UDP or full-device tunnel before captures prove them.

## DNS and FakeIP

**CONFIRMED**: modern FakeIP is a typed DNS server, e.g. `{ "type": "fakeip", "tag": "fakeip", "inet4_range": "198.18.0.0/15" }`; the old `dns.fakeip` object/legacy address transport should not be emitted. [Pinned FakeIP docs](https://github.com/SagerNet/sing-box/blob/v1.14.2/docs/configuration/dns/server/fakeip.md).

A `direct` inbound on a managed DNS address/port plus a route `hijack-dns` action is a useful ordinary-socket DNS entry point. It is not a general transparent proxy inbound. It supports TCP and UDP without an explicit `network` restriction. Bind the prototype to loopback; deployment may bind the VETH address with RouterOS access control. RouterOS DNS DNAT can target this known DNS service because original remote DNS destination is not needed for the managed resolver.

**TESTED**: the example below passed `sing-box check` and ran on macOS ARM64. A raw UDP A query for `example.com` to `127.0.0.1:5354` returned NOERROR, one answer, `198.18.0.2`. Runtime logs show `inbound/direct[dns-in]` and the FakeIP answer. This proves DNS treatment, not RouterOS selected packet interception or VLESS egress.

The selective model is: selected A records receive synthetic addresses; RouterOS routes only the synthetic range and full-proxy sources into the capable ingress. Unselected destinations keep real IPs and RouterOS DIRECT routing. IPv6/AAAA/HTTPS/SVCB require an explicit policy; silently allowing AAAA while only steering IPv4 creates bypass. An IPv4-only first milestone must explicitly bound IPv6 support instead of claiming parity.

Use domain rules before unconditional FakeIP treatment. Internal endpoint/bootstrap DNS must target a real DNS server via `domain_resolver`; otherwise an endpoint hostname can receive a synthetic address and recurse into the proxy. A DNS `query_type` filter prevents trying to use FakeIP for unsupported record types. Selected HTTPS/SVCB handling and ECH behavior need lab tests.

Persistent FakeIP mapping belongs in `experimental.cache_file` with `enabled`, stable `path`, and `store_fakeip: true`. Mapping is data, not disposable config: retain it across ordinary restarts. Persistent mappings make recovery more predictable but do not provide fail-open while the engine is dead. [Cache docs](https://github.com/SagerNet/sing-box/blob/v1.14.2/docs/configuration/experimental/cache-file.md).

**Critical fail-open limit**: disabling steering does not make `198.18.0.0/15` destinations publicly routable. Existing client DNS caches and existing flows to synthetic addresses cannot automatically go DIRECT on WAN after engine failure. DNS fallback must restore real answers; short synthetic TTL bounds some cache persistence but does not guarantee applications honor TTL or re-resolve immediately. A claim that all cached selected flows instantly become DIRECT would be false. The lab must separately prove unselected internet continuity and selected-domain recovery, recording TTL, client retry, conntrack behavior, and any DNS failover delay.

## Domain metadata and source policy

**CONFIRMED**: route rules support `source_ip_cidr`, domain/suffix/keyword/regex and rule sets. Default-rule matching combines source and domain groups conjunctively; a device + domain rule can be expressed directly. [Route rules](https://github.com/SagerNet/sing-box/blob/v1.14.2/docs/configuration/route/rule.md).

Prerequisites for correct per-device policy:

1. Preserve original LAN source into the ingress; do not masquerade LAN traffic before handing it over.
2. Feed original destination/FakeIP mapping into sing-box. SOCKS from a common gateway loses the original source unless an ingress adapter conveys it explicitly.
3. Preserve source on DNS interception too. RouterOS forwarding all DNS as its own resolver address makes per-client DNS policy unavailable.
4. Define rule precedence: device DIRECT override, device full-proxy, scoped device/domain rules, global domain/service rules, default DIRECT.

FakeIP mapping establishes domain identity without sniffing only when the client used the managed DNS and traffic reaches sing-box with the original synthetic destination. Sniffing is optional supplemental metadata; encrypted client DNS, ECH, IP literals and fragmented QUIC can reduce domain visibility. Do not treat domain-to-real-IP lists as exact domain identity on shared CDNs.

**CONFIRMED**: [pre-match](https://github.com/SagerNet/sing-box/blob/v1.14.2/docs/configuration/shared/pre-match.md) runs before L3 connection establishment. In 1.14 L3 route forwarding can target Bridge/WireGuard/Tailscale for TCP/UDP; FakeIP destinations on that path require a `resolve` action in pre-match. TCP sniffing stops pre-match; UDP sniffing can use the first datagram. `bypass` is a Linux `auto_redirect` action, not a RouterOS routing shortcut. A VLESS L4 route should retain recovered domain metadata; do not blanket resolve the destination through the FakeIP server.

## Engine, endpoints, groups and rule sets

**CONFIRMED**:

- [VLESS](https://github.com/SagerNet/sing-box/blob/v1.14.2/docs/configuration/outbound/vless.md): `server`, `server_port`, `uuid`; optional TLS, REALITY/uTLS in TLS, V2Ray transport and `xtls-rprx-vision` flow. Default UDP packet encoding is xudp. A URI transport `type=tcp` does not mean `network: tcp`; the latter disables UDP. Unsupported flow/transport/credential combinations must be rejected.
- [Shadowsocks](https://github.com/SagerNet/sing-box/blob/v1.14.2/docs/configuration/outbound/shadowsocks.md), [Trojan](https://github.com/SagerNet/sing-box/blob/v1.14.2/docs/configuration/outbound/trojan.md), [Hysteria2](https://github.com/SagerNet/sing-box/blob/v1.14.2/docs/configuration/outbound/hysteria2.md) remain supported. Protocol support does not imply the container ingress captures UDP. Hysteria2 depends on QUIC build support and UDP reachability.
- [Selector](https://github.com/SagerNet/sing-box/blob/v1.14.2/docs/configuration/outbound/selector.md) is a group over outbound tags; runtime switching is currently controlled through Clash API. Keep that API private and put application authorization in front of it.
- [URLTest](https://github.com/SagerNet/sing-box/blob/v1.14.2/docs/configuration/outbound/urltest.md) tests candidates with configurable URL/interval/tolerance/idle timeout; it is not a readiness proof for all user services or automatic replay of established failed TCP connections.
- [Rule sets](https://github.com/SagerNet/sing-box/blob/v1.14.2/docs/configuration/rule-set/index.md) support local/remote source or binary formats. [Source format](https://github.com/SagerNet/sing-box/blob/v1.14.2/docs/configuration/rule-set/source-format.md) is separate from the full config. Treat remote updates as untrusted input and preserve a validated last-known-good set.
- [WireGuard endpoint](https://github.com/SagerNet/sing-box/blob/v1.14.2/docs/configuration/endpoint/wireguard.md) replaces old WireGuard outbound forms. `system: false` is userspace; `system: true` requires privilege. Neither solves missing transparent LAN ingress by itself. Prefer a future separate RouterOS-native WireGuard adapter for the product; no legacy outbound generation.

The tested official executable has `with_gvisor`, `with_quic`, `with_wireguard`, `with_utls`, `with_clash_api` among its build tags. Product images must record their own tags and test features on both Linux ARM64 and AMD64; these observed macOS tags do not prove future image builds.

## Current migrations that affect the generator

[Version-pinned migration guide](https://github.com/SagerNet/sing-box/blob/v1.14.2/docs/migration.md) is the authority. Generate current structures rather than relying on compatibility flags:

- Typed DNS servers, route `hijack-dns` and `reject` actions replace old DNS/block outbound plumbing.
- Modern route `sniff` and `resolve` actions replace old inbound sniff/domain strategy settings.
- Use unified TUN `address`, `route_address`, `route_exclude_address` rather than old `inet4_*`/`inet6_*` tun fields.
- Use `domain_resolver` or `route.default_domain_resolver` for endpoint hostnames; with multiple DNS servers this is required instead of old DNS `outbound` rule matching. An explicit resolver skips DNS rule matching, making bootstrap deterministic.
- Remove `dns.independent_cache`; cache is keyed by transport automatically.
- `store_dns` replaces deprecated `store_rdrc` when persistent full DNS cache is wanted.
- DNS address-response filters now require `evaluate` followed by `match_response`; do not mix old IP filter semantics with modern `query_type`/`ip_version` matching.
- No fragmentation/spoofing/DPI-evasion fields belong in MikroCentauri output, despite their presence in upstream.

## Executable configuration smoke test

This is a **TESTED configuration-schema/DNS fixture**, not a deployment recipe and not an end-to-end milestone. It intentionally uses high loopback ports and a placeholder loopback VLESS endpoint. The endpoint is not a real external service. URLTest has no successful candidate until a test VLESS server is provided. Full-device source policies cannot be exercised by loopback clients. No credentials below are production secrets.

Validation command: `sing-box check -c config.json` with v1.14.2. Exit status observed: **0**. Runtime DNS test: **passed**. No transparent RouterOS path was tested.

```json
{
  "log": {
    "level": "info"
  },
  "dns": {
    "servers": [
      {
        "type": "udp",
        "tag": "bootstrap",
        "server": "1.1.1.1"
      },
      {
        "type": "fakeip",
        "tag": "fakeip",
        "inet4_range": "198.18.0.0/15"
      }
    ],
    "rules": [
      {
        "domain_suffix": [
          "example.com"
        ],
        "query_type": [
          "A"
        ],
        "action": "route",
        "server": "fakeip"
      }
    ],
    "final": "bootstrap"
  },
  "inbounds": [
    {
      "type": "direct",
      "tag": "dns-in",
      "listen": "127.0.0.1",
      "listen_port": 5354
    },
    {
      "type": "mixed",
      "tag": "test-in",
      "listen": "127.0.0.1",
      "listen_port": 2080
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct",
      "domain_resolver": "bootstrap"
    },
    {
      "type": "vless",
      "tag": "proxy",
      "server": "127.0.0.1",
      "server_port": 8443,
      "uuid": "bf000d23-0752-40b4-affe-68f7707a9661"
    },
    {
      "type": "urltest",
      "tag": "proxy-auto",
      "outbounds": [
        "proxy"
      ],
      "url": "https://www.gstatic.com/generate_204",
      "interval": "3m",
      "tolerance": 50
    },
    {
      "type": "selector",
      "tag": "proxy-select",
      "outbounds": [
        "proxy-auto",
        "proxy"
      ],
      "default": "proxy-auto"
    }
  ],
  "route": {
    "rules": [
      {
        "inbound": [
          "dns-in"
        ],
        "action": "hijack-dns"
      },
      {
        "source_ip_cidr": [
          "192.168.88.30/32"
        ],
        "action": "route",
        "outbound": "direct"
      },
      {
        "source_ip_cidr": [
          "192.168.88.20/32"
        ],
        "action": "route",
        "outbound": "proxy-select"
      },
      {
        "domain_suffix": [
          "example.com"
        ],
        "action": "route",
        "outbound": "proxy-select"
      }
    ],
    "final": "direct",
    "default_domain_resolver": "bootstrap"
  }
}
```

For a TUN lab, substitute a TUN ingress only after the Linux/RouterOS TUN probe succeeds and explicitly construct the VETH→TUN route. For a custom gateway lab, replace `mixed` with the adapter's documented handoff and prove preservation of both source and destination. Simply switching the inbound type does not solve interception.

## Validation, reload and last-known-good

`sing-box check` validates config construction; it cannot prove kernel interception, endpoint reachability, protocol behavior or fail-open. Combine generated golden fixtures with this exact binary and a live candidate probe.

Proposed safe workflow (**ASSUMED**, controller responsibility): generate in a staging directory; check; run candidate with isolated listener ports/resources when feasible; verify DNS and configured outbound; record last-known-good; change engine/router desired state under controller transaction; verify readiness; rollback engine and owned RouterOS state together on failure. The same TUN/interface/port cannot be owned by old and candidate processes concurrently. Do not claim zero-downtime reload without a test.

Clash API exposes runtime group controls and configuration operations, but it is not a controller transaction or rollback journal. Keep [external controller](https://github.com/SagerNet/sing-box/blob/v1.14.2/docs/configuration/experimental/clash-api.md) on loopback/private IPC and protect with a random secret; do not publish an additional unauthenticated LAN administration surface.

## Licensing boundary

**CONFIRMED**: [v1.14.2 LICENSE](https://github.com/SagerNet/sing-box/blob/v1.14.2/LICENSE) declares GPL-3.0-or-later and adds a restriction on using the application name or implying association without prior consent. Preserve notices and corresponding-source obligations when distributing images. A linked modified engine/gateway has a different reuse boundary than an independently orchestrated executable; the project license audit must explicitly account for the selected implementation. This research copied no engine code into the repository.

## Required RouterOS lab evidence

**TODO** before functional claims:

- Probe `/dev/net/tun`, effective capabilities, `IP_TRANSPARENT`, AF_PACKET access, supported kernel route/netfilter mechanisms; record RouterOS version and real error codes.
- Compare selected real-IP destination lists vs selective FakeIP vs full-gateway ingress; capture both sides of VETH with original source/destination.
- VLESS selected domain goes through a test server; unselected domain never enters engine; verify egress identity independently.
- UDP and QUIC selected traffic roundtrip, or explicitly declare unsupported and reject unsupported policies.
- Two devices reach the same domain with different route policies.
- Crash candidate, controller and full container separately. Verify ordinary DIRECT continuity plus cached FakeIP recovery timings.
- Reject bad JSON/URI/empty subscription while old engine continues; reboot/reconcile; remove only owned state.

Research completion does not mean the requested CHR milestone is complete. The present verified result is a current version pin plus real engine configuration and DNS smoke checks; the transparent RouterOS boundary remains a target lab gate.
