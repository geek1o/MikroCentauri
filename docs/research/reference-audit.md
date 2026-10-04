# Reference implementation audit

Research date: 2026-10-04 (Europe/Moscow). Status: **CONFIRMED by source inspection**, not tested on OpenWrt or RouterOS. Repositories were shallow-cloned into `/tmp/mikrocentauri-audit` outside this project. No implementation, artwork, font, or fixture was copied into MikroCentauri.

## Reproducible source baseline

| Project | Observed default branch / exact commit | Latest stable release reported by GitHub API |
|---|---|---|
| [Podkop](https://github.com/itdoginfo/podkop) | main / `c0a2736bb95884c19fedf638345ed6148c5fd6af` (2026-08-18) | `0.7.22`, published 2026-08-18 |
| [Tachyon](https://github.com/Dushnilin/tachyon) | main / `6c2f9a3a4a9c427c34c3572a82d2292ca5961a85` (2026-10-04) | `1.4.10`, published 2026-10-04 |
| [Forkop](https://github.com/ushan0v/forkop) | main / `dd483297be0ac4e52bb8f482e2640238b75af532` (2026-07-18) | `1.0.5`, published 2026-07-18 |
| [Steer](https://github.com/splify2/steer) | main / `fa24f0588b8375a7a46a927f78151ea6ea7798fa` (2026-10-04) | `v2.0.2`, published 2026-10-04 |

Release labels are API observations, not claims that the inspected branch equals the release tag. The source commits above define this audit. Build-time versions and frontend package versions are not interchangeable with releases. `xyzmean/steer`, named in Tachyon's README, redirects to canonical `splify2/steer`; do not treat these as two separate upstreams. GitHub records Forkop as a fork of Podkop. Tachyon's README identifies Forkop and Steer ancestry, although GitHub reports Tachyon as an independent repository; this is stated ancestry, not a full Git history/provenance reconstruction.

## Podkop: current implementation

Primary source tree: [pinned Podkop source](https://github.com/itdoginfo/podkop/tree/c0a2736bb95884c19fedf638345ed6148c5fd6af).

- `podkop/files/usr/bin/podkop` is the shell orchestration entrypoint. It loads OpenWrt configuration through `config_load`, `config_get`, `config_foreach`, commits UCI state, configures DNS and policy routes, and produces sing-box JSON.
- `podkop/files/etc/config/podkop` is the UCI application model: sections, outbound choices, URI strings, selector/urltest links, local/remote domain and subnet lists, device source policies.
- `podkop/files/usr/lib/sing_box_config_manager.sh` provides JSON transformations; `sing_box_config_facade.sh` adapts proxy strings to outbound objects; `helpers.jq` contains shared transformations. Generation is conceptually portable; shell/jq and UCI coupling should be replaced with a typed Go compiler and pinned sing-box validation.
- `podkop/files/usr/lib/rulesets.sh` and entrypoint import functions build source/local/remote rule sets. Domain lists also feed FakeIP DNS rules. This relationship is useful: the domain policy must drive both DNS and route treatment.
- The inspected configuration exposes explicit proxy URIs and selector/urltest URI lists. No provider subscription-fetch/cache module was found in the inspected Podkop tree. Remote domain/subnet lists are **rule feeds**, not proxy-node subscriptions; do not claim full subscription parity from this reference.
- DNS setup saves selected `dhcp.@dnsmasq[0]` fields, forwards dnsmasq to the sing-box DNS listener, disables its cache and restarts `/etc/init.d/dnsmasq`; stop restores state. This implementation is entirely OpenWrt-specific. The transferable lesson is snapshot/ownership/restore, not the dnsmasq mutation.
- nftables table/set construction is in `nft.sh`; entrypoint installs TProxy capture and fwmark policy routing (`ip rule`, routing table, priority 105). RouterOS routing to VETH is not Linux local-delivery TProxy and requires a separate experiment.
- `/etc/init.d/podkop` uses `procd`, OpenWrt configuration triggers and interface events. The frontend uses LuCI UCI APIs, `fs.exec`, global `ui`, translations and LuCI menus/rpcd ACLs. Its dashboard also directly reaches Clash API; README documents HTTP/HTTPS restrictions.

## Tachyon and Forkop

Primary sources: [pinned Tachyon](https://github.com/Dushnilin/tachyon/tree/6c2f9a3a4a9c427c34c3572a82d2292ca5961a85), [pinned Forkop](https://github.com/ushan0v/forkop/tree/dd483297be0ac4e52bb8f482e2640238b75af532).

Tachyon backend now uses modular `ucode`, not merely an unchanged copy of Podkop shell scripts. Modules are stored under `tachyon/files/usr/lib/` and installed into its application library directory.

| Concern | Inspected source location | Transferable concept / replacement |
|---|---|---|
| Configuration | `core/`, `config/`, `/etc/config/tachyon` | Typed model, validation, migrations; replace UCI with own schema/store |
| sing-box generation | `singbox/generator_outbounds.uc`, `route.uc`, `servers.uc`, `rulesets.uc`, `runtime.uc` | Deterministic compiler, stable tags, group/reference normalization; implement anew |
| Subscriptions | `subscription/parser.uc`, `cache.uc`, `share_link.uc`; `singbox/subscription.uc` | URI/plain/base64/Clash parsing, source metadata, cached candidates and persistent cache; bounded safe HTTP client and LKG |
| Compatibility | `singbox/generator_outbounds.uc` | Filter unsupported protocol/transport nodes and repair group references; do not silently accept extended-only transports |
| Apply/preflight | `service/config_plan.uc`, `reload.uc`, `known_good.uc`, `snapshot.uc` | Candidate generation, binary validation, observation before LKG promotion, rollback |
| DNS | `dns/apply.uc` | Explicit managed state/snapshots; replace dnsmasq/procd manipulation |
| Firewall/routes | `nft/apply.uc` | Separate compiler/applier, exclusions and capture rules; replace nft/iproute2 with RouterOS adapter |
| Health/events | `service/watchdog.uc`, `reconciler.uc`, `state.uc`, `event_controller.uc` | Health state and reconciliation; outside-container fail-open is still required |
| UI/backend contract | `contracts/tachyon-rpc.json`, generated frontend contracts | Versioned typed API contracts; replace LuCI/rpcd transport |

Observed `subscription/parser.uc` has share-link and base64 decoding and a custom Clash YAML reader. It is a useful list of edge cases, not a reason to inherit a custom YAML parser or every upstream transport. `runtime.uc` retains a persistent subscription cache format; this confirms an actual node subscription implementation distinct from Podkop rule feeds. The reviewed source does not prove its runtime guarantees on RouterOS.

Tachyon reads network state using `ubus call network.interface ...`, ships rpcd ACLs and an OpenWrt interface hotplug monitor, calls `ip -4/-6 rule`, uses nft TProxy for TCP and UDP and restores dnsmasq fields. Forkop supplies the inherited UCI/LuCI structure and subscription/state concepts; Tachyon is the richer current code audit target. Anti-DPI providers, AI/MCP, Telegram, parental controls and extra engines are outside MikroCentauri's scope and are not imported.

## Steer

Primary source: [pinned Steer](https://github.com/splify2/steer/tree/fa24f0588b8375a7a46a927f78151ea6ea7798fa).

The current project is a C rule compiler and routing/protocol runtime driven by YAML/JSON spec v2. It is not a portable RouterOS shell manager. `src/platform/openwrt.c` and `android.c` show platform separation, but underlying dataplane uses Linux netlink, nf_tables, fw4 integration and routing rules (`src/lib/rtnl.c`, `nftnl.c`, `src/daemon/fwcheck.c`). Its FakeIP system uses Linux DNAT/state maps; this must not be confused with sing-box's FakeIP cache and domain restoration. A copied gateway rule cannot make RouterOS support nftables.

Useful concepts: ordered rules with first match semantics, explanatory diagnostics, dry-run plans, policy/group failure semantics, preserving DNS identity across reloads and atomic data-plane updates. RouterOS REST sequences are not equivalent to one nftables transaction; rollback and a disabled staging state must be explicit. The current repository also includes anti-DPI/obfuscation modules which are deliberately excluded here.

## Portability decision

**Use concepts; independently implement application logic.** No whole frontend is suitable for direct adoption: the UI transport and runtime assume LuCI globals, UCI/rpcd, shell execution and direct Clash API access. Some pure URI validators, formatting helpers or components could be technically extracted only after per-file licensing and provenance review; this milestone instead creates original API/CLI and postpones UI until dataplane evidence exists.

| Dependency | Why it cannot be transplanted | MikroCentauri replacement |
|---|---|---|
| UCI | OpenWrt configuration database/section conventions | Versioned application document/store |
| ubus/rpcd | OpenWrt IPC, network and authorization contracts | Own `/api/v1`, RouterOS REST inside adapter |
| dnsmasq | OpenWrt DHCP/DNS lifecycle and UCI mutation | Managed container DNS plus RouterOS DNS/NAT policy |
| nftables/fw4 | Linux host firewall and local TProxy capture | RouterOS mangle/NAT/routing; gateway ingress validated separately |
| `ip rule` / `rt_tables` | Linux kernel policy routing | RouterOS FIB tables/rules with ownership comments |
| procd/init.d/hotplug | OpenWrt service/event runtime | Controller supervisor, reconcile loop, RouterOS Netwatch |
| LuCI | OpenWrt forms, global APIs and auth | Original web client of versioned backend API |

License and asset decisions are in [license-audit.md](../legal/license-audit.md). Status labels: source architecture **CONFIRMED**; functionality on MikroTik **NOT TESTED**; direct reuse **NONE**.
