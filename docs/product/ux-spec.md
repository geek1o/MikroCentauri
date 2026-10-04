# Initial UX specification

Status: design only. No frontend before ADR-0001 is accepted by experiments.
Product name: **MikroCentauri**; no reference-project branding or assets reused.

People choose subscriptions, proxies, groups, services, domains and devices. A
rule reads “YouTube → proxy-auto”; DIRECT is the default. The interface must show
whether a rule is supported by the actual router/dataplane, not hide incompatibility.

Onboarding: authenticate with a one-time setup token, connect to RouterOS over
verified HTTPS, inspect version/capabilities/LAN/WAN/DNS/FastTrack/storage, check
address conflicts, preview owned changes, apply and verify. Physical device-mode
confirmation is a separate explicit step. Do not change DHCP leases automatically.

The first lab milestone uses a CLI/file configuration: one validated VLESS URI,
one exact selected domain, then generate/check/preview. It exposes no unauthenticated
application API. The eventual Save → Validate → Plan → Apply flow separates drafts
from the working revision. A failed candidate keeps the prior revision visible.

Screens planned after lab proof: dashboard, proxies, subscriptions, groups, ordered
rules, devices, DNS, diagnostics, system. Proxy import previews credentials as
redacted fields. Rule conflicts and source precedence must be visible. “DIRECT”
source rules precede full-proxy source rules; application rules remain ordered.

Diagnostics distinguishes backend liveness, child process, DNS, applied router
state and native watchdog state. Never display a green “ready” badge from API
liveness alone. The current prototype does not implement readiness or watchdog.

Capability disclosures: explicit SOCKS/Socksify is a TCP-only candidate and cannot
claim transparent UDP/device parity; custom client DoH/DoT bypasses DNS-based
selection; managed AAAA suppression is not complete IPv6 leak prevention. Cached
FakeIP connections can remain unavailable after a crash. Do not label their failover
instantaneous. These limitations must inform the final dataplane choice.

Product model: ProxyEndpoint (secrets separate), Subscription (candidate + LKG),
ProxyGroup (selector/urltest/fallback behavior), Rule (ID/priority/sources/destinations/
action), Device (lease/IP/stability), ConfigRevision, ApplyJournal, Capabilities.
Initial source implements only a narrow milestone subset, not these full managers.
