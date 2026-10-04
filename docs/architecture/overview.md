# Architecture overview

Proposed boundaries: domain configuration → config/rules/subscriptions engine →
sing-box supervisor; orchestration → PlatformAdapter → RouterOS REST; API → domain
operations and drafts; UI → API only. RouterOS owns routing/firewall/native watchdog.
Controller has no independent authority to modify unowned resources.

Implemented now: strict milestone configuration, VLESS/TCP URI subset, pinned sing-box
config generator/validator, private atomic output, exact-ownership RouterOS planner,
REST/mock compensation, source-preserving CHR TUN lab, TCP/UDP/HTTP3 traffic,
native lab watchdog/boot guard and measured alternatives. Missing full product:
subscription/group/rules managers, lifecycle supervisor/LKG, durable production
watchdog/controller, API/auth, UI and production app image. Cached FakeIP fallback,
remote proxy health, full IPv6/device/version policy and zero-loss boot ordering
remain acceptance gates. Track them in ADR-0001 and the Phase-1 report.
