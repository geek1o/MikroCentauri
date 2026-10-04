# Architecture overview

Proposed boundaries: domain configuration → config/rules/subscriptions engine →
sing-box supervisor; orchestration → PlatformAdapter → RouterOS REST; API → domain
operations and drafts; UI → API only. RouterOS owns routing/firewall/native watchdog.
Controller has no independent authority to modify unowned resources.

Implemented now: strict milestone configuration, VLESS/TCP URI subset, pinned sing-box
config generator/validator, private atomic output, exact-ownership RouterOS planner,
REST/mock compensation, lab capability probe and process smoke. Missing full product:
subscription/group/rules managers, lifecycle supervisor/LKG, native watchdog, API/auth,
UI, production app image and E2E dataplane. Track gates in ADR-0001 and phase report.
