# Sections acceptance — 2026-10-08

First-class sections now persist in the core model and redacted policy API.
The section compiler emits separate domain and destination-CIDR alternatives,
retains source scopes, orders sections, and excludes disabled sections. The
existing generation, immutable DNS namespace handling, plan review and safe
backup paths retain section semantics.

The UI supports create/edit/copy/delete, reorder, enable/disable, community
list search and filtering, inline domains/CIDRs, device scopes, DIRECT
exceptions and separate manual/automatic selectors. Section cards embed real
sing-box selector controls and explain shared-selector effects and possible
rule overlaps. List refresh is isolated to the selected section.

Validation:

- Core tests cover domain/CIDR OR semantics, device scopes, order, disabling,
  invalid targets, fake-IP destination rejection and generated-ID collisions.
- Pinned sing-box validates section configurations. The real mixed-inbound
  integration test forwards through a local Shadowsocks server, changes section
  order, disables a section, and changes source scope. Socket counters verify
  DIRECT bypass and proxy use.
- API tests cover immutable source snapshots, refresh isolation, failed-download
  preservation, stale revisions, health responsiveness during downloads,
  concurrent draft protection, own selector creation and safe backup/restore.
- Browser acceptance covers list selection, own selector creation, overlap
  notices, reordering, copying, disabling, plan/apply, safe export and draft-only
  deletion, with desktop and mobile screenshots.

The full Go race suite passed, followed by focused section/namespace checks
after generation optimization. All five browser scenarios passed in Chromium
and WebKit; final section presentation changes received another focused pass.
Frontend checks, 13 unit tests and the asset budget also passed.

These checks are local application/engine evidence. They do not establish native
RouterOS interception, IPv6 support, wildcard DNS admission or the reachability
of a user's external subscription endpoints.
