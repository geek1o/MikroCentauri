# Centauri interface

The primary workflow is subscription → selector → site lists → reviewed apply.
An existing selector also supports a separate immediate action: change the
running engine's selected member. Its state is read back from sing-box and shown
on server rows. Draft selection and live selection are visibly distinct.

## Visual and interaction principles

The interface uses a midnight-blue sky, original SVG constellations and layered
reading surfaces. [Proton 2025](https://github.com/ChesterGoodiny/luci-theme-proton2025)
was reviewed as an appearance reference; its assets and code are not dependencies.
Light, dark and system themes share semantic status colors and keyboard focus
outlines. Controls and server rows remain opaque for readability.

System settings provide stars, constellations or a plain background, star density,
brightness, scale, optional motion and a separate login-background switch. Changes
preview immediately; Save persists them in private server preferences and safe
backups. Legacy preferences and backups remain valid. Older clients that omit
sky settings preserve the saved sky when updating preferences.

The public, read-only `/api/v1/appearance` endpoint exposes only theme and bounded
sky settings so the login screen can use saved appearance without browser storage.
It retains TLS, origin and client restrictions; it exposes no account, routing,
subscription or timezone data. Preference writes require authentication.

The decorative sky has no input handlers, external assets or canvas loop. Its
star count is bounded to 200, generated deterministically. Optional motion uses
one slow CSS animation; `prefers-reduced-motion` disables it. The constellation
artwork is illustrative, not an astronomical chart.

Server rows expose protocol, address, current selection, measured latency and
measurement time. Search and ordering help navigate larger subscriptions.
Tests measure an HTTPS request through an individual outbound, not ICMP.
Failures display “Нет ответа”; there are no invented successful measurements.
Up to three UI checks run concurrently. Selection is independent of pending
network checks. Existing connections are not interrupted by selector changes.

Onboarding steps appear only before servers are configured. Working dashboards
prioritize selectors and current state. Server rows retain distinct live/draft
actions and collapse into a compact stacked layout on narrow screens.

The catalog separates domain lists from CDN/IP networks, shows selection counts,
and keeps the import action visible while scrolling. Technical and destructive
actions are disclosed separately from everyday selection. Mobile navigation
keeps every section accessible.

These choices follow [visibility of system status](https://www.nngroup.com/articles/visibility-system-status/)
and [progressive disclosure](https://www.nngroup.com/articles/progressive-disclosure/).
The [Forkop catalog](https://github.com/ushan0v/forkop/blob/main/fe-app-forkop/src/constants.ts)
and [rule sources](https://github.com/ushan0v/forkop/blob/main/forkop/files/usr/lib/singbox/rulesets.uc)
were reviewed for workflow/source coverage. Implementation and styling are original.

## Engine boundary

Administrative browser actions use authenticated MikroCentauri endpoints. The private
[sing-box Clash API](https://sing-box.sagernet.org/configuration/experimental/clash-api/)
listens on loopback with a secret. The browser cannot choose its URL, secret,
latency target, configuration or arbitrary API method. Only active manual-group
members may be selected. Revision checks reject stale requests; the selected
member is read back before success is reported. Switching does not create or
apply a policy draft.

The native runtime serializes selection against policy transitions. A live
engine may be selected while readiness is withdrawn, allowing recovery from a
bad server; selection never publishes readiness or releases the traffic gate.
The normal health owner must independently prove readiness again.
