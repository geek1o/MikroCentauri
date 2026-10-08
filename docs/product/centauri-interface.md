# Centauri interface

The primary workflow is subscription → selector → site lists → reviewed apply.
An existing selector also supports a separate immediate action: change the
running engine's selected member. Its state is read back from sing-box and shown
on server cards. Draft selection and live selection are visibly distinct.

## Visual and interaction principles

A celestial palette uses midnight surfaces, indigo accents, a warm star mark and
subtle orbital geometry. Standard text/action labels remain literal. Light,
dark and system themes share semantic color tokens and keyboard focus outlines;
no external fonts, graphics or animated background are required.

Server cards expose protocol, address, current selection, measured latency and
measurement time. Search and ordering help navigate larger subscriptions.
Tests measure an HTTPS request through an individual outbound, not ICMP.
Failures display “Нет ответа”; there are no invented successful measurements.
Up to three UI checks run concurrently. Selection is independent of pending
network checks. Existing connections are not interrupted by selector changes.

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

The browser talks only to authenticated MikroCentauri endpoints. The private
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
