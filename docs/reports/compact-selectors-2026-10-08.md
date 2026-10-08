# Compact selectors and automatic selection — 2026-10-08

The shared selector panel uses compact rectangular tiles. The shared check action
aligns with search/order controls; measured time is a tooltip, not another row.
Proxy management uses compact tiles with existing import/edit/delete behavior.
The orbital mark is one SVG reused by login, navigation and favicon.

Section-owned selectors can switch between manual and URLTest through a reviewed
draft, retaining the group ID, section contents and chosen members. Interval and
latency tolerance are configurable. Live type and draft type remain distinct.

Acceptance includes:

- Real sing-box with generated URLTest: choose the faster controlled HTTPS path,
  switch when that path fails, and return after it recovers.
- Browser: measured tile height is unchanged; mode settings survive editor
  reopening; auto/manual changes retain one group and section domains; only
  plan/apply changes the live policy.
- Browser: shared logo identity, compact proxies, 1280/390 pixel widths and
  existing list, section, theme and live-selector scenarios.

The engine starts periodic URLTest on first use and suspends it after the default
30-minute idle timeout. Polling the browser is not its scheduling owner. The test
uses synthetic transports and no TUN; it establishes no new native RouterOS
packet-path or external-provider acceptance.

The previous public build from main commit
465715500bc18fc8d66c97bfd86686b7d02ebb79 passed build and publish jobs:
https://github.com/geek1o/MikroCentauri/actions/runs/37732876030
It published amd64/arm64 artifacts and anonymously accessible corresponding
sources, image and catalog. The immutable image index was
sha256:2240674cb66bd5170f7c7eb36b1fa2d899a8c2e9f4d2d14f8561d52743448c52.
The changes described above require their own subsequent build.
