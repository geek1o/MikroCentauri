# MikroCentauri

![Experimental: vibe-coded, personal use, no warranties](assets/experimental.svg)

Selective IPv4 routing for MikroTik RouterOS. RouterOS stays in control of the
network; a separately executed sing-box engine handles selected traffic.
MikroCentauri provides an HTTPS management UI, proxy and subscription management,
reviewed routing changes, and readiness checks before publishing DNS aliases.

> [!WARNING]
> **⚠ EXPERIMENTAL · VIBE-CODED · PERSONAL USE**
>
> This project is developed with extensive AI assistance for its author's personal
> use. It has no independent security audit and is supplied **without warranties,
> support commitments, or guarantees of availability, privacy, or correctness**.
> Routing failures can expose selected traffic through a DIRECT connection.
> Review the code and configuration, keep recoverable backups, and test on an
> isolated router before using it on your network. You are responsible for the
> consequences of installation and use.

## What it does

- Imports supported proxy configurations and manages subscriptions with explicit
  compatibility reports instead of silently dropping unsupported servers.
- Offers downloadable domain and IPv4/CDN catalogs, custom lists and ordered
  [traffic sections](docs/product/sections.md), each with its own list snapshots,
  device scope and route.
- Reads live sing-box selector state, switches manual groups and measures HTTPS
  delay through individual outbounds. Draft routing changes require reviewed apply.
- Provides a stellar interface with configurable vector sky, constellations,
  reduced-motion support and saved login appearance.
- Serves an embedded web UI and authenticated HTTPS API.
- Reserves persistent IPv4 DNS aliases and publishes them only after current
  runtime and RouterOS mapping verification.
- Coordinates controlled RouterOS rules, startup quarantine, and a finite
  readiness lease. On the tested profile, loss of admission withdraws steering
  and permits the reviewed DIRECT fallback.
- Preserves private installation state across the documented stopped
  upgrade/rollback procedure.

No anti-DPI engine or packet-mangling component is included.

## Compatibility

| Component | Status |
| --- | --- |
| CHR RouterOS 7.24.5, x86_64 | Architecture tested on a synthetic IPv4 profile; newly built images require their own exact-image native qualification |
| Linux arm64 image | Built and checked; physical ARM RouterOS runtime is not qualified |
| sing-box | Pinned to 1.14.2 |
| Image base | Pinned to Alpine 3.24.2 |
| Other RouterOS versions and topologies | Require their own installation and packet-path validation |

This is selective IPv4 routing. Literal IPv6, alternate DNS, DoH/DoT and clients
outside the reviewed policy can bypass it. It is not a privacy or anonymity
boundary. Read the [limitations](docs/limitations.md).

## Install

Start with the [installation guide](docs/install.md). The App first opens a
management UI in an empty DIRECT configuration; selected forwarding stays off.
The native routing owner additionally needs a reviewed network profile, trusted
TLS/RouterOS access and stopped privilege verification. It is not an unattended
whole-router installer. Automatic updates are disabled.

After the publication workflow verifies public image and source downloads, the
App Store URL is:

```text
https://geek1o.github.io/MikroCentauri/catalog.yml
```

Add it in RouterOS **Apps → Settings → App Store URLs**, then select MikroCentauri.
The workflow refuses to publish this catalog while the image or corresponding
sources are private. See the installation guide for the one-time GitHub settings.

Use only a catalog/image whose successful publication is recorded by the
repository's GitHub Actions run. A YAML template or a planned registry URL is
not evidence that a pullable image exists. Verify the immutable image digest
and release checksums before installation.

[Upgrade and rollback](docs/upgrade.md) require a complete stopped-volume backup.
A UI export does not include credentials, allocator identity or engine cache.

## Build and contribute

The [development guide](docs/development.md) describes pinned tooling, checks and
local multi-platform image builds. `main` contains the public application,
packaging and automation; `develop` retains additional engineering material.
Source builds do not require a live RouterOS device or private subscriptions.

See [security guidance](docs/security.md) before deploying or reporting a bug.
Never publish router credentials, subscription URLs, private TLS keys, or full
installation backups in issues or Git.

## License

MikroCentauri application source is [MIT licensed](LICENSE). Shipped engine,
base-system and UI components have separate licenses and distribution
requirements; see [third-party notices](THIRD_PARTY_NOTICES.md).
RouterOS/CHR is proprietary MikroTik software and is not redistributed here.
MikroCentauri is independent and is not endorsed by MikroTik or sing-box.
