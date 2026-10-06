# MikroCentauri administrative UI

Svelte + TypeScript compile the UI into a small static bundle served by the Go
API's existing HTTPS listener. There is no Node runtime on RouterOS, no CDN,
remote fonts, third-party analytics, or client credential persistence.
Hash navigation keeps the server's static allowlist small. Bearer sessions stay
in module memory; reload requires another login. Passwords, subscription URLs and
proxy import/replacement URIs clear as soon as they are submitted. All user text
uses escaped Svelte text bindings, never HTML injection.

`npm ci`, `npm run check`, `npm test`, `npm run build`. Node 22.18+ is required for
strip-only TypeScript tests; the build follows Vite's supported Node versions.
Exact development package versions and integrity hashes are recorded in the
lockfile. Asset budget: 350,000 raw bytes and 100,000 gzip bytes. Production assets
are copied by `scripts/build-webui.py` into Go's embedded package. `npm run format`
uses the pinned Prettier/Svelte plugin.

The ten pages expose the accepted backend: dashboard; pre-provisioned setup
checks; proxies; subscriptions and shared refresh interval; groups; routing rules;
DHCP devices/source policies; DNS; fixed-target diagnostics; system metadata,
preferences, safe backup/restore and redacted logs. Group members and outbound
choices display names. The rules page reports advisory overlaps for different
outbounds using explicit domains/suffixes, IPv4 source/destination CIDRs, network
and ports. Lower priorities win; equal priorities retain declared order. Analysis
is bounded to 256 enabled rules, 32 entries per condition and 64 reported pairs.
Remote sets, services, IPv6, domain/IP resolution and limits explicitly mark the
analysis incomplete. It never labels the complete configuration conflict-free. Edits preserve unmodified private fields on the server.
Enabled proxy rules add their explicit domain names to selected DNS in the same
draft, preserving previously admitted names. Direct/disabled rules add no names;
deleting a rule never retires DNS. FakeIP suffix publication is disabled because
finite namespace admission does not yet cover it; ordinary route suffixes remain
valid.
Each policy/proxy import or edit uses the durable draft revision; saving never
activates traffic. The user validates, reviews a five-minute single-use plan and
explicitly applies it. Readiness is checked again after the result.

The setup wizard checks an **existing operator profile**, reads bounded network
facts and previews IPv4 FakeIP/LAN overlap. It does not provision a RouterOS App,
VETH or an arbitrary topology. Node rows expose an isolated per-node canary probe for active enabled endpoints,
including WireGuard. New draft nodes need activation first. Results carry sample
time, scope, and HTTP request latency excluding probe-child startup. They are
momentary measurements, not continuous monitoring or global runtime readiness.
Global diagnostics separately probe the configured active proxy path.
Missing adapters, failed queries, disconnected runtime and empty DHCP data are
reported separately. Core checks work with the configured server runtime.
Safe backups omit keys/URLs and need matching credentials already on this
installation. Installation/update belongs to product Phase 6.

UI text is Russian. The backend language preference is preserved, but this
version does not offer a translated English interface. Theme and IANA time zone
preferences are persisted by the server.
