# ADR-0020: embedded administrative UI

Status: accepted for product Phase 5, pinned CHR profile.

The functioning native owner and authenticated API precede the UI. The UI must
operate the accepted draft/validation/plan/apply boundary without downloading
private credentials or adding a second network owner.

Use Svelte and TypeScript, compiled by Vite, with a committed dependency lock.
Svelte compiles components into browser code rather than requiring a server
framework ([official overview](https://svelte.dev/docs/svelte/overview)). The
production bundle is embedded into the existing Go executable; RouterOS needs
no Node runtime. Source and compiled assets are both committed, and reproducible
asset comparison is a build gate. A 100,000-byte gzip budget covers the complete
shell, JavaScript and stylesheet. There are no remote fonts, CDN scripts or
analytics. Hash navigation permits an exact static asset allowlist.

The existing HTTPS listener enforces TLS, exact Host/origin and actual socket
client CIDRs before serving the public login shell or assets. The API still
requires bearer authentication. Tokens stay in memory; credentials are write-only
and cleared after submission. CSP admits only same-origin scripts/styles/API
requests and forbids inline scripts, frames and form navigation. All names are
escaped text. Safe downloads use locally created Blob URLs.

Policy forms mutate durable CAS drafts. Validation creates a reviewed, expiring,
single-use plan; the apply button delegates to the existing owner and reloads
verified readiness. Explicit enabled proxy-rule domains enter the same DNS draft;
existing names are retained until an explicit DNS retirement. Unsupported suffix
admission is explained and blocked. Overlap warnings are bounded advisory checks,
with incomplete analysis clearly identified.

The wizard reads the existing environment and checks address overlap, then
uses the same policy plan. RouterOS App installation/provisioning is Phase 6.
Diagnostics accept fixed composition-owned targets. Per-node measurements use
an isolated, bounded socksify child with private temporary state, no TUN,
no live FakeIP cache and no DIRECT fallback. They are timestamped samples,
not continuous health or proof of the selected live path.

Browser acceptance uses Playwright with a disposable HTTPS server and the real
API/auth/pinned validator. The runtime and router/subscription transport in that
fixture are explicitly simulated; this is UI contract evidence, not a new CHR
packet proof. The native Phase 4 evidence remains the routing acceptance basis.
Playwright's supported browser tooling is documented in its
[official documentation](https://playwright.dev/docs/test-webserver).
