# Product Phase 5: Web UI acceptance

Date: 2026-10-06. Status: **complete for the accepted backend/profile boundary**.
Canonical roadmap: product phases 0–8, not historical engineering report numbers.
Next: **Phase 6 RouterOS App installation/packaging**.

The existing native owner/API remains the sole activation path. A compact
Svelte/TypeScript SPA is embedded in the Go executable and served on its existing
HTTPS listener. No frontend server/runtime is installed on RouterOS. The complete
shell, assets and notices occupy **111,270 raw bytes / 37,197 gzip bytes**, below
the 100,000-byte compressed budget. Dependency versions/integrities are locked,
and rebuilding must match the committed assets byte-for-byte.

## Completed UI checklist

| Page | Accepted behavior |
| --- | --- |
| Dashboard | Runtime/readiness, RouterOS, subscription state, mode, routing summary, active/draft revisions and bounded recent events |
| Setup | Existing environment/access/network review, RAM/storage, FakeIP/IPv4 address overlap, draft validation, reviewed plan/apply/readiness; installation is explicitly separate |
| Proxies | URI import, metadata/credential replacement, enabled state and delete with reference validation; credentials stay server-side; active-node sample button with timestamp/scope/HTTP latency |
| Subscriptions | Write-only HTTPS URL, include/exclude filters, refresh status/LKG nodes, paging/select/import/delete and durable shared 1–1,440-minute or disabled refresh schedule |
| Groups | Selector/auto/fallback forms, named members and configured selection; existing private test URLs preserved |
| Rules | Human names, sources/domains/suffixes/CIDRs/known rule-set references/outbound/priority; bounded actual overlap warnings and explicit incomplete-analysis limits |
| Devices | Read-only DHCP hostname/IP/MAC and source policies for traffic entering the prepared engine path; no implicit whole-device interception claim |
| DNS | Actual mode/immutable profile values, finite selected-domain edits and fixed gateway diagnostic; enabled proxy-rule domains enter the same draft, previous names retained; suffix admission clearly unavailable |
| Diagnostics | Actual fixed RouterOS/core/DNS/DIRECT/proxy/routing/watchdog checks, subscription refresh and safe bundle download; missing adapters are never reported healthy |
| System | Development/build/expected versus observed pinned core versions, filesystem capacity, theme/time zone, runtime recovery, safe backup preview/draft/restore and bounded logs; installation/update remain later phases |

Every policy/proxy/import edit saves a CAS draft. A user validates, reviews the
full redacted candidate and explicitly applies an expiring single-use plan.
The result reloads committed revision/readiness. Private endpoint/WireGuard
credentials, rule-set sources, group URLs and cache identity stay server-side.
URI identity changes rewrite references atomically; disabling/deleting a referenced
node fails instead of silently choosing DIRECT.

Subscription scheduling persists a private atomic record, waits the full first
interval, refreshes serially and never auto-imports/applies. Its settings are
installation-local and excluded from safe credential-free backups.

## Security and actual node proof

The shell/assets pass the same TLS/exact Host/origin/socket-CIDR boundary as the
API; administrative data still requires an expiring bearer. Tokens stay in memory,
reload needs login, logout invalidates the token, and secret form values clear
after submission. CSP allows same-origin external code/styles/API only, excludes
inline scripts/frames/form navigation, and user names are escaped text. Known
assets/notices are embedded; arbitrary paths, traversal and source maps fail.
Third-party notices ship in `/licenses.txt`.

Actual sing-box 1.14.2 node integration starts a private isolated socksify child
for one enabled current endpoint, with loopback random ports and independent
temporary configuration/cache. It requires that child's own listener/startup
events, requests the fixed canary, then cancels/reaps before cleanup. Tests verify
no TUN, FakeIP publication, shared engine cache or DIRECT fallback, private
permissions, cancellation/unknown-node handling and unchanged cache sentinel.
Stopping the SS server leaves the canary reachable but makes the node check fail.
This measures one timestamped HTTP sample, excluding startup; it does not claim
continuous health or the live selector's current endpoint. Native diagnostics
are bounded/read-only except an ordinary DNS query's existing publication proof.

## Validation and limits

`make check cross-build` passed: Go race suite/vet, pinned integration smokes,
malformed switch peer regression, frontend type check, **11 frontend regressions**,
bundle budget/reproducibility and Linux amd64/arm64 builds. Typed actual-response
OpenAPI contracts cover new routes. Proxy mutation tests preserve private fields,
reject stale CAS/null/collision/invalid references, and never apply during edits.
RouterOS network tests permit fixed GETs only, redact raw rows and skip existing
IPv6 addresses without widening mutation permissions.

Chromium and WebKit passed the complete browser workflow against a disposable
**real TLS 1.3 API/auth/durable draft/pinned validator**: all ten pages, setup
read checks, escaped hostile names, import/rename/disable/delete, groups/rules,
automatic finite DNS union, DHCP/source policy, stale rejection, plan/apply,
honest unavailable node adapter, subscription selection/schedule, actual core
validation, diagnostics download, safe backup/restore, theme, 390-pixel layout,
logout/token revocation and reload. No browser storage holds a token/credential.
The fixture's runtime/router/subscription transport are **simulated**. This is UI
contract proof, not another CHR packet-path proof; the
[accepted Phase 4 native evidence](product-phase-4-api-completion.md) remains its
dataplane basis. No real subscription/router was modified for UI acceptance.

Firefox failed before application navigation in both headless/headed launches
on this Mac, with sandbox/compositor errors. It remains a selectable test project,
not a passing result; wider browser/device coverage belongs to hardening.
Playwright's WebKit screenshotter injects transient inline `body {}` CSS. The
unchanged CSP correctly rejects this capture-only operation; tests require zero
application violations and attribute only that exact screenshot utility event.

An actual-browser regression caught `structuredClone` rejecting Svelte state
proxies after login. JSON-only model snapshots now handle nested reactive proxies;
the regression test and the complete browser rerun passed.

The wizard intentionally reviews a preprovisioned profile. It does not install a
RouterOS App or provision arbitrary VETH/firewall/topology. Full encrypted
credential backups, suffix admission/IPv6 and broader native/browser/device
release acceptance are outside this phase. UI text is Russian; theme/time zone
are supported, and the backend language preference is preserved.

Evidence: [browser contracts](product-phase-5-evidence/browser-contracts.json),
[bundle hashes](product-phase-5-evidence/bundle.json),
[validation](product-phase-5-evidence/validation.txt),
[desktop](product-phase-5-evidence/chromium-dashboard.png) and
[mobile](product-phase-5-evidence/chromium-mobile.png).
Operation: [Web UI guide](../api/web-ui.md),
[adapter contracts](../api/web-ui-adapters.md),
[ADR-0020](../adr/0020-embedded-administrative-ui.md).
