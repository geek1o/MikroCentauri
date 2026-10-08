# Site-list and subscription workflow verification

Date: 2026-10-08. Scope: host-side API, parser, engine schema and browser contracts.
This report does not establish RouterOS installation or packet-path acceptance.

## Behavior

- Eleven ready service/category lists download from the public
  `itdoginfo/allow-domains` repository; an HTTPS custom list is also supported.
- Downloaded domain snapshots become draft suffix rules with individually
  selectable outbounds. Refresh preserves the selected outbound. Failed fetches
  retain the cached snapshot and do not replace the configuration.
- Subscription imports retain supported distinct URI endpoints, show counts and
  safe per-line reasons for unsupported entries, and can atomically extend/create
  a manual selector. Unsupported transports are not downgraded.
- Visible server selectors update the draft; apply still requires its plan.
- System-dark surfaces, links and status text use theme-aware colors. Mobile
  navigation exposes every section without horizontal scrolling.
- The manual preview uses production subscription downloads. Automated browser
  contracts use a deterministic provider fixture and an actual local HTTPS
  domain-list source. Both explicitly label their simulated RouterOS runtime.

## Validation

- Full `go test -race ./...` passed with the pinned sing-box validator; focused
  API/parser/list regressions passed after the final changes. `go vet ./...`
  passed.
- A real trusted-local-TLS subscription download retained all 20 supported
  endpoints and reported one unsupported entry. A subsequent invalid response
  preserved the valid cache.
- Seven extended endpoint profiles passed the actual sing-box 1.14.2 schema
  checker. TLS validation remains enabled; XHTTP, custom gRPC authority and
  insecure TLS requests are refused.
- Domain-list tests cover parsing, deduplication, explicit limits, source privacy,
  invalid-refresh preservation, symlink refusal and digest syntax.
- API regressions cover stale revision rejection, atomic selector creation,
  no partial update on invalid selection, and downloads that do not block health
  reads or overwrite a concurrently changed draft.
- Chromium and WebKit cover subscription import, HTTPS custom-list download,
  list assignment, visible server selection and configuration planning.
  Desktop (1280 px) and mobile (390 px) light/dark/system themes retain a draft
  text contrast ratio of at least 4.5:1 and avoid horizontal overflow.
- All eleven catalog sources downloaded and parsed during the live source audit.
  The broad upstream Block file is excluded because it contains the top-level
  `.ua` suffix, outside the current domain model. No rule is silently dropped.
- Frontend type checking, unit tests, production build and asset budget passed.

## Remaining limits

Site-list refresh is manual. Native DNS admission remains a finite reviewed
namespace; suffix rules do not automatically admit arbitrary new subdomains.
IP-subnet lists, alternate-DNS traffic, IPv6 routing and full Podkop/Forkop
packet-path equivalence are not established by these UI checks. Live server
connectivity and traffic forwarding require separate network acceptance.

Private source URLs, endpoint credentials and user inventory are excluded from
this report, browser artifacts and repository evidence.
