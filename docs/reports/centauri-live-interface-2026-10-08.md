# Centauri interface and live-engine acceptance

Date: 2026-10-08. Branch: develop. Scope: host-side browser, private controller,
parser and schema integration; native RouterOS interception is separate.

## Changes

- Celestial visual system: indigo/midnight semantic surfaces, warm star mark,
  orbital dashboard graphics, responsive server cards and readable theme states.
- Searchable interactive selectors show the current engine member, protocol,
  address, latency, measurement time, failed checks and draft-only state.
  Ordering supports source order, names and measured latency.
- Live member selection uses authenticated private sing-box Clash API calls,
  revision/membership validation and read-back confirmation. It changes neither
  policy revision nor draft. Network checks do not hold the selector lock.
- Native control is serialized with transitions, permits recovery selection on
  a live unready engine, and cannot release readiness or the traffic gate.
- A real local SOCKS engine is available in the manual preview. RouterOS remains
  simulated; actual engine actions are explicitly identified in the banner.
- Twenty-seven catalog sources: sixteen domain lists and eleven IPv4 lists.
  CDN entries include Cloudflare, CloudFront, Hetzner, OVH and DigitalOcean.
  Domain/network filters and a sticky import summary reduce catalog navigation.
- Private network snapshots create destination-CIDR rules without adding network
  prefixes to the DNS admission namespace. Invalid/reserved/IPv6/over-limit
  records are refused; failed refresh preserves the valid snapshot.

## Verification

- All 27 public source URLs downloaded and parsed in a live catalog audit.
- Full `go test -race ./...` passed with the pinned engine. Focused tests passed
  after final control/recovery and measurement-metadata changes.
- The private bridge was exercised against an actual sing-box 1.14.2 process:
  member selection was read back without replacing the process.
- API tests reject stale revisions, unknown groups/members and failed engine
  actions. Successful selection does not create a draft or bump a revision.
  Recovery tests reject stopped/pending engines and do not publish readiness.
- CDN tests prove canonical public-IPv4 parsing, private snapshot reload and
  CIDR rule creation without DNS namespace changes.
- Four browser scenarios passed in each of Chromium and WebKit with a real
  local sing-box controller. They include card selection, unchanged revision,
  actual failed delay checks for unreachable documentation-range test nodes,
  catalog filters and HTTPS list import. Six desktop/mobile theme combinations
  retain draft text contrast >=4.5:1 without horizontal overflow.
- Frontend type/unit checks, production build, asset budgets and `go vet ./...`
  passed. Synthetic screenshots were visually reviewed; they contain no real
  subscription names, URLs, credentials or inventory.

## Boundaries

The manual preview uses a real loopback SOCKS engine and production subscription
fetching; it does not steer the host or RouterOS. Latency is an HTTPS URL test,
not ICMP or continuous availability. Existing connections are not interrupted
by selection. Public-IP interception, arbitrary-subdomain native admission,
IPv6 routing, binary SRS/adblock/country-source parity and complete Forkop native
packet-path equivalence are not established by this report.
