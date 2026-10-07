# Phase 7 management and download security review

Date: 2026-10-07. Scope: production management composition, API authentication,
secret projections, safe backup/restore, diagnostics, launch/provisioning and
remote subscription/rule-set downloads. This report supplies the management
security gate; native packet-path, reboot and FastTrack acceptance is recorded
separately in the Phase 7 completion report. Review and tests used synthetic
credentials, local test servers and a local DNS fixture. No production router,
provider subscription or external service was contacted.

## Reproduced defect and fix

`api.New` validated `Options.Clients` but retained the caller-owned prefix slice.
Changing that slice after construction replaced the live socket admission policy.
The regression `TestClientAdmissionCannotBeWidenedAfterConstruction` first proves
that a documentation-range socket is refused, mutates the original slice to admit
that socket, then requires continued refusal and continued admission of the
original loopback client. It failed before the fix with:

```text
--- FAIL: TestClientAdmissionCannotBeWidenedAfterConstruction
    caller mutation widened live API admission
FAIL mikrocentauri.local/core/internal/api
```

The server now owns a copy of the validated policy. The test and full API race
suite pass. Severity is low for the current production CLI: its slice is composed
locally and is not mutated by a remote API operation. The defect nevertheless
violated the constructor's authority boundary and permitted integration code to
change policy without a new server configuration. This is not evidence of an
unauthenticated remote privilege escalation.

## Download regressions

New `download_security_test.go` files in both downloader packages use a controlled
local UDP DNS fixture, real HTTPS handlers and the explicit test-only loopback
CIDR override. The tests verify observable network behavior:

| Experiment | Required result |
| --- | --- |
| One DNS answer contains allowed loopback and denied private IPv4 | Reject the entire result before the HTTP handler is reached |
| First lookup is allowed; later lookups return private IPv4 | First download succeeds after exactly one A lookup, proving the transport dials the checked literal without another hostname resolution; the next download performs a fresh lookup and is denied |
| Allowed HTTPS origin redirects to a reachable, denied IPv6 loopback HTTPS server | Destination handler receives no request; download fails |
| Allowed HTTPS origin redirects to a reachable plain HTTP server | Destination handler receives no request; download fails |

The TLS fixtures cover the tested hostnames and trust roots, so the permitted
first download is a positive control. Private redirect fixtures have valid TLS
for their destination IP; absence of a handler hit is not attributed to an
unreachable destination or an invalid certificate. The tests require no public
DNS or HTTP access. They run serially within each package while replacing
`net.DefaultResolver`, restore it during cleanup, and pass under the race detector.

Existing Phase 7 regressions already establish omission of credential-bearing
Referer on redirect and immutable copied CIDR/certificate policies. Existing
subscription/rule-set tests cover size/time/redirect bounds, invalid inputs,
private state, LKG preservation and pinned engine compilation. No new production
downloader change was needed for the additional DNS and redirect experiments.

## Reviewed threat boundaries

| Surface | Current behavior and verification |
| --- | --- |
| Management transport | Production server requires TLS 1.3; listener is a literal loopback/private address; LAN listen requires explicit client CIDRs. Header/body/connection time limits and eight admitted request slots bound resource use. Exact configured Host and Origin are checked; forwarded client headers never grant socket admission. |
| Authentication | PBKDF2-SHA256 with 600,000 iterations and a random 32-byte salt; credential file contains a hash rather than plaintext. Random bearer sessions expire after 30 minutes, are held as SHA-256 token digests in memory, and disappear after restart. Global login window and session count are bounded. Closed auth state refuses login and validation. |
| Browser secrets | Bearer token is held in the frontend module's memory, not local/session storage. Login password input is cleared before the request; credentials are not placed in URLs. Embedded assets retain the TLS/socket/origin boundary and restrictive CSP. |
| Filesystem | API state uses bounded regular 0600 reads with no-follow/nonblocking flags, 0700 directories and exclusive ownership locks. Private bootstrap reads also reject symlink parents. CLI/App settings are strict bounded JSON; duplicate/unknown fields fail. These controls do not protect against a privileged actor able to replace process memory or mount state. |
| Secret output | Proxy/WireGuard previews, subscription views, policy reviews and history use explicit public projections or enum codes. Raw dependency errors, child stderr, subscription source URLs and private models are excluded from API errors and ordinary diagnostics. Bundle members have fixed names/private modes and a cumulative size bound; bundles never read arbitrary files. |
| Backup/restore | Safe backup excludes proxy/WireGuard keys, remote source URLs, canary URLs and local cache paths. Restore reuses matching local private identity, creates a reviewed draft and uses the same single-use plan/CAS owner as normal activation. Allocator journals and engine cache are not restored by safe backup. Restore settings replay only after proving the exact model/revision committed. |
| Downloads | Production API subscription `validateSpec` requires HTTPS. The lower-level subscription manager separately supports HTTP compatibility; HTTP provides no confidentiality. Remote rule sets require HTTPS. TLS verification stays enabled, every resolved IP is checked before dialing, redirects are bounded and revalidated, and environment proxies are disabled. Explicit operator CIDR overrides intentionally grant matching private destinations. |
| Imported content | Invalid subscriptions and unsupported rule predicates fail before activation. Imported endpoints enter a draft and require normal validation/plan/apply; a subscription provider is not a trusted authority to activate nodes. Rule-set compilation uses bounded inputs and contexts, a pinned compiler version, and immutable hash-checked local artifacts rather than engine-side remote URLs. |
| Diagnostics | Diagnostic kinds are fixed enums; node probes select an already active endpoint. Canary/DNS targets come from the private operator profile, not arbitrary browser URLs. Node probes run a separate child/cache without TUN or RouterOS writes; child output is consumed for readiness and is not returned. Probe commands and HTTP canaries are bounded and reject redirects. |
| Launch/provisioning | Go App launcher establishes restrictive inherited permissions. One-time provisioning admits only unique allowlisted regular private tar members in bounded totals, stages a complete validated bundle and refuses overwriting durable content. `app.json` is published last; reported output contains fixed status fields. Existing authentication is reopened rather than reset on restart. Installation review checks image identity, stopped/disabled state, persistent mounts and executable-shadow/command override denial. |

The read-only review found no additional established defect in backup, diagnostics,
launch or provisioning. This is a source review and targeted acceptance, not an
independent penetration test or a claim that every possible dependency defect is
excluded.

## Validation

All commands ran in the repository with Go 1.27.1:

```sh
.cache/go/bin/go test -race ./internal/api
.cache/go/bin/go test -race ./internal/subscriptions ./internal/rulesets -run '^TestSecurity' -count=1
SING_BOX_BINARY="$PWD/.cache/sing-box-1.14.2-darwin-arm64/sing-box" .cache/go/bin/go test -race ./internal/subscriptions ./internal/rulesets ./internal/application ./internal/health -count=1
.cache/go/bin/go test -race ./cmd/mikrocentauri -run '^Test(AppProvision|AppInstall|AppAuthentication|AppSettingsPrivate|AppTLSLiveness|RouterControlDoesNotInherit|ConnectionTrustAndTransport|PrivateInputs)' -count=1
```

Results: API passed (80.657s); additional DNS/redirect tests passed in both
packages; complete downloader/application/health packages passed with the actual
pinned sing-box binary (1.360s/1.818s/2.082s/1.330s); selected CLI/App security
regressions passed (3.389s). The aggregate final build and native acceptance are
performed by the root Phase 7 completion workflow.

## Explicit accepted limitations

- A trusted operator controls private profile, credentials, topology, certificate
  trust and any intentional private-destination overrides. A privileged host or
  RouterOS administrator can replace those controls and is outside their protection.
- Safe backups are redacted application exports. Full encrypted credential backups
  and secret rotation workflows are not implemented; private at-rest deployment
  files require operator protection and retention policy.
- The global login limiter can temporarily deny legitimate login after attempts
  from an already allowed management network. It bounds hashing work but is not
  availability isolation between allowed clients.
- Fixed operator canaries may use HTTP, as isolated fixtures do; trusted HTTPS
  canaries are required where authenticity of the network observation matters.
- Downloader controls are an application fetch boundary, not a general firewall.
  Endpoint connectivity deliberately uses the operator-approved proxy configuration;
  imported provider content still requires review before activation.
- IPv6/FastTrack/reboot guarantees are scoped to the separate, pinned native
  acceptance. This management review does not establish physical ARM, arbitrary
  RouterOS versions, all topologies, or complete prevention of alternate DNS/DoH.
