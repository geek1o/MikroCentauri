# Product Phase 7: security foundation

Historical intermediate status; superseded by [Phase 7 completion](product-phase-7-hardening-completion.md) for its pinned native profile.

Date: 2026-10-07. Status: first hardening block complete; **product Phase 7 remains
in progress**. Starting point: Phase 6 commit `b129cc5`, with pinned CHR 7.24.5
x86_64 and sing-box 1.14.2 acceptance. This block changes production download and
RouterOS CLI transport behavior, strengthens regression coverage and replaces
obsolete prototype security documentation.

## Reproduced defects and corrections

Six local regressions failed before the patch and passed with Go's race detector
after it. The fixtures use only isolated HTTP/TLS test servers and synthetic URLs.
[Before](evidence/phase-7-security/before-fix.txt) and
[after](evidence/phase-7-security/after-fix.txt) output is retained in Git.

| Boundary | Before | Corrected behavior |
| --- | --- | --- |
| Subscription redirect | Go added the full source URL as Referer, including a credential-bearing query | Delete Referer on every redirect |
| HTTPS rule-set redirect | Same disclosure to the redirect destination | Delete Referer on every redirect |
| Subscription CIDR authority | Constructor retained the caller's mutable prefix slice | Copy prefixes on construction |
| Rule-set CIDR authority | Constructor retained the caller's mutable prefix slice | Copy prefixes on construction |
| Rule-set TLS trust | Constructor retained the caller's mutable certificate pool | Clone the operator trust store |
| Production CLI RouterOS transport | Cloned default transport retained its proxy hook | Explicitly disable proxy before making control requests |

The redirect tests complete a successful download and inspect the destination's
received header. Policy tests mutate the caller's original inputs after manager
creation, then require denial without any HTTP handler hit. The RouterOS test
installs a default proxy hook, performs real TLS discovery and requires zero hook
calls. TLS verification remains enabled. Existing download bounds, checked-IP
dialing, redirect limits and last known good state are preserved.

Mutable policy defects are caller-side authority changes, not evidence that an
unauthenticated remote client can modify operator policy. The proxy defect concerns
the unreviewed control network path; these tests do not demonstrate plaintext
RouterOS credential disclosure through verified TLS. The lower-level client still
allows an explicitly supplied transport; callers own its configuration.

## Regression and packet-path boundaries

[Targeted regression output](evidence/phase-7-security/regression.txt) covers remote
SSRF/URL redaction, redirect bounds, timeout and LKG, API origin/authentication,
session expiry/rate limits, private credential projections and diagnostics,
activation crash recovery and quarantine failures. These are local tests with
controlled failures, not a new native router reboot acceptance.

The selected-domain DNS test now explicitly checks TXT, SVCB and HTTPS rejection
as well as empty AAAA. None of those requests may reach the allocator or publisher.
This supports the managed IPv4 DNS boundary. It does not prevent cached/literal
IPv6, a different resolver or client DoH/DoT. Automatic router IPv6 detection and
the full leak matrix remain unfinished.

Existing Phase 6 native packet, App restart and immutable-image rollback acceptance
is recorded in [the completion report](product-phase-6-app-completion.md). No CHR,
physical router, real subscription or external deployment was changed in this
block. The new image receives packaging verification, not a fresh native packet
acceptance. No broad FastTrack disable or IPv6 firewall mutation was introduced.

## Build validation

`make check cross-build` passed: complete Go race tests and vet, integration and
sing-box smoke checks, frontend validation/build, whitespace checks and Linux
amd64/arm64 builds. [Full output](evidence/phase-7-security/validation.txt) is
retained. The targeted DNS test expansion also passed in the separate regression
run linked above.

Updated local App images were built in `.cache/app-image-phase7` and independently
verified for OCI digests, ELF architecture, RouterOS archives and secret-free
packaging on both architectures. [Verification](evidence/phase-7-security/image-verification.txt)
and [build metadata](evidence/phase-7-security/image-build.json) are retained.
The new index is `sha256:f7426c71b4f39a7c883f54fd17f0c3ed628c27488db6ab1265357413bac7c9fe`.
These images have not been published or admitted on CHR in this block.

Subsequent [IPv6 observation](product-phase-7-ipv6-observation.md) implements the
read-only detection and visible deployment policy in the first item below; the
packet experiments and other acceptance gates remain open.

## Remaining Phase 7 acceptance

- Read-only IPv6 capability detection and visible deployment policy, followed by
  controlled cached/literal IPv6, alternate-DNS and managed-query experiments.
- Full FastTrack matrix for managed traffic, DIRECT and source policies while
  preserving unrelated router rules.
- Native reboot/failure matrix on the updated image, including admission timing,
  durable recovery and fresh TCP/UDP/HTTP3 packet witnesses.
- Sustained resource, physical arm64, RouterOS version and browser coverage.
- Complete security review beyond the download/control transport surfaces.

Phase 8 release candidate and publication remain separate. Current implemented
boundaries and limitations are summarized in [security status](../security.md).
