# Product Phase 2: HTTPS discovery and durable staging controller

## Outcome

The product CLI now discovers RouterOS capabilities and plans, stages, reconciles
and recovers explicitly disabled owned objects over certificate-verified HTTPS.
This block advances original product Phase 2; it does not close that phase or
constitute product Phase 8 release acceptance. Native server: CHR x86_64 RouterOS
7.24.5 (stable), built-in `www-ssl`; executed CLI: darwin/arm64.

## Implemented contract

- `router-inspect` reads version, platform, packages, interfaces and availability
  of five managed resources. Discovery does not expand the mutation allowlist.
- `router-plan` creates a private schema-versioned artifact from fresh discovery
  and application configuration. The configured LAN interface must exist and be
  enabled. Staging accepts only the verified CHR 7.24.5 profile; inspection can
  describe other profiles without approving them.
- `router-stage` applies the exact reviewed plan and rejects changed preconditions.
- `router-reconcile` recovers a pending transaction, discovers current state,
  plans against the artifact's complete desired set and applies under one process
  lock. An explicit empty desired array requests cleanup of owned disabled objects.
- `router-recover` restores an interrupted transaction using durable journal and
  native readback. Ambiguous outcomes retain pending state until recovery succeeds.
- Before, after and realized journal objects must be explicitly disabled. Active
  objects, foreign edits, unsupported scripted Netwatch deletion and ordered
  firewall deletion are refused rather than losing unrecorded ordering or hooks.
- Connection secrets and artifacts require regular 0600 files with no symlink
  ancestors. Journals use a private directory and exclusive lock; JSON parsing
  rejects duplicates, unknown fields, trailing content and excessive nesting.
  HTTPS uses TLS >=1.2, system roots plus an optional explicit CA, without an
  insecure mode. Errors do not include credentials or raw server response bodies.

Capability presence and the accepted version profile do not prove write rights,
container device-mode, TUN support or production readiness. Native mutation below
separately demonstrates write/readback for the tested disabled route.

## Verification

`make check cross-build` passed: race tests, vet, pinned sing-box checks,
namespace/binding/smoke integration and linux/amd64 plus linux/arm64 builds.
Python scripts compiled and `git diff --check` passed.

Native CLI acceptance passed against CHR's own HTTPS service:

1. Discovery accepted the actual CHR board description and all five resources.
2. A disabled owned route was created and read back; repeated reconciliation was
   idempotent with the same native object identifier.
3. An external distance change made the reviewed plan stale. Exact staging
   rejected it and preserved the external value; fresh reconciliation applied
   the requested disabled state.
4. An active candidate was rejected. Committed recovery was a no-op, and an
   empty desired set removed the disabled canary.
5. Configured-state hashes for unrelated objects across all five tables matched
   before and after: `f0330bfbb6f195c1a0ca9da4991c38da69be3921302a45bd9c3db75ceb027c31`.
6. Planning from application configuration produced three disabled desired
   objects. The same HTTPS endpoint without its explicit CA was rejected.
7. The lab transport discarded a successful native PUT reply and blocked further
   requests. A disabled route existed while its durable journal remained pending.
   A fresh CLI process recovered it, removed the route and recorded `rolled-back`.

Evidence: [native CLI](product-phase-2-evidence/native-results.json),
[planning and TLS](product-phase-2-evidence/extra-cli-results.json),
[lost reply](product-phase-2-evidence/lost-reply-results.json),
[host checks](product-phase-2-evidence/host-checks.log),
[binary identity](product-phase-2-evidence/binary.json),
[cleanup](product-phase-2-evidence/cleanup.json).
The binary SHA describes the executed pre-commit `-buildvcs=false` build, not a
release artifact. No connection file, private key or PKCS#12 archive is published.

## Cleanup and remaining work

Canary routes, temporary certificate and imported archive were removed; the
original `www-ssl` settings were restored. The CHR was shut down normally and its
persistent lab disk retained. The existing gateway was not started for this block.

This is management-plane acceptance, not another TCP/UDP/QUIC dataplane test.
Enabled-rule integration, placement-aware rollback, generic native watchdog
installation, full desired-state coverage and broader device/version acceptance
remain open in product Phase 2. Core subscriptions, groups, general rules and
supervisor/LKG remain open in Phase 3. No production installation or router
credentials are needed to reproduce this disposable lab proof.

## Primary references

RouterOS [REST API](https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST%2BAPI)
explains HTTPS via `www-ssl`, Basic authentication, string-valued JSON and CA trust.
RouterOS [Certificates](https://help.mikrotik.com/docs/spaces/ROS/pages/2555969/Certificates)
describes certificate import and service certificate use. These references explain
the interface; the evidence above establishes behavior on the pinned CHR build.
