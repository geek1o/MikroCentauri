# Product Phase 7 — native hardening progress

Historical intermediate status; superseded by [Phase 7 completion](product-phase-7-hardening-completion.md) for its pinned native profile.

Date: 2026-10-07. Phase 7 remains **in progress**. All observations below concern
only the disposable CHR 7.24.5 x86_64 / sing-box 1.14.2 synthetic fixture.

Management review and targeted admission/DNS/redirect regressions are recorded in
[the security review](phase7-management-security-review.md). The API now freezes
its validated socket CIDRs instead of retaining a mutable caller slice.

A rejected full native attempt passed FastTrack OFF/ON TCP/UDP/HTTP3, exact DIRECT
conntrack evidence, IPv6 DNS controls/literal bypass/scoped operator guard,
VLESS SIGSTOP/resume, real engine and owner SIGKILL, independent cold startup
quarantine and two consecutive enabled-App reboots. It then failed the minute
load oracle: selected DNS returned REAL and used DIRECT. These successful partial
observations are not complete acceptance. Subsequent attempts also observed
readiness withdrawal and missing UP lease; a lifecycle history identified a
core verification failure after cold startup. The initiating verification stage
was not available in the earlier image; a causal attribution remains open.

The runtime now emits fixed namespace/cache/allocator/publication failure codes,
with regressions proving that classification still quarantines forwarding and
omits private dependency errors. A separate `--hardening-probe` experiment stores
load/state/history snapshots and is explicitly diagnostic only: it never sets
`accepted` or `completed`. Final native acceptance, immutable-image rollback,
exact-run captures and resource checks remain required before closing this phase.

A digest-bound, separately reviewed operator startup scheduler addresses the
observed App child boot limitation. It never enables a disabled App, checks the
exact container config digest, waits for the child to stop and rechecks identity.
The controller startup steering guard remains independent. See
[installation](../install.md#reviewed-boot-configuration).

A separate boot test-oracle defect was established: the scheduled App restart
invalidated a bearer session obtained earlier. Old authenticated queries returned
401; a fresh login returned ready=true. The acceptance harness now refreshes only
on 401 and still requires actual readiness and a fresh dynamic lease.

Private disks, credentials and raw captures remain outside Git. Validation and
rejected-observation summaries are staged under `evidence/phase-7-completion`;
that directory name is not a completion claim. A final report will identify the
accepted exact run and supersede this intermediate status when all gates pass.

## Follow-up: private publication lease proof

The diagnostic image localized the withdrawal to publication. A private
`Adapter.Check` proof could cross the old TTL floor and return
`ErrLeaseExpiredDuringVerification`; unlike reconcile, it did not renew once.
The bounded correction retries only that sentinel, verifies from a fresh DNS
origin and never extends the authoritative TTL. Persistent expiry, other failures,
invalid receipts and cancellation still quarantine; public DNS remains strict.

The regression fails with renewal disabled and passes after correction. Native
corrected diagnostics observed eight `publication_lease_refreshed` events and
17 successful PROXY/DIRECT load pairs through 153 seconds without readiness
withdrawal. A later DNS SERVFAIL retained ready=true. Another full native attempt
passed all 19 forwarding/failure/reboot stages, then encountered a DNS SERVFAIL
with readiness retained. Neither diagnostic nor rejected attempt is acceptance.

The final resource smoke therefore exercises cached verified aliases and literal
real IPs; it separately retains the fresh-DNS denial limitation. Immutable-image
UDP checks also use the admitted cached alias, matching their cache-preservation
scope. Full acceptance/capture evidence is still pending.
