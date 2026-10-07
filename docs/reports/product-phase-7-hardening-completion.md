# Product Phase 7 — hardening completion

Date: 2026-10-07. Acceptance is scoped to **CHR 7.24.5 x86_64, sing-box 1.14.2,
Alpine 3.24.2 and the explicit synthetic laboratory profile**. Product Phase 7's
Phase 8 release qualification/publication is separate. This report supersedes
open packet/reboot/failure gates in the Phase 7 foundation and IPv6 observation
reports; it does not turn earlier limited evidence into general device acceptance.

## Checklist and evidence

| Deliverable | Accepted behavior |
| --- | --- |
| Security review | Management, auth, private state, backup/restore, diagnostics, imports and launch/provisioning reviewed. API freezes caller-provided client CIDRs; the authority-mutation regression failed before the fix and passes afterward. |
| SSRF controls | Mixed permitted/denied DNS answers fail before HTTP; checked literal dialing performs no second hostname lookup; the next download rejects rebound private IPs; denied IPv6 and HTTPS-to-HTTP redirects do not reach destination handlers. Earlier immutable CIDR/CA and Referer regressions remain accepted. |
| Secret handling | Protected bootstrap and inherited umask, secret-free images, redacted API/diagnostics/safe backup and unchanged original private bytes through real image replacement/rollback. Restart preserves credential hashes and invalidates in-memory bearer sessions. Full encrypted credential backup remains unsupported. |
| FastTrack compatibility | User rule OFF/ON; selected PROXY, native DIRECT, managed bound DIRECT, source PROXY and source DIRECT each exercise TCP, UDP and HTTP/3. A specific 512 KiB DIRECT conntrack tuple records fasttrack=false/true under OFF/ON. Original user rule is restored. |
| IPv6 leak handling | Read-only settings/status and UI warnings; real upstream AAAA positive controls, managed empty AAAA, unselected AAAA preserved, managed SVCB/HTTPS fail closed over UDP/TCP. Literal IPv6 bypass is reproduced and explicitly unsupported; an operator-scoped guard blocks the tested source/target and removal restores it. |
| Reboot tests | Independent startup guard closes all three persistently enabled steering targets while Netwatch and App are disabled; no RAM UP lease survives. Cached/fresh traffic is DIRECT, then manual startup restores PROXY. Digest-bound operator bootstrap passes disabled-App and wrong-digest checks and two consecutive enabled-App reboots. |
| Failure injection | Remote VLESS process SIGSTOP/resume, real engine SIGKILL with new PID, owner SIGKILL and native restart. DOWN cached aliases/fresh DNS and restored TCP/UDP/HTTP3 are checked; image replacement and rollback use different actual image configurations and preserve protected bytes. |

Management details: [security review](phase7-management-security-review.md),
[foundation](product-phase-7-security-foundation.md) and
[IPv6 observation](product-phase-7-ipv6-observation.md).

## Native boot procedure and rejected observations

An enabled App with its generated child `start-on-boot=false` did not recover
without an operator step. Compose `restart: unless-stopped` left that flag false
on the tested release. Setting the child flag true recovered once, but App setup
reset it false. The accepted procedure uses `scripts/render-app-boot.py`: separate
operator bootstrap, exact App/container names, exact OCI config digest, enabled-App
condition, bounded child stop before re-enable and a second digest check. It does
not grant privilege or enable forwarding. The independent controller startup guard
still owns steering. See [installation](../install.md#reviewed-boot-configuration).

The first bootstrap test also exposed a test-oracle error: login could precede the
scheduled App restart, so the accepted old session became unauthorized. Captured
system/log queries returned 401 while an independent new login returned current
ready=true and recovery_verified. The harness now refreshes a session only on 401
and continues requiring actual native readiness and a fresh dynamic lease.

Rejected attempts remain documented in the evidence. Immediate REST/UP-lease
readback did not guarantee observed NAT cutover: initial/recovered probes sometimes
saw DIRECT or EHOSTUNREACH before convergence. DOWN tests now require all three
steering objects disabled as well as lease absence, then a one-second quiet period.
UP tests also include a one-second quiet period. No zero-delay, atomic cutover,
continuous existing-session or zero-loss guarantee is established.

The earlier 2 s/1 s Netwatch profile (5 s RAM lease) and 256 KiB sustained exercise
did not meet the continuous-UP oracle. The accepted TCG fixture explicitly uses
**10 s interval, 3 s timeout, two successes, 23 s finite lease**, and a modest
64 KiB cached-alias/real-IP transfer pair every five seconds for at least one minute. Fresh DNS is tested separately and can return SERVFAIL when a proof crosses the TTL floor. These are the
accepted test settings, not a proven attribution of every earlier failure or a
hardware capacity recommendation. The reported fault-to-DOWN/fallback duration
includes workload verification, not an isolated lease-withdrawal latency.

## Verification lease defect found during acceptance

The diagnostic image localized an uncommanded withdrawal to
`core_publication_check_failed`. `Host.verify` first reconciles real-target mappings,
then `Adapter.Check` validates the engine namespace and freshly publishes each
alias again. The second proof can cross the old authoritative TTL's one-second
floor. Reconcile already renews such an expired proof once; the private adapter
check instead treated it as a fatal verification failure and withdrew readiness.

The adapter now retries **only** `ErrLeaseExpiredDuringVerification`, once and
inside its existing context bound. The publisher resolves from a new authoritative
origin and verifies again; no TTL is extended. Persistent expiry, other backend
errors, invalid receipts and cancellation still quarantine forwarding. Public DNS
publication retains its strict denial behavior. Fixed lifecycle codes distinguish
namespace/cache/allocator/publication failures without returning dependency errors.

The new private-check regression fails with the retry disabled and passes with
it enabled; repeated expiry is limited to two calls and unrelated backend errors
to one. The existing real publisher regression still refuses an expired public
DNS receipt. Native corrected-image diagnostics observed 17 successful load pairs
through 153 seconds and eight `publication_lease_refreshed` events without a
readiness withdrawal. The next selected DNS query returned SERVFAIL while native
readiness remained true; the follow-up snapshot also retained readiness. That
strict DNS denial is preserved as a limitation and is not called a proxy outage.
These diagnostic runs never set accepted/completed; the final full acceptance is
recorded separately below. They do not retrospectively identify every earlier
rejected attempt's cause.

## Captures and resources

Accepted run: **`1791398213085080000`**; native `accepted=true`,
`completed=true` and hardening `completed=true`. The final image index is
`sha256:0ae1b54998cf60e48deec5b766a4c20d711b6f5c8db907b492e0af47f8a7a24f`;
its amd64 config is `sha256:a3750b0dce3c211026ad85828bef3cd72da109d24ea2cbd41edd96a68076cd86`.

| Observation | Result |
| --- | --- |
| Forwarding stages | 19 hardening stages; 23 exact-run UDP witnesses including initial App paths and both immutable image changes |
| FastTrack | User rule OFF counter unchanged at 4245; ON DIRECT counter rose to 4448; separate new 512 KiB tuples prove fasttrack=false/true |
| IPv6 | 10 DNS queries; bypass/restoration HTTP markers on LAN and WAN; guard counter 3, positive LAN SYNs and zero matching WAN SYNs in the guarded window |
| Engine SIGKILL | PID 163 → 293; unready observed and verified recovery |
| Cold reboot | Persisted steering closed with App and observer disabled; cached and fresh DIRECT; manual recovery PROXY |
| Automatic reboot | Two consecutive actual boots, startup scheduler run-count=1 each, fresh dynamic lease and TCP/UDP/HTTP3 PROXY |
| Cached-flow resource smoke | 68.12 seconds; 11 pairs × 64 KiB per transfer; each path and readiness/lease checked |
| RSS/swap | Owner 16628 → 16740 KiB; engine 60168 → 61924 KiB; swap=0 |
| Image rollback/return | Two different OCI configs; all original private bytes and cache equal before startup; cached TCP/UDP/HTTP3 accepted on both |
| Cleanup | Exact controlled objects absent, original FastTrack restored, App disabled; private state retained and all 11 test listener ports closed |

The [evidence directory](evidence/phase-7-completion/) contains native results,
filtered exact-run capture records, UDP/IPv6 witnesses, build metadata, diagnostics,
regression logs and cleanup proof. Full PCAP SHA256 digests are retained in the
summaries; aggregate frame counts describe the whole multi-attempt captures, while packet
acceptance uses only this run's markers and scoped IPv6 guard window.


Packet witnesses require exact run ID, unique UDP markers, correct LAN source,
actual WAN forwarding path and every expected hardening stage. IPv6 verification
requires both LAN/WAN HTTP markers for bypass/restoration, positive LAN SYNs and
zero matching WAN SYNs in the scoped guard window. Negative unit checks reject
wrong runs/sources/paths, missing stages, leaked guard SYNs, absent witnesses and
truncated PCAP records. Raw captures and private disks remain outside Git; safe
summaries bind retained evidence to their SHA256 digests.

## Validation and reproduction

The evidence directory retains full make check/cross-build, actual pinned-engine
integration, targeted admission/DNS/redirect regressions, frontend checks/build,
four Chromium/WebKit HTTPS contracts, seven evidence/boot-renderer regressions,
both OCI architecture verifications, native results and capture verification.

```sh
make check cross-build
python3 scripts/test-webui.py --node <available-node>
python3 -m unittest discover -s tests/e2e -p test_capture_verifiers.py -v
python3 scripts/verify-app-image.py --out .cache/app-image-phase7-complete
python3 tests/e2e/chr_app_native.py --hardening \
  --oci .cache/app-image-phase7-complete/oci \
  --rollback-oci .cache/app-image-phase7-ipv6/oci \
  --work .cache/phase7-hardening
python3 scripts/summarize-lab-pcap.py \
  .cache/phase7-hardening/lan.pcap .cache/phase7-hardening/wan.pcap \
  --out .cache/phase7-hardening/capture-summary.json
python3 scripts/verify-app-capture.py \
  --results .cache/phase7-hardening/native-results.json \
  --captures .cache/phase7-hardening/capture-summary.json \
  --out .cache/phase7-hardening/udp-witnesses.json
python3 scripts/verify-phase7-capture.py \
  --results .cache/phase7-hardening/native-results.json \
  --captures .cache/phase7-hardening/capture-summary.json \
  --out .cache/phase7-hardening/ipv6-witnesses.json
```

The native command requires the separate prepared CHR clone and bounded Linux
fixtures described in [the lab](../lab.md). It uses synthetic private inputs,
actual default production entrypoint/healthcheck and explicit operator privileges.
All test listeners are stopped afterward; the original disks are not opened by
QEMU. Temporary IPv6/guard/bootstrap fixtures and app6 objects are removed; test
private state and rejected fixture disks remain locally for review.

## Limits carried into release qualification

- No physical ARM throughput/RAM/thermal/storage result, RouterOS 7.22 runtime
  acceptance, Firefox acceptance or arbitrary topology/protocol/provider matrix.
  arm64 packaging/ELF/hash verification is not native arm64 acceptance.
- IPv4 MVP: no complete IPv6 routing, literal/cache/alternate-resolver enforcement,
  general DoH/DoT blocking or IPv6 source-policy parity. Operators must review
  network policy for clients requiring enforced proxy isolation.
- Source PROXY/DIRECT tests cover admitted IPv4 aliases. They do not establish a
  full-traffic proxy policy for arbitrary unsteered real-IP destinations.
- One-minute cached-flow RSS/liveness observations do not prove absence of long-term leaks,
  production throughput, packet-loss behavior or sustained hardware capacity.
- Operator topology, bootstrap, time synchronization, trust, privilege and reviewed
  scheduler/image updates remain deployment boundaries. RouterOS tags are not an
  authorization boundary against another administrator.
- Full encrypted secret backup, independent penetration testing, public registry
  images/catalog, release SBOM and complete release E2E delivery remain separate.
