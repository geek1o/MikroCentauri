# Product Phase 8 — RC E2E report

Date: 2026-10-07. Candidate version: **v0.1.0-rc.1**. This report assembles
retained E2E acceptance for the exact RC image, rather than claiming a second
native run during packaging. Qualification is limited to **CHR RouterOS 7.24.5
x86_64, sing-box 1.14.2, Alpine 3.24.2 and the disclosed synthetic IPv4 profile**.
Release artifact verification/publication is recorded separately in the release
manifest. No real router or production subscription was used.

## Accepted image identity

The accepted image comes from `.cache/app-image-phase7-complete`; its retained
[build metadata](evidence/phase-7-completion/image-build.json) binds platform
manifests, controller/engine hashes, pinned inputs and import archive hashes.
The [source snapshot](evidence/phase-7-completion/source-snapshot.json) identifies
implementation commit `9e7b2fd5a1fb5b532a56dd7b62f9b8a9390cd7af`; subsequent
report/release packaging changes do not create a new native runtime result.

| Image identity | SHA256 digest |
| --- | --- |
| Multi-platform OCI index | `0ae1b54998cf60e48deec5b766a4c20d711b6f5c8db907b492e0af47f8a7a24f` |
| amd64 manifest | `51b788255d2ecf90d8e2cc693bbcaef1843441d7eab3e14129a863baf620f3f6` |
| amd64 config | `a3750b0dce3c211026ad85828bef3cd72da109d24ea2cbd41edd96a68076cd86` |
| arm64 manifest | `4a3ddd1002caaa49570346c279f8b4a7395150e806b3744e46fb93190da520dd` |
| arm64 config | `b9115b9596942a5b1913844132b9bd342f47bb7a70588c7a00723570dd01b67f` |

Platform config digests are derived from their verified OCI manifests. Image
archive checksums describe the files, not registry upload. arm64 construction
and ELF/hash checks are accepted; native arm64 execution is not.

## Exact-image native matrix

Canonical run **`1791398213085080000`** has `accepted=true`, `completed=true`
and `hardening.completed=true` in the retained
[native results](evidence/phase-7-completion/native-results.json).
The [completion report](product-phase-7-hardening-completion.md) describes
fixtures, failures, quiet periods and cleanup in detail.

| Area | Retained result and evidence |
| --- | --- |
| Protected install/defaults | Native App production Go entrypoint and image-default TLS health, stopped plan/privilege/verify, protected volume, authenticated readiness and finite UP lease. No shell entrypoint or admission-time extra mounts. |
| Initial selected/direct traffic | Fresh TCP, UDP echo and HTTP/3 distinguish actual proxy/direct server peers. Stopping/restarting App preserves auth/namespace and recovers retained aliases. |
| FastTrack OFF/ON | Five cases in each state: selected PROXY, native DIRECT, bound DIRECT, source PROXY and source DIRECT; each TCP/UDP/HTTP3. New 512 KiB DIRECT tuples prove fasttrack=false/true; the user rule is restored. |
| Packet attribution | 19 hardening stages and 23 exact-run UDP witnesses, including initial paths and both image changes. Unique markers, source and WAN proxy/direct path are required by the verifier; [UDP witnesses](evidence/phase-7-completion/udp-witnesses.json). |
| IPv6/DNS limits | Ten DNS queries with positive upstream AAAA controls, managed empty AAAA, preserved unselected AAAA, managed HTTPS/SVCB failure over UDP/TCP. Literal IPv6 bypass/restoration and a scoped operator guard are demonstrated; [IPv6 witnesses](evidence/phase-7-completion/ipv6-witnesses.json). |
| Process/endpoint faults | Remote VLESS SIGSTOP/resume, actual engine SIGKILL (PID 163 → 293), owner SIGKILL/native restart. DOWN cached/fresh DIRECT and restored TCP/UDP/HTTP3 PROXY are observed. |
| Cold reboot safety | Persistently enabled steering closes independently with App/Netwatch disabled; all three controlled targets disabled, no RAM UP lease, cached/fresh DIRECT. Manual restart restores PROXY. |
| Repeated automatic boot | Reviewed exact-name/config-digest operator helper; disabled-App and wrong-digest checks; two consecutive actual enabled-App reboots, scheduler run-count 1 each, fresh dynamic lease and traffic proof. |
| Immutable image rollback/return | Previous amd64 config `58d17e363ba1df1745e69ee51ee575200ea4e9446cbefd2c02ea5d81f28006d7` → final `a3750b0d…` across genuinely different images. Original private bytes and nonempty engine cache equal before each start; cached TCP/UDP/HTTP3 accepted afterward. |
| Bounded resource smoke | 68.12 s, eleven cached-alias/real-IP pairs, 64 KiB per transfer. Owner RSS 16628 → 16740 KiB, engine 60168 → 61924 KiB, swap 0. These observations are not throughput/leak/hardware capacity qualification. |
| Cleanup | Exact controlled objects absent, original FastTrack restored, App disabled, private state preserved; all eleven fixture listener ports closed; [cleanup proof](evidence/phase-7-completion/cleanup.json). |

The upgrade pair predates formal RC naming. It proves the described native
image replacement and cache preservation, not every previous/future version's
state compatibility. RC uses the already accepted final image without changing
its OCI config/layer identity.

## Management, UI and regression evidence

The [Phase 4 API E2E](product-phase-4-api-completion.md) proves a real production
CLI/HTTPS/durable draft path on the pinned native profile: Validate → Plan →
Apply → Verify, stale/single-use refusal, topology rejection without replacing a
healthy child, safe backup restore, owner death, cached DIRECT and forward
recovery. Its earlier development binary is distinct from the RC image; it is
subsystem acceptance, not an additional RC install proof.

The [Phase 5 UI acceptance](product-phase-5-web-ui-completion.md) covers ten pages,
CAS drafts, redacted forms, subscription controls, plan/apply, diagnostics, safe
backup, responsive layout, logout/reload and actual pinned validator. Retained
[Phase 7 browser output](evidence/phase-7-completion/browser.log) records four
passing Chromium/WebKit HTTPS contracts in 16.9 s, including honest IPv6 UI
behavior. Browser runtime/router/subscription transports are simulated; native
packet proof comes from the matrix above. Firefox is unqualified.

The retained [full check/cross-build log](evidence/phase-7-completion/check-cross-build.log)
covers Go race tests/vet, pinned-engine integration, frontend checks/build,
image integration and static amd64/arm64 builds. Both image architectures pass
[OCI/ELF/archive/secret checks](evidence/phase-7-completion/image-verify.log).
Security regressions include mixed/private/rebound DNS, literal checked dialing,
IPv6/downgrade redirect refusal and frozen caller-provided client CIDRs.
Capture/boot negatives reject wrong runs, missing stages, leaked guard SYNs,
absent witnesses and malformed captures.

A reproduced private verification expiry regression fails before the fix and
passes after a single bounded renewal of `ErrLeaseExpiredDuringVerification`.
Repeated expiry/unrelated errors still quarantine. Public DNS remains strict:
selected DNS may return SERVFAIL at the authoritative TTL floor while readiness
stays true. Diagnostic/rejected runs retain their original nonaccepted status;
see [rejected observations](evidence/phase-7-completion/rejected-observations.json).

## Evidence integrity and reproduction

[sha256.json](evidence/phase-7-completion/sha256.json) binds all retained safe
Phase 7 artifacts. Raw PCAP, private disks/bootstrap/snapshots and credentials
remain outside Git and release assets. Capture summaries bind raw PCAP digests;
only exact-run markers and the scoped IPv6 guard window count as acceptance.
This disclosure is not a signature or independent third-party attestation.

The fixture commands and preparation are in
[Phase 7 reproduction](product-phase-7-hardening-completion.md#validation-and-reproduction)
and [lab documentation](../lab.md). Native reruns require the separate official
user-provided CHR image, isolated stopped-disk clone, explicit operator authority
and synthetic peers. The immutable image check can run without native fixtures:

```sh
python3 scripts/verify-app-image.py --out .cache/app-image-phase7-complete
python3 -m unittest discover -s tests/e2e -p test_capture_verifiers.py -v
```

Do not treat absence of private native fixtures on another checkout as a new
passing native result. Use [installation](../install.md),
[upgrade](../upgrade.md), [rollback](../rollback.md) and
[known limitations](../known-limitations.md) for the operational boundary.
Release checksums/SBOM/source materials qualify distribution artifacts; they do
not widen the accepted device, IPv6, browser, throughput or fault matrix.
