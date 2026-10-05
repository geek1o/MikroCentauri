# Engineering milestone 8: integrated activation and startup recovery

Date: 2026-10-05. Status: **all steps of the bounded engineering milestone passed**.
This is not product Phase8 release candidate. The original task has nine product
phases0–8; controller/core work remains within product phases2–3. See the
[roadmap](../product/progress.md). Production auth/API, general configuration
lifecycle, LKG, app packaging, UI and release acceptance remain open.

## Delivered

The reusable activation core now drives the opt-in namespace gateway. One
lifecycle mutex serializes health, apply, start and stop. The runtime adapter
holds DNS/admission, gracefully stops the engine and confirms native lease
revocation before preparing intent. It stages the exact committed/pending
configuration, admits all known engine aliases and proves their native mappings
while ingress stays quarantined. The controller owns durable Commit; only then
does the adapter release TUN/DNS. Native UP still requires observer health.

Every namespace-mode startup invokes Recover for either pending or committed
state. Committed disk state alone never grants readiness. A failed attempt stays
held and reports failure; restart or `/control/start` repeats proof after repair.
Matching manual `resume` remains compatible. Namespace `/control/start` deliberately
replays recovery even if an engine was running. Legacy non-namespace start still
rejects an already running engine without stopping it. See
[ADR0016](../adr/0016-policy-activation-recovery.md).

## Native acceptance

[The final run](phase-8-evidence/activation.json) uses isolated QEMU CHR7.24.5,
stock sing-box1.14.2 and a Linux/amd64 gateway, privileged=false, user0:0. Its
preserved baseline is revision16, following recorded preliminary runs. It retires
second.test at17; an abrupt after-Verify exit leaves pending18, then startup
automatically proves and commits18. A before-Release exit leaves committed19;
startup re-proves19 before release. A disabled third.test fallback mapping denies
candidate20, and restart with that defect remains quarantined/pending. Repair
followed by `/control/start` proves and commits20. Revision21 restores all known
names. No cache or reservation was erased to manufacture a fresh fixture.

Five aliases remain unchanged throughout:

| Domain | Immutable alias |
| --- | --- |
| selected.test | 198.18.0.2 |
| second.test | 198.18.0.3 |
| third.test | 198.18.0.4 |
| fourth.test | 198.18.0.5 |
| fifth.test | 198.18.0.6 |

Active cached addresses use proxy peer10.77.0.10; retired addresses and all
addresses during container death use native DIRECT peer10.77.0.1. The matrix
covers HTTP with foreign active Host, certificate-verified HTTP3 with active SNI,
and UDP for every alias. Retired fresh DNS returns10.77.0.20. Source.20/.30
retain PROXY/DIRECT precedence. Stale revision, duplicate and capacity candidates
leave the healthy engine's admission epoch unchanged.

A fixed input reject then blocks only the gateway's native REST connection.
Apply refuses to prepare new intent when quarantine cannot prove native state;
the committed revision remains21, Linux stays blackholed and all saved addresses
use DIRECT after the native lease disappears. After removing the reject, recovery
re-proves revision21 and restores the active matrix. No fallback traffic is
claimed while a fallback map itself was deliberately disabled: that map is
restored before DIRECT assertions.

[50 marked UDP workloads](phase-8-evidence/udp-path-witnesses.json) each have a WAN
forwarding witness matching their expected mode: plaintext lab VLESS TCP8443 to
10.77.0.10 for PROXY, or native UDP9000 to10.77.0.20 for DIRECT. These are packet
witnesses, not stream reconstruction, transaction counts or packet-loss bounds.
The [capture summary](phase-8-evidence/capture-summary.json) spans preliminary
runs, final acceptance and setup. [Retained preliminary barrier logs](phase-8-evidence/activation-trace.json)
record Stage/Verify/Commit/Release and both injected exits at revisions13–16;
they are not a complete stdout trace of the final run. Final crash acceptance is
backed by its stopped-container journal snapshots and subsequent native proof.
The test-only marker is consumed and directory-synced before exit86; it simulates
abrupt process/container death, not hardware power loss.

## Failure-driven fixes and validation

A [snapshot harness failure](phase-8-evidence/first-snapshot-failure.json) occurred
after the first successful pending crash. Restricted mc-lab could not read the
private container journal and sent an empty HTTP body. A fixed administrative
snapshot helper now reads that one lab file; it is removed after testing. An
earlier Python import-shadowing error was also corrected before acceptance.
A temporary FTP permission experiment did not solve container-file access;
FTP and reboot permissions are explicitly disabled again in the
[final permission check](phase-8-evidence/cleanup-permissions.log).

A [cold-start transport failure](phase-8-evidence/initial-transport-failure.json)
left recovery held. The native Netwatch read now retries transport failure only
under the existing deadline. Failed or unavailable proof never counts as lease
revocation, and state-changing requests are not blindly retried.

Review found that the admission error path killed the engine before the core's
graceful cleanup. It now leaves SIGTERM/wait to that cleanup, allowing the stock
allocator to persist its cursor. Native proof covers failures with the five
existing aliases; newly allocated aliases followed by admission failure are not
a separate native acceptance case in this milestone.

[Host checks](phase-8-evidence/host-checks.log) pass race tests, vet, real pinned
sing-box namespace/binding/smoke tests and CLI cross-build. Linux gateway vet and
amd64/arm64 builds pass; [HTTP3 fixture checks](phase-8-evidence/quic-checks.log)
pass. Unit fault tests cover request cancellation, independent cleanup, cleanup
errors and concurrent CAS; those cancellation/cleanup faults are not claimed as
new native Linux fault-injection cases.

Two independent gateway archives match SHA256:
`2740690f0e655e21f4ec93e6be15b399006cf90eb11f4b14984b16553dc3f100`.
The native executable matches the archive's build:
`7cf56ec75354bd5a6b1b1fe90a7ec3295892c9b0f3a2a80712c69397a15092e4`.
The runtime five-name configuration is
`87f83e20522ddfa9adfba9f2405d3b94f0569837f6fcbcaf2bec9cb145946866`.
See [build validation](phase-8-evidence/build-validation.json),
[native console](phase-8-evidence/native-console.log) and
[native state](phase-8-evidence/native-state.json). Linux/arm64 compiles but has
not been executed on a RouterOS device in this milestone.

## Cleanup and limits

The [cleanup snapshot](phase-8-evidence/cleanup-state.json) confirms the gateway
stopped, observer disabled, no UP lease, original selectors enabled and all five
owned maps retained. Fault injection is disabled; no injected reject or snapshot
script remains. Private namespace/publication directories are0700 and
journals/cache0600. Local raw captures, disks and binary archives remain ignored.

This closes the current engineering milestone's core, runtime adapter, automatic
startup recovery, crash windows, damaged-backend refusal, native control outage
and reproducible evidence. It does not close original product phase2 or3.
Empty-active gateway, automatic background retry/rollback, supervisor/LKG,
production authentication/TLS, multiwriter control, device/version coverage,
IPv6, earliest boot ordering, atomic DNS transport switching, cached real-IP
activation bypass, existing conntrack and hardware power loss remain open.
Next product work is capability-aware production controller integration and the
remaining sing-box configuration lifecycle, tracked by the canonical roadmap.
