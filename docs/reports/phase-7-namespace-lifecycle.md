# Phase 7 — retained FakeIP history and active namespace revisions

**Status: bounded namespace lifecycle implemented and verified on isolated CHR;
production activation remains OPEN.** RouterOS7.24.5, stock sing-box1.14.2,
Alpine3.24.2, Linux/amd64 gateway, QEMU TCG. Implementation commit `74d56d5`.
No external subscription/server or production router was used. All development
is recorded locally and published to the private
[MicroCentauri repository](https://github.com/geek1o/MicroCentauri).

Known names and engine aliases remain reserved when removed from Active. Public
DNS then returns a real IP while saved aliases use terminal DIRECT before
sniffing. Reactivation restores PROXY with the same alias. New names append;
there is no recycling, compaction or TTL-based retirement of bindings. The
private namespace journal has committed/pending revisions and compare-by-revision
controls. See [ADR-0015](../adr/0015-append-only-namespace-policy.md).

## Native acceptance

The accepted [native run](phase-7-evidence/namespace.json) begins with four preserved
bindings. Its baseline reactivates their complete known set at revision4, retires
second.test at5, adds fifth.test at6, reactivates second.test at7, resumes a repaired
pending revision8, then restores all five active names at9. The preliminary
[fourth-name run](phase-7-evidence/container-down-harness-failure.json) had already
proved expansion from three to four before a test-harness error. Its new issued
binding was preserved for the final run rather than removed to manufacture a
fresh fixture. Complete binding history is:

| Domain | Immutable alias |
| --- | --- |
| selected.test | 198.18.0.2 |
| second.test | 198.18.0.3 |
| third.test | 198.18.0.4 |
| fourth.test | 198.18.0.5 |
| fifth.test | 198.18.0.6 |

Retired second.test returns10.77.0.20 through canonical real DNS. Its saved alias
works through native TUN/DIRECT even with active selected.test HTTP Host or
certificate-verified HTTP3 SNI. Active names use PROXY peer10.77.0.10; retired
names use DIRECT peer10.77.0.1. Source.20 retains PROXY priority for the retired
alias and source.30 DIRECT priority. HTTP, UDP and verified HTTP3 are exercised
for all saved bindings, including while the entire container is stopped and
after its restart. The restarted policy retains retired state and all aliases.
Reactivation gives second.test its original.3 DNS answer and PROXY path.

A stale revision, duplicate names and capacity overflow are rejected without
stopping the healthy engine or changing the committed policy. An exact owned
third.test mapping is then temporarily disabled to force backend rejection.
The transition remains pending; that map is restored before testing DIRECT.
No fallback is claimed while the deliberately damaged object is disabled.
Container restart retains the intent, installs a blackhole, launches no child
and exposes no admitted receipt. Cached paths for all five names remain DIRECT.
Explicit matching resume after repair commits revision8; third.test is retired
through DIRECT until revision9 reactivates it. The pending intent never becomes
ready merely because the container restarts.

[Packet witnesses](phase-7-evidence/udp-path-witnesses.json) link44 accepted UDP
workloads to revision/domain/sequence markers on WAN. Each marker's forwarding
path matches its HTTP-derived expected mode: native UDP9000 to10.77.0.20 for
DIRECT, or plaintext lab VLESS TCP8443 to10.77.0.10 for PROXY. These are packet
witnesses, not transaction counts, stream reconstruction or loss/latency bounds.
[Full capture summary](phase-7-evidence/capture-summary.json) spans preliminary
attempts, diagnostics and final acceptance. [DNS witnesses](phase-7-evidence/dns-witnesses.json)
retain the observed public UDP answers. Raw PCAP, disks, engine databases and
binary archives stay ignored locally.

## Failure-driven fixes

The [first retirement attempt](phase-7-evidence/first-retirement-failure.json)
committed its new policy and returned real DNS for the retired name, but one
active cached HTTP request used native DIRECT. A stricter health-settling attempt
also [failed](phase-7-evidence/health-settle-first-failure.json). Diagnostics
identified repeated `DNS lease expired during backend verification` during
background mapping reconciliation, not Host/SNI reclassification. The
[pre-fix diagnostic](phase-7-evidence/health-diagnostic-before-fix.json) retains
those observed errors; it is not a timing-correlated causal proof for every packet.

Background Reconcile now retries exactly once for that specific lease-floor
failure, obtaining a fresh authoritative TTL and fresh backend proof. Other
errors/cancellation are not retried by this rule. Public PublishAlias still
rejects an expired receipt without this retry. Unit regression tests cover the
whole-second boundary, repeated expiry, unrelated failures and cancellation.
The final native run keeps the original5s fixture TTL; it does not extend or
replace it with a longer test TTL.

The fourth-name attempt failed when its down-path helper queried diagnostics
inside the stopped container. The helper now uses the already recorded revision.
Before the accepted run, only the preliminary three-name policy/config were
preserved aside and reinitialized while the engine was stopped; no alias cache
or publication mapping was removed. After fourth.test was issued, its history
was retained and the final run added fifth.test instead.

Code review also found invalid candidates stopping a healthy engine, and old
real-DNS requests surviving policy changes. Preview now validates before any
stop. A DNS Switcher cancels both allocator and real-DNS exchanges, and checks
its generation before returning an answer. Race tests verify late real answers
become SERVFAIL. The subsequent transport write is not an atomic revision boundary;
answers clients already received remain valid according to their own caching.

RouterOS file replacement produced `Text file busy` before shutdown completed,
and then `Permission denied` because tool/fetch removed executable mode. The lab
install waited for stopped=true, used a temporary sleep entrypoint to restore755,
and restored explicit /bin/mc-gateway afterward. The accepted run uses that real
entrypoint, not the temporary sleep process. Native hashes/modes are retained.

## Validation and remaining scope

`make check` passes race tests, vet, pinned sing-box validation and actual routing
process tests for active/retired/reselected Host/SNI. The negative process fixture
without the terminal retired DIRECT rule reproduces erroneous PROXY selection.
The host TLS test disables certificate checks only to isolate SNI; native HTTP3
verifies its public laboratory certificate, including both new names.
[Host checks](phase-7-evidence/host-checks.log),
[QUIC checks](phase-7-evidence/quic-checks.log) and
[cross-builds](phase-7-evidence/cross-build.log) are retained. Linux gateway vet
and amd64/arm64 builds also pass; Python runners compile.

Two independently built gateway archives share SHA256
`bd5f1ea4ce3a9d983fdde6b1ce668b5643f6b2706645ba41ef891eebb245db5e`.
The [native binary/config readback](phase-7-evidence/native-shell.log) and
[build metadata](phase-7-evidence/build-validation.json) prove the exact executable
used. The full archive was not reimported into the crowded2GiB disk; executable
replacement reused the isolated preserved root. Runtime policy updates rewrite
its validated config. [Native state](phase-7-evidence/native-state.json) shows
five maps, admitted aliases, private engine listeners and committed revision9.
[Cleanup](phase-7-evidence/cleanup-state.json) confirms lease removal, disabled
observer and stopped container; CHR, workload VMs, switches and artifact HTTP
server were shut down. No global conntrack flush was used.

This is fresh-flow, step-driven acceptance with settled health, not atomic policy
switching, cold-start availability, power-loss or existing-conntrack acceptance.
Cached real-IP answers from before activation may still bypass hybrid TUN until
clients resolve again. Known reservations remain finite and consume capacity
forever. Empty-active gateway mode, automatic pending recovery/rollback, multiple
writers, IPv6, hardware/version coverage, production API/auth and UI remain OPEN.
The next stage is production controller activation and recovery built around
these proved publication, generation and policy barriers.

The separate [Git attribution correction](git-author-correction.md) records the
user-approved rewrite of17 prior commits, exact old/new hash map and GitHub API
verification that both author and committer are now geek1o. Historical report
hashes are kept as provenance and resolved through that map.
