# Phase 6 — bound-domain routing and native boot DIRECT

**Status: bounded CHR policy and boot-lease cases verified; production acceptance
OPEN.** RouterOS7.24.5, stock sing-box1.14.2, Alpine3.24.2, Linux/amd64 gateway,
QEMU TCG. Implementation commit: `36869e4`. The private GitHub repository
[geek1o/MicroCentauri](https://github.com/geek1o/MicroCentauri) is now the project
remote; this stage publishes the existing local history as well as Phase6.
No production router, external server or subscription was needed.

An early terminal route now uses the domain stored for the admitted FakeIP before
sniffing. Source DIRECT/PROXY rules remain higher priority. Native readiness is
represented by one finite RAM address-list lease, with persistently enabled DNS
and saved-alias selectors. Missing lease means native DNS and DIRECT DNAT of every
published alias before routing. See [ADR-0014](../adr/0014-bound-domain-and-volatile-readiness.md).

## Binding authority

The real process test reproduces the previous Host/SNI DIRECT escape, then proves
that the new ordering preserves PROXY. It adapts loopback addresses/source rules
for the host and disables TLS certificate verification only to isolate sniffed
SNI. The native [binding matrix](phase-6-evidence/binding.json) separately uses
certificate-verified HTTP3: second.test, uppercase, mixed case with terminal dot
and unselected.test SNI stay PROXY to saved alias198.18.0.3. HTTP Host includes
those variants plus the numeric alias. Egress remains10.77.0.10; source.30 remains
DIRECT10.77.0.1 and source.20 PROXY even with a foreign name.

Real-IP cohost classification passes in the host test when traffic enters the
engine. Native hybrid real-IP requests bypass TUN and remain DIRECT regardless
of Host. An initial incorrect native expectation is preserved in
[the failed attempt](phase-6-evidence/real-ip-expectation-failure.json); it was
corrected to reflect topology rather than changing hybrid ingress.

## Boot and observer failure

The [continuous boot run](phase-6-evidence/boot.json) starts new cached HTTP,
cached UDP and fresh DNS+HTTP requests before an actual RouterOS reboot. The
startup scheduler is disabled and container start-on-boot is false during this
proof. Native uptime resets from2m5s to12s, management becomes unavailable, and
readiness lease is absent after boot. All four persistent selector flags stay
enabled. The first successful request after each stream's observed outage uses
DIRECT: HTTP sequence89, UDP sequence92, DNS sequence92. Fresh DNS returns real
10.77.0.20; cached flows continue using198.18.0.3. Restarting the admitted container
restores PROXY10.77.0.10.

Management recovery is observed at23818ms from probe start. First successes begin
at24658–24792ms, after management recovery. This is evidence of the first observed
successful samples after an outage, not proof of delivery before management or
of every earliest packet. WAN [packet witnesses](phase-6-evidence/boot-packet-witness.json)
match the first recovered UDP sequence92 to native10.77.0.1→10.77.0.20:9000.
All50 captured forwarding markers after the first post-trigger UDP error use that
DIRECT path. These are packet markers, not transaction counts or loss bounds.

The [lease lifecycle run](phase-6-evidence/lease-lifecycle.json) disables the
observer while its token still exists, without executing DOWN. After native row
disappearance, cached HTTP and verified HTTP3 plus fresh DNS+HTTP use DIRECT;
reenabling observation restores PROXY. Static/duplicate tokens are rejected and
removed. A changed observer pointed at an unrelated HTTP200 endpoint is UP but
cannot grant a lease, because renewal revalidates its exact target.

The configured timeout is6s, renewal probe interval2s. Native deletion was observed
after7576ms in the accepted run. A first attempt expecting disappearance within
10s failed; [its record](phase-6-evidence/lease-expiry-first-failure.json) and
[a subsequent diagnostic](phase-6-evidence/lease-expiry-diagnostic.json) show
an expired row can remain visible at timeout0s before garbage collection.
The runner now records disappearance with a20s observation window. Neither row
visibility nor these runs establish exact dataplane expiry latency. No6s failover
guarantee is claimed. The first boot-precondition failure is also
[retained](phase-6-evidence/first-boot-precondition-failure.json).

## Reproducible evidence and cleanup

`make check` passes Go race tests, vet, pinned-engine validation and actual routing
process smoke including the old-policy regression. `make quic-test`, CLI amd64/
arm64 cross-builds and the arm64 lab gateway build pass. Python runners compile.
[Host checks](phase-6-evidence/host-checks.log),
[QUIC checks](phase-6-evidence/quic-checks.log),
[cross-build](phase-6-evidence/cross-build.log) and
[build hashes](phase-6-evidence/build-validation.json) are retained.
Two independent final gateway archives have the same SHA256
`6bf8dd35da983db9ce1449faf2cda85e1199d18ee10a15c270a8d907199b8eb7`.
To preserve the crowded2GiB fixture volume, the exact final executable/config
were copied into the preserved Phase5 root instead of importing another full
root; native SHA256 readback matches. Container was renamed mc-gateway-phase6
with MC_NATIVE_LEASE=1, privileged=false, user0:0.

[Native state](phase-6-evidence/native-state.json) and
[native shell](phase-6-evidence/native-shell.log) retain the three immutable
bindings, executable/config hashes and private loopback engine listeners.
[Capture summary](phase-6-evidence/capture-summary.json) and
[DNS witnesses](phase-6-evidence/dns-witnesses.json) cover final native binding,
boot and lifecycle runs. Earlier raw captures remain separately in ignored local
storage; databases, binaries, disks and PCAP are excluded from Git. Failed records
are retained alongside accepted results; captures are not TCP stream reconstruction.

Cleanup disabled the observer, revoked its lease, stopped the container, restored
the defensive startup scheduler and removed the owned debug script.
[Cleanup state](phase-6-evidence/cleanup-state.json) records those changes.
RouterOS retained `reboot` when omitted from a group `set`; a cleanup-only restart
explicitly revoked it with `!reboot` and confirmed
[permission readback](phase-6-evidence/cleanup-permission.txt). CHR, workload VMs,
capture switches and artifact HTTP server were then stopped. No global conntrack
flush was used.

Acceptance remains limited to fresh flows, one cached alias during boot and the
finite three-domain policy. Hardware power-loss, existing conntrack behavior,
all RouterOS/device versions, IPv6, namespace addition/retirement and a production
controller/API/auth/UI remain OPEN. The next milestone is safe namespace change
and retirement while clients retain old aliases; arbitrary alias reuse remains
forbidden until that lifecycle is defined and proved.
