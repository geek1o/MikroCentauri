# Dataplane lab

Functional targets: client → CHR LAN → RouterOS; CHR VETH → MikroCentauri gateway;
CHR WAN → local test VLESS server. Compare A hybrid, B full gateway and C Socksify.
Capture both sides and record egress identity. Native QEMU TCG is functional testing
only; do not publish hardware throughput conclusions from it.

## CHR host runner

Provide an official raw CHR image yourself, downloaded from
[MikroTik CHR downloads](https://mikrotik.com/download/chr). Images/NPK are ignored
and never redistributed in Git. `scripts/chr-lab.py` copies the disk, adds separate
2GiB container storage, a WAN user-network and a LAN socket on localhost.

```sh
python3 scripts/chr-lab.py --image /absolute/path/chr-7.24.5.img
```

Management binds only 127.0.0.1:22222 (SSH), 18080 (HTTP), LAN socket 19188.
Use plain console `admin+ct`; set a disposable lab password before enabling HTTP
REST. Native TCG avoids nested virtualization. A socket-compatible QEMU client NIC
can connect with `-netdev socket,id=lan,connect=127.0.0.1:19188`. Checksum-pinned RAM-root Linux client/server builders are included below; Docker
is not required.

On a fresh isolated CHR: install matching container package via official NPK upload,
**graceful `/system/reboot`** (cold QEMU reset is not the install procedure). Enable
container device-mode with console confirmation + power cycle during the requested
window. Preserve your original disk and use the runner's copy for all mutations.
Format the extra disk only after inspecting `/disk/print`; never format a real router
storage device using disposable lab instructions. Inspect package/version and disk.

## TUN capability probe

```sh
make probe
python3 -m http.server 18081 --bind 127.0.0.1 --directory .cache
```

Host is available to QEMU WAN as 10.0.2.2. Disposable CHR commands live in
`lab/chr/probe.rsc`; read them and apply only to a dedicated empty lab. They create
VETH/bridge/private address and import the locally built docker-save probe archive.
Probe returns effective capabilities, whether TUN can open and whether `TUNSETIFF`
succeeds. It has no RouterOS credentials. Compare normal/root/privileged separately
on 7.22, 7.23 and 7.24.5; never infer older-version support from one success.

The TUN probe alone cannot establish transparent packet capture, routing permissions,
forwarding, source retention or loop-free sockets. Run A/B workloads only after these
gates. Keep generated config's auto_route false; set ingress routes and explicit
outbound exclusions under capture rather than silently looping the proxy sockets.

## Explicit process smoke

`make smoke` runs without Docker, real proxy credentials or external resolvers.
The generated SOCKS listener is adapted to localhost and lab FakeIP test removes the
TUN inbound for macOS. This verifies engine behavior; it does not verify the RouterOS
socket/forwarding plane or distinct egress.

## Evidence and benchmarks

For each A/B/C, collect: TCP, UDP echo, HTTP/3, DNS TCP/UDP, original source, domain,
IPv4, IPv6 leak behavior, WAN outbound loop capture, DIRECT through gateway, container
kill/recovery, router reboot, Netwatch transition times, FastTrack state, throughput,
latency, packet loss, CPU and RSS. Keep `.pcap` and VM images outside Git; commit small
sanitized result tables and hashes. `lab/e2e-status.json` distinguishes executed, partial, failed and unrun scenarios. No fabricated benchmark values.

## Executed CHR result

On 2026-10-04, CHR7.24.5 successfully imported and started the local amd64 probe,
opened `/dev/net/tun` and created TUN with root `user=0:0`, `privileged=no`. Exact
capabilities/kernel/feature mask and archive hash are in
`docs/reports/chr-capability.json`. RouterOS keeps VETH named `mc-probe` inside the
container; the TUN name must differ (`mc-tun-probe`). The first same-name attempt
returned EINVAL; privileged mode did not fix the collision. Transparent packet-path/failure experiments are now in
[the Phase-1 report](reports/phase-1-dataplane.md), with explicit remaining gates.

## Reproduce the isolated Ethernet lab

Run `make bootstrap`, then `make dataplane-lab`. This builds a private gateway
config, Docker-save archive, static workloads and checksum-pinned Linux RAM-root
image. It starts no router and accepts no real subscriptions. The musl release is
explicitly required for Alpine. The separate QUIC module uses its own go.sum.
Run `make quic-test` for a real loopback HTTP/3/TLS fixture test.

Start each long-running process in its own terminal, **switches before VMs**:

```sh
python3 scripts/lab-switch.py --port 19188 --capture .cache/dataplane/lan.pcap
python3 scripts/lab-switch.py --port 19177 --capture .cache/dataplane/wan.pcap
python3 scripts/chr-lab.py --image /absolute/path/official-chr.img --lan-connect --wan-socket 19177
python3 scripts/linux-lab.py --role client --socket 127.0.0.1:19188
python3 scripts/linux-lab.py --role server --socket 127.0.0.1:19177 --mac 52:54:00:77:00:10
python3 -m http.server 18082 --bind 127.0.0.1 --directory .cache/dataplane
```

Client control: localhost19010; QUIC control19110. Server control19020. The VMs
have a separate10.0.2.15 control NIC, no control-network IPv4 default route. Control-NIC IPv6 is disabled to avoid
QEMU RA creating a bypass route; this is lab isolation, not product IPv6 policy. The server
starts VLESS, target HTTP/DNS/UDP and QUIC; the client starts HTTP workload controls.
virtio-rng provides fresh boot entropy without disabling TLS checks. LAN aliases
.20/.30 and server TEST-NET alias203.0.113.20 are local fixtures. RAM-root contents
are lost on VM shutdown; pinned build inputs remain local.

Prepare only a disposable empty CHR with matching container package/device-mode
as above. `lab/chr/dataplane.rsc` is an assembled fresh provisioning recipe from
verified primitives; **its whole fresh one-shot import has not been independently
replayed**. It rejects existing LAN/account and does not format a disk. It sets up
LAN, test WAN, gateway VETH, disabled FakeIP and real-IP objects, and a public lab
REST account. If reusing the older capability-probe disk, inspect existing objects
instead of importing duplicates. Do not run this on a user/production router.

Inspect the extra container disk and format it manually only on that disposable
VM. The third NIC changed the observed disk slot to pcie2, so discover actual slots
rather than assuming pcie1. Transfer the generated gateway-image.tar through the
admin console; the restricted runtime REST account lacks file-write permission.
For the observed lab disk layout, import into a fresh root:

```routeros
/tool/fetch url=http://10.0.2.2:18082/gateway-image.tar dst-path=pcie2/gateway-image.tar
/container/add file=pcie2/gateway-image.tar interface=mc-probe root-dir=pcie2/mc-gateway logging=yes user=0:0 name=mc-gateway
/container/start [find where name="mc-gateway"]
```

Use root with privileged=no, as measured. Do not overwrite a running binary using
fetch: execution bits are lost and stop is asynchronous. Wait for extraction and
then for gateway readiness. The fixture's9099 control endpoints are **unauthenticated
lab controls**, not a deployable management API. They have no RouterOS credentials.

Test A, then install its native watchdog by transferring `lab/chr/watchdog.rsc`
and importing once through the console. Inspect Netwatch errors; successful import
alone is not runtime proof. Tests have fixed loopback forwards and lab credentials:

```sh
python3 tests/e2e/chr_dataplane.py
python3 tests/e2e/chr_protocols.py
python3 tests/e2e/chr_failures.py
```

For D, disable the FakeIP Netwatch, run mc-lab-down, enable the exact static FWD
record, then import `lab/chr/realip-watchdog.rsc`. Never leave both watchdogs active
as competing mode controllers. `chr_realip.py` exercises cached real-IP engine
failure/recovery. `chr_fasttrack.py` installs one-time disposable user FastTrack
fixtures and managed exceptions in D; it rejects duplicate fixtures.
`chr_benchmark.py` explicitly switches modes and leaves both watchdogs disabled;
restore the intended mode manually after it. It measures all **fixture** destinations
through TUN, not a complete internet exclusion policy.

Read the failure report before interpreting a PASS: cached FakeIP and remote proxy
outage remain failed acceptance cases. Capture both switches across tests, then
stop them before hashing. `scripts/summarize-lab-pcap.py` produces endpoint counts
and capture hashes, not a packet-loss or TCP-reconstruction proof. Keep captures
local and publish only sanitized summaries. Gracefully stop the gateway and
shutdown CHR/client/server; never reset the user's original image.


## Phase 2: proxy health, static cached-IP fallback and durable controller

Continue the isolated topology above; stop older gateway generations before sharing
`mc-probe`. Build the current gateway with `scripts/build-gateway-lab.py` into a
new archive and import it into a **new root directory**, named `mc-gateway-phase2`.
Stop both experiment Netwatch entries before replacing the gateway; keep the
real-IP experiment disabled. Copy/import `lab/chr/cached-fallback.rsc` once after
`watchdog.rsc`: it replaces the existing watchdog sources and owns one pinned
mapping `198.18.0.2 -> 10.77.0.20`. Duplicate imports intentionally fail.
RouterOS typed addresses are normalized with `:tostr` in shape checks.

Readiness starts HTTP503 and requires three fresh successful SOCKS/VLESS canary
requests; two failed samples produce DOWN. The canary must report peer10.77.0.10.
Native Netwatch continues to poll every2s and owns failover when the container dies.
The internal HTTP control and unauthenticated SOCKS remain lab-only.

```sh
python3 tests/e2e/chr_cached_fallback.py
python3 tests/e2e/chr_controller.py
python3 tests/e2e/chr_mapping_guard.py
```

For the separate external-proxy case, in the **server VM console** stop its lab
sing-box process (`kill $(pidof sing-box)`), then on the host run
`python3 tests/e2e/chr_proxy_health.py down`. Restart in that same VM with
`/lab/sing-box run -c /lab/server.json >/tmp/vless-restarted.log 2>&1 &`, then run
`python3 tests/e2e/chr_proxy_health.py up`. Keep the gateway process running throughout.
Controller tests use only a disabled route in reserved instance `stage2`; they
simulate a lost creation response, restart the process and recover from a private
0700/0600 journal. They leave that canary absent. They do not activate product routing.

The earlier `chr_failures.py` records the **Phase-1 negative baseline** and expects
cached-IP failure and immediate startup readiness. Use the new Phase-2 tests after
installing the new scripts. Results: [Phase-2 report](reports/phase-2-resilience.md).
This static map is not general FakeIP fail-open; existing conntrack, boot ordering,
dynamic mapping publication and capacity are still acceptance gates.


## Phase 3: dynamic publication gate

Prepare the same Linux assets (additional second.test/third.test DNS and certificate
names are included), then build the explicit dynamic fixture:

```sh
make dataplane-lab
python3 scripts/build-gateway-lab.py --dynamic-dns --out .cache/dataplane/phase3-gateway.tar
```

The builder derives the private loopback5354 allocator listener, the external5353
publication gate and the three exact selected domains. It retains native FakeIP
processing in sing-box, including UDP translation. Use a fresh container root and
name `mc-gateway-phase3`; stop older generations sharing `mc-probe` first. As admin,
allow the lab HTTP REST service from `10.0.2.0/24,172.30.0.0/24` using
`/ip/service/set www available-from=10.0.2.0/24,172.30.0.0/24`. This grants only the
public isolated fixture path, not a production installation recipe.

Import `lab/chr/dynamic-fallback.rsc` once after the Phase-2 watchdog; it disables
old static fallback and replaces the existing UP/DOWN sources with a dedicated
backup-chain jump. Do not leave the real-IP watchdog or older gateway active.
The initial dynamic chain must have no test mappings; the publisher creates them.

```sh
python3 tests/e2e/chr_dynamic_publication.py
```

The runner requires a fresh three-domain fixture. It verifies two initially
published aliases, rejects the real gateway-to-REST transport (including existing
HTTP keep-alive sockets), checks that third.test gets no address/new router map,
restores control and publishes the third alias, stops the entire container and
checks cached TCP/UDP/HTTP3 DIRECT access, then verifies restored PROXY and stable
aliases after restart. A temporary exact input-filter rule is removed in `finally`.
Initial/recovery publication attempts are retained, including any transient DNS
SERVFAIL; positive readiness is not a promise of error-free cold DNS requests.

Service access-list edits alone do not stop already open control connections.
The runner therefore rejects only172.30.0.2->172.30.0.1 TCP80 in the disposable
router, while host management remains accessible. Generic arbitrary-domain,
CNAME, address churn, alias reuse, capacity and boot/power-loss behavior are outside
this fixture. See [Phase-3 report](reports/phase-3-publication.md).
## Phase 4: real-target refresh

Continue the isolated Phase3 dynamic fixture with CHR7.24.5 and sing-box1.14.2.
The gateway now reads actual positive wire TTLs over TCP, and refreshes the
real target without releasing its domain/FakeIP reservation. See
[ADR-0012](adr/0012-real-target-refresh.md) and the
[Phase4 report](reports/phase-4-target-refresh.md).

Build Linux client/server fixtures with `scripts/prepare-dataplane-lab.py`, then
build the dynamic gateway with `scripts/build-gateway-lab.py --dynamic-dns`.
The Linux server has additional address10.77.0.21, explicitly bound UDP echo
listeners on both targets, and an HTTP/3 listener on all IPv4 interfaces.
Its lab-only `/dns-fixture` control on host localhost19020 changes only
`second.test`, with target10.77.0.20/.21, TTL1..30 and optional SERVFAIL.
No production server or subscription is involved.

Prepare a fresh private root named `mc-gateway-phase4` on the already isolated
router. Stop prior generations and disable the existing watchdog before removing
only owned disposable maps for a fresh scenario. Reuse the existing single
dynamic jump; do not reimport the one-shot Phase3 RSC. This reset is fixture
preparation, not supported production cache retirement.

Run `python3 tests/e2e/chr_target_refresh.py` after starting the VMs and enabling
the existing readiness watchdog. It preserves failed DNS attempts and exercises
target change, full-container restart, upstream DNS failure and a control-link
failure during target refresh. Cached TCP/UDP requests use `skip_dns=true` and an
explicit saved alias; HTTP/3 likewise uses its explicit alias. Thus cached-path
proof does not accidentally depend on a successful new DNS resolution.

The test briefly invokes the owned UP script while readiness remains DOWN, only
to capture a gate SERVFAIL response during upstream failure. Cleanup restores
native DOWN and removes its exact disposable transport-blocking filter. Gateway
`GET /diagnostics/dns` returns bounded category counts and the last32 failures;
it is unauthenticated and exists only inside this lab.

Artifacts land in ignored `.cache/dataplane`; curated public fixture evidence
is stored in `docs/reports/phase-4-evidence`. Shut down containers/VMs and disable
the lab watchdog after collecting evidence. No global conntrack flush is used.

## Phase 5: engine admission before ingress

Use the same isolated topology and a private root named `mc-gateway-phase5`.
`scripts/build-gateway-lab.py --dynamic-dns` now creates the finite namespace and
loopback-only engine DNS/SOCKS listeners. Ensure the container disk has space for
both import and runtime files; the accumulated 2GiB fixture roots left too little
space in the first run. The host archive copy is preserved outside Git.

Run `python3 tests/e2e/chr_generation.py healthy` with the existing native readiness
watchdog enabled. It verifies preseeded aliases, canonical DNS, saved-alias
TCP/UDP/HTTP3, full-container restart and native fallback, then stops the child.
Confirm `/diagnostics/generation` reports no child and table100 blackhole before
mutating any disposable cache fixture. These endpoints remain unauthenticated
lab controls; they are not production API endpoints.

For the missing-cache scenario, move `/data/singbox-cache.db` to
`/data/singbox-cache.saved` inside that stopped-child lab container, then run
`python3 tests/e2e/chr_generation.py missing`. Keep the saved original intact.

For the foreign-generation scenario, while still quarantined and with no engine
cache at the normal path, set umask0077 and manually run stock sing-box with the
same config. Invoke `/bin/mc-generation-tool third.test selected.test second.test`
inside the container. Stop that manual engine with SIGTERM and wait for its close
before running `python3 tests/e2e/chr_generation.py mismatch`. The helper allocates
through private DNS; it neither edits nor imports database content. The wrapper
must reject this foreign set before exposing its TUN.

Move the foreign database to a separate diagnostic filename, restore the saved
original, then run `python3 tests/e2e/chr_generation.py recovered`. Both rejection
scenarios deliberately force the owned native UP script once to prove the Linux
blackhole still protects a cached packet; their cleanup restores native DOWN.
Never use these destructive cache fixtures against a production installation.

The existing target-refresh replay accepts `--container mc-gateway-phase5 --admission`
for regression checking against this generation. The admission option waits for
blocked startup to finish, verifies quarantine, and explicitly retries admission
after restoring management. Collect all failed attempts
alongside passing results; summarize public fixture captures, retain raw PCAP and
databases only in ignored local storage, then shut down the lab. See
[Phase5 evidence](reports/phase-5-generation-admission.md) and
[ADR-0013](adr/0013-engine-generation-admission.md) for proof boundaries.

## Phase 6: immutable routing authority and RAM boot lease

Use the isolated Phase5 topology, admitted three-name cache and persistent maps.
Build with `scripts/build-gateway-lab.py --dynamic-dns --native-lease`; this option
requires dynamic DNS. Enable `MC_NATIVE_LEASE=1` in the native gateway environment.
Do not run legacy tests that toggle selector flags against this migrated fixture.
Import `lab/chr/lease-fallback.rsc` once through the admin console. It validates and
migrates the existing observer, preserving enabled selectors and replacing its
UP/DOWN callbacks. A failed partial import requires explicit repair; importing a
second time is rejected. Keep the old cache/root/host archive intact.

Run `python3 tests/e2e/chr_binding_policy.py` for saved-alias Host and HTTP3 SNI
variants and source overrides. For the reboot proof, use container name
`mc-gateway-phase6`, `start-on-boot=no`, and disable only the owned scheduler
`mc-lab-boot-direct`. Temporarily grant `reboot` to the disposable `mc-lab-rest`
group through the admin console. Run `python3 tests/e2e/chr_boot_lease.py` while
both workload VMs and capture switches stay running. It starts three continuous
fresh-flow streams before the actual reboot, verifies management outage and
uptime reset, checks lease absence, and records the first success after each
stream's observed outage. Then it restarts the container and verifies PROXY.

Run `python3 tests/e2e/chr_lease_lifecycle.py` to stop the observer, observe token
expiry, test DIRECT and recovery, and reject static/duplicate tokens and a
changed HTTP200 probe target. Results and raw captures remain in ignored `.cache`;
retain failed attempts together with passing results. Native timeout-row cleanup
can exceed6s, so the test records disappearance and route rather than asserting
an exact6s availability guarantee.

After collection, disable the observer, run `mc-lab-down`, stop the container,
restore the scheduler and remove the temporary group permission explicitly with
`policy=!reboot,read,write,test,api,rest-api`. Omitting `reboot` from RouterOS `set`
does not necessarily revoke it. Confirm the readback, then shut down CHR and the
workload VMs and stop captures. No global conntrack flush. See
[Phase6 evidence](reports/phase-6-boot-and-policy.md) and
[ADR-0014](adr/0014-bound-domain-and-volatile-readiness.md).

## Phase 7: retained namespaces and active revisions

Build with `--dynamic-dns --native-lease --namespace-policy` and explicitly enable
`MC_NAMESPACE_POLICY=1` alongside the native lease option. Keep the entire stock
engine cache, publication ledger and all persisted mappings intact. The initial
known order is inherited from the admitted generation; it is never compacted.
Namespace state is private `/data/namespace/namespace.json`. A pending revision
is exposed in diagnostics, but cannot automatically start an engine after restart.

`GET /diagnostics/namespace` returns committed Known/Active and an optional pending
candidate. `POST /control/namespace` accepts `{revision, active}` for a change or
`{revision, resume:true}` for a matching pending revision. These are disposable
lab controls reachable only within this topology, not production management API.
The pinned canary selected.test must stay active. Invalid candidate/stale revision
is rejected before stopping a healthy engine. A transition waits for native DOWN;
a backend/config/admission failure retains pending intent and DIRECT. Repair the
exact fault before explicit resume. The test never removes issued aliases.

`python3 tests/e2e/chr_namespace.py` tests retirement, real DNS, saved HTTP/UDP/
verified HTTP3, source priority, addition, full-container restart and reactivation.
It can extend the initial three-name fixture with fourth.test, or a four-name
fixture with fifth.test. Its revision expectations derive from the actual baseline.
The upstream workload and public lab certificate support both additions. During
its backend fault, one exact owned map is temporarily disabled; it is restored
before testing cached DIRECT. No fallback is claimed while that object is damaged.
An unresolved pending intent must remain unadmitted after container restart.

The native test requires a running container named mc-gateway-phase7 and enabled
lease observer. It records settled health before traffic; this is not a cold-start
availability guarantee. Do not query the container's diagnostic API while it is
stopped: down-path tests use the already recorded revision and explicit aliases.
Keep every failed attempt and raw capture locally. UDP requests carry phase7
revision/domain/sequence markers for packet summaries.

RouterOS tool/fetch replacement can remove executable mode or fail with Text file
busy before stop completes. Wait for stopped=true. For a lab binary replacement,
use a temporary /bin/sleep entrypoint, restore executable/file modes in its shell,
then restore explicit /bin/mc-gateway entrypoint and empty cmd. Confirm final
native hashes and environment; do not mistake the sleep container for an admitted
gateway. Preserve any preliminary policy/config before fixture-only reinitialization;
never delete issued binding history to obtain a fresh test.

After evidence collection, disable the observer, run mc-lab-down, stop the container
and shut down the VMs/switches. See [Phase7](reports/phase-7-namespace-lifecycle.md)
and [ADR-0015](adr/0015-append-only-namespace-policy.md).


## Engineering milestone 8: activation and startup recovery

The product roadmap still has nine phases (0–8); these engineering report numbers
are a separate sequence. See [the roadmap](product/progress.md).

Build the opt-in namespace gateway with the same pinned lab dependencies:

```sh
python3 scripts/build-gateway-lab.py --dynamic-dns --native-lease --namespace-policy --out .cache/dataplane/phase8-gateway.tar
```

The gateway now calls activation Recover on every namespace-mode start, including
`/control/start`. It gracefully stops the previous child, holds DNS, confirms the
native lease is absent, stages the generation, proves its bindings/mappings,
commits pending intent and then releases TUN/DNS. A failed attempt stays held;
after fixing its cause, restart the process or call `/control/start` again.
The matching manual `resume` operation remains compatible for pending revisions.
The production CLI still only generates/plans offline, and lab HTTP controls
remain unauthenticated.

`tests/e2e/chr_activation.py` requires the preserved five-name fixture described
in the Phase7 report, named `mc-gateway-phase7` with its existing private root.
It does not erase reservations or caches. The crash-only native run additionally
opts into `MC_ACTIVATION_FAULTS=1`. This is not enabled by the image builder.
Single-use `/data/activation-fault` values `after-verify` and `before-release`
are consumed and directory-synced before exit86. There is no HTTP arm endpoint.
Test provisioning uses the explicit disposable localhost admin/blank-password
fixture to write that marker and read the private journal; the runtime continues
to use its restricted public mc-lab account. Never use those test credentials on
an installed product.

The native runner needs a temporary fixed-path administrative script
`mc-lab-activation-snapshot` (policy read,write,test):

```routeros
:local s [/file/get "pcie2/mc-gateway-phase5/data/namespace/namespace.json" contents]
/tool/fetch url="http://10.0.2.2:19082/snapshot" http-method=post http-header-field="Content-Type: application/json" http-data=$s output=none
```

The runner listens for this snapshot on localhost19082 only while running. It
records partial results on failure, preserves cached aliases across both crash
boundaries, refuses damaged native proof and exercises a blocked native REST link.
Restore any injected mapping/filter in cleanup, remove the snapshot script and
disable `MC_ACTIVATION_FAULTS` after testing. The historical Phase7 manual-recovery
proof remains tied to its implementation commit; its current runner now expects
automatic repaired-pending recovery.

```sh
python3 tests/e2e/chr_activation.py
python3 scripts/summarize-lab-pcap.py .cache/dataplane/phase8-lan.pcap .cache/dataplane/phase8-wan.pcap --out .cache/dataplane/phase8-capture-summary.json
python3 scripts/verify-activation-capture.py --results .cache/dataplane/activation-results.json --capture-summary .cache/dataplane/phase8-capture-summary.json --out .cache/dataplane/phase8-udp-witnesses.json
```

These are step-driven new-connection tests, not atomic DNS transport switching,
power-loss, existing-conntrack, hardware throughput or production auth acceptance.

## Product Phase 2: native HTTPS controller acceptance

The separate management-plane runner is
`tests/e2e/chr_staged_controller.py`; it requires the disposable CHR 7.24.5 fixture,
not an installed router. Start `scripts/chr-lab.py` with `--https-port 18443` to
forward localhost18443 to native guest443. The optional forward does not change
existing HTTP-only lab invocations.

Prepare a short-lived certificate with SAN IP127.0.0.1, import its PKCS#12 into
CHR, and assign it to native `www-ssl`. Keep private material under ignored
`.cache/router-stage` (directory0700, key/archive0600). Save its public PEM as
`tls.crt` and create private0600 `router.json` with target
`https://127.0.0.1:18443/rest`, the restricted disposable `mc-lab` fixture account
and the absolute CA path. The runner expects the existing lab account; never
reuse its public fixture password outside the disposable guest. Build the CLI
as `.cache/router-stage/mikrocentauri` before running:

```sh
go build -buildvcs=false -trimpath -o .cache/router-stage/mikrocentauri ./cmd/mikrocentauri
python3 tests/e2e/chr_staged_controller.py
```

The runner owns only instance `stage2secure`, requires a clean canary scope, and
compares unrelated configured state. The separate `lab/stagedfault` helper fixes
its target to this same localhost TLS fixture, uses instance `stage2tls`, discards
a successful PUT reply and blocks subsequent requests. Its expected failure
leaves a pending journal for a fresh `router-recover` process. Do not enable
fault injection in the product CLI.

Snapshot service/certificate settings before setup. After testing, remove both
canary scopes, restore the original `www-ssl` settings, remove the temporary
certificate/archive and shut down CHR normally. This setup and the accepted
results are recorded in the
[product Phase 2 report](reports/product-phase-2-staged-controller.md).
