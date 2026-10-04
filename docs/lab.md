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
