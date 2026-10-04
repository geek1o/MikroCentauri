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
can connect with `-netdev socket,id=lan,connect=127.0.0.1:19188`. A complete provisioned
Linux client image is not included; Linux Docker Compose alternative remains future.

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
sanitized result tables and hashes. `lab/e2e-status.json` records required scenarios
as NOT RUN until actual CHR packet evidence exists. No fabricated benchmark values.

## Executed CHR result

On 2026-10-04, CHR7.24.5 successfully imported and started the local amd64 probe,
opened `/dev/net/tun` and created TUN with root `user=0:0`, `privileged=no`. Exact
capabilities/kernel/feature mask and archive hash are in
`docs/reports/chr-capability.json`. RouterOS keeps VETH named `mc-probe` inside the
container; the TUN name must differ (`mc-tun-probe`). The first same-name attempt
returned EINVAL; privileged mode did not fix the collision. Transparent traffic
routing and fail-open remain NOT RUN.
