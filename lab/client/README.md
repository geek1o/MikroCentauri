# Client workload (pending CHR packet-path provisioning)

Attach a dedicated Linux VM NIC to the runner's LAN socket 127.0.0.1:19188, set
192.168.88.10/24 and gateway/DNS 192.168.88.1 after creating that LAN on CHR ether2.
A second client IP is needed to distinguish source policies. No claim of automated
client boot/provisioning is made yet.

Workloads: ordinary HTTP, selected exact domain, two-device source policy,
TCP/UDP DNS, UDP echo, HTTP/3, endpoint loop capture, fail-open/crash/recovery.
Do not treat host explicit-SOCKS requests as LAN transparent routing evidence.
