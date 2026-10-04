# Prototype troubleshooting

Use exact pinned sing-box 1.14.2; moving website examples can include future fields.
CLI errors hide sing-box stderr because it may include secrets. For trusted local
lab fixtures, run `sing-box check -c <private-candidate>` directly to inspect details.
Do not paste private endpoint output into diagnostics or Git.

CHR package absent after cold reset: transfer a matching official NPK again, verify
file size, and use **RouterOS `/system/reboot`** to trigger package installation.
Enable device-mode and confirm physically in the isolated lab. TUN node presence
alone does not mean `TUNSETIFF`/routing is permitted. Use the probe before dataplane.

FakeIP after a crash: cached addresses remain synthetic; disabling a route will not
make them public destinations. Read ADR-0002. A lab readiness/Netwatch pair restores new real-IP DIRECT but does not translate
cached FakeIP or detect remote VLESS outage. Complete production failure recovery
remains unimplemented; exact observed limitations are in the Phase-1 report.

Alpine sing-box exits with a loader error: use checksum-pinned **linux-amd64-musl**,
not the dynamic glibc build. Gateway fetch replacement loses execution permission:
import the image to a fresh container root after stopping the old container.

Lab VM crypto startup consumes CPU without listener/logs: ensure virtio-rng device
and module are present. The measured Go stack was in vgetrandom before CRNG became
ready. Do not disable TLS verification as a workaround. A disconnected QEMU socket
NIC can report link-up inside the guest: start Ethernet switches before launching
both CHR and Linux VMs, then relaunch QEMU if a connection was initially missed.
