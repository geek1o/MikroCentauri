# Version baseline

Research date: **2026-10-04**, Europe/Moscow. Namespaces use `mikrocentauri`,
CLI `mikrocentauri`; no project Git remote or public registry has been assigned.

| Component | Baseline | Evidence / execution |
|---|---|---|
| RouterOS latest stable | 7.24.5, released 2026-10-01 | [Vendor stable changelog](https://mikrotik.com/download/changelogs?channelFilter=stable) |
| Minimum installation target | >= 7.22 | [Custom Apps](https://manual.mikrotik.com/docs/containers/apps/); full dataplane support conditional on capability tests, not promised for every 7.22 device |
| CHR lab | 7.24.5 official raw image | TESTED boot/package/device-mode and non-privileged container TUN creation; no full packet-path claim |
| sing-box | 1.14.2, `af6e64c3b69e6132ebaee0e1a3d24e93903f6709` | [Release](https://github.com/SagerNet/sing-box/releases/tag/v1.14.2); real check and process smoke executed |
| Production architectures | linux/arm64, linux/amd64 | Go cross-build targets; RouterOS reports arm64/x86 or CHR x86_64; packaging compatibility not yet tested |
| Go | 1.27.1 | [Official downloads](https://go.dev/dl/?mode=json); locally verified SHA-256; stdlib only |
| Node | Not used | No frontend before dataplane gate |
| Python lab helper | 3.14.6 locally | Standard library only; Python >= 3.12 required for safe tar extraction |
| QEMU lab host | 11.1.1 on macOS arm64 | TCG emulates amd64 CHR; no hardware-performance interpretation |
| Podkop | release 0.7.22; source `c0a2736bb95884c19fedf638345ed6148c5fd6af` | [Audit](reference-audit.md) |
| Tachyon | release 1.4.10; source `6c2f9a3a4a9c427c34c3572a82d2292ca5961a85` | [Audit](reference-audit.md) |
| Forkop | release 1.0.5; source `dd483297be0ac4e52bb8f482e2640238b75af532` | [Audit](reference-audit.md) |
| Steer | release v2.0.2; source `fa24f0588b8375a7a46a927f78151ea6ea7798fa` | [Audit](reference-audit.md) |

Exact Go and sing-box binary download URLs/checksums for four developer-host
platforms are committed in `toolchain.lock.json`. No toolchain/runtime is globally
installed. Downloaded binaries, CHR disks and NPK files stay in ignored `.cache/`.

The moving sing-box website already describes 1.15 changes; generator validation
uses **1.14.2**, not unreleased API fields. Current RouterOS manual also contains
7.25-verified REST examples; 7.22/7.24.5 support needs release-specific execution.

## Lab provenance

Downloaded from official MikroTik HTTPS endpoints, not redistributed in Git:

- CHR archive `chr-7.24.5.img.zip`: verified SHA-256
  `16f07222a3213352c9c4fbea4f4dec6a8ffb78fdc0fa5e398c23103ed357c6eb`.
- x86 container package from official extra-package archive: verified SHA-256
  `7515c52499bd11b063517c7b48a6553519976098040d9dec67f6bf087876a3c9`.

Both hashes match the vendor-published HTTPS `.sha256` sidecars.
The initial downloaded zip is preserved; the working CHR disk is a separate copy.
