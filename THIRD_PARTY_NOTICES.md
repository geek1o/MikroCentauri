# Third-party notices

Repository code is independently written, MIT licensed. No Podkop, Tachyon,
Forkop, Steer, LuCI frontend code or assets are copied. Research excerpts and attributions are in docs.

sing-box is a separately executed upstream binary, GPL-3.0-or-later with additional
name/association restrictions. It is downloaded to ignored local cache and is not
redistributed in this Git repository. When bundling/distributing an image, include
upstream license/notice and corresponding source for the exact pin and modifications
as required. Independent MIT source does not remove these binary-distribution obligations.
See `docs/legal/license-audit.md` and upstream LICENSE at the pinned tag.

RouterOS/CHR is proprietary MikroTik software; official images and NPK are user/local
lab inputs and never redistributed here. Go toolchain is a local build dependency.

The isolated HTTP/3 laboratory has its own Go module under `lab/quic`: quic-go
v0.63.0 and qpack v0.6.0 are MIT; golang.org/x/{crypto,net,sys,text} use BSD-3-Clause.
The module's go.sum pins its dependencies; none are vendored into this repository.
The public deterministic test certificate/key is fixture material, never a deployment key.

Local VM/image builders download checksum-pinned Alpine 3.24.2 rootfs and netboot
assets. These include separately licensed operating-system components (including
Linux/BusyBox GPL and musl MIT); generated local archives are ignored and are not
redistributed here. A future distributed app image requires a complete binary
license/source inventory in addition to sing-box's corresponding-source obligation.
