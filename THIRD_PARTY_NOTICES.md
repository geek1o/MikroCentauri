# Third-party notices

MikroCentauri application source is independently written and MIT licensed.
No reference-project application code, logos or UI assets are included.

## Engine

sing-box is a separately executed upstream binary. Its pinned version is 1.14.2;
it is GPL-3.0-or-later with additional naming/association restrictions described
in its upstream license. MIT licensing of this application's source does not
remove the engine's distribution obligations. Distributed images must include
applicable notices and complete corresponding source/build material for the
exact engine and included dependencies. See the published build's license and
source inventory; the repository's source alone is not that complete inventory.

## Base system

Image inputs are checksum-pinned Alpine 3.24.2 rootfs archives. Components such
as BusyBox and musl have their own licenses; GPL components require applicable
corresponding source. Image SBOMs identify actual bundled packages. Build-only
Linux/VM fixtures must not be confused with the application's shipped userspace.

## Web UI and tooling

The embedded UI includes Svelte 5.57.1 and Vite 8.3.3-generated runtime helpers
under MIT. Their upstream copyright/permission notices are retained in
`frontend/public/licenses.txt` and served at `/licenses.txt`. Lockfiles identify
build tooling and dependencies. Node, TypeScript, formatters and browser-test
runtimes are development tools, not application server runtimes.

The Go toolchain has its own license. The disposable HTTP/3 test module, when
retained, uses separately licensed Go dependencies recorded in its module files;
it is not part of the shipped controller runtime.

## RouterOS

RouterOS/CHR is proprietary MikroTik software. RouterOS images, NPKs and lab disks
are operator-supplied local inputs and are not redistributed by this project.
No MikroTik, sing-box or other upstream endorsement is implied.
