# Roll back MikroCentauri

Rollback means restoring the previous **admitted immutable image and its own
complete stopped-volume snapshot**. It is an operator procedure, qualified on
CHR RouterOS 7.24.5 x86_64; it is not an automatic image downgrade or a promise
that older code can read a newer state schema. The Phase 7 native run accepted
rollback/return between two different image configurations with preserved
private bytes, a nonempty cache and cached TCP/UDP/HTTP3 traffic.

## Required recovery material

Retain the previous platform image/index/manifest/config digests and verified
image bytes or available immutable registry reference. Retain the original
pre-upgrade full private state snapshot, inventory/hashes, exact App/container
identity, network/profile settings and previous digest-bound boot scheduler
review. Keep release licenses and source materials with distributed images.
The safe UI export omits credentials/allocator/cache and cannot recover a lost
installation identity. Never reuse an empty ledger with retained client aliases.

## Restore while stopped

1. Under exclusive administrative control, disable the exact operator boot
   scheduler and disable/stop the current App. Wait for its child to stop;
   positively read back disabled controlled steering and absence of its dynamic
   UP lease. Check the reviewed LAN DIRECT fallback. Preserve bounded redacted
   failure diagnostics and, separately, a protected snapshot of the failed
   installation if needed for investigation.
2. Remove/recreate only the exact App using the previous immutable image YAML,
   keeping it disabled. Wait for the old VETH to disappear. Assume managed
   `state` can be cleared by native App removal/recreation.
3. Restore **contents of the original pre-upgrade snapshot**, rather than
   merging it with newer state. Confirm exact state location and private file
   hashes before startup; repair directory/file modes to `0700`/`0600` with the
   bounded stopped helper. Do not modify the recovery snapshot itself.
4. Remove all temporary mounts/helpers/command overrides. Run a fresh stopped
   `app-install-plan`, review/apply the exact privilege action and run
   `app-install-verify` for this previous image's **config** digest. Recheck
   image, IP/Linux interface, model/profile, trust and the persistent mount.
   See [installation](install.md#stopped-installation-review) for commands.

## Prove recovery

Enable only after review. Confirm TLS image-default health, fresh login,
authenticated native readiness and the finite dynamic UP lease. Sessions from
the stopped process are invalidated; preserving authentication files preserves
the password identity, not bearer tokens. Check retained namespace/alias
identity, selected PROXY, native DIRECT and previously cached aliases through
fresh TCP, UDP and HTTP/3 connections. No established-flow continuation is
claimed. A live UI with readiness false remains a failed recovery.

Render/review the operator boot scheduler against the **restored** image config
digest and exact current names. Update only that helper; leave the independent
startup guard active. Test two consecutive actual reboots before returning to
unattended operation. Keep the failed candidate's private snapshot separate from
the accepted rollback snapshot.

If the previous image/snapshot cannot be verified, keep the App disabled and
observed DIRECT fallback, restore network service through the reviewed operator
configuration and preserve existing state. Do not invent a compatible downgrade,
reassign cached FakeIP addresses or import a credential-free backup as complete
installation recovery. See [upgrade](upgrade.md) and
[known limitations](known-limitations.md).
