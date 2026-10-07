# Upgrade and rollback

Automatic App updates are disabled. Use an exclusive maintenance window and keep
an independent management path. Native App removal or YAML replacement can clear
the managed state volume on the tested RouterOS release.

1. Record the admitted image index, platform manifest and **config** digests,
   exact App/container names, IP/interface, volume, profile and boot helper.
   Verify the new build's checksums and review state-schema compatibility.
2. Disable the exact operator boot scheduler, stop/disable the App, and wait for
   its child to stop. Read back disabled controlled steering and absence of the
   dynamic UP lease. Test the reviewed DIRECT fallback from a LAN client.
3. Make a complete binary-safe, protected snapshot of the **stopped** volume
   outside managed `state`. Include credentials, bootstrap, journals, allocator,
   verified rule sets and engine cache. Retain a private hash inventory. A UI
   export is not a replacement for this snapshot.
4. Recreate only the exact same App name at the intended immutable image, while
   disabled. Wait for the previous VETH to disappear. Restore snapshot contents
   into the exact new volume, repair directories/files to `0700`/`0600`, and
   compare original hashes before startup. Keep the original snapshot unchanged.
5. Remove temporary helpers/mounts/entrypoint overrides. Run fresh stopped
   installation plan/privilege review/verification from [installation](install.md).
   Old reviews cannot authorize a new container.
6. Enable and require TLS liveness, authenticated native readiness and a fresh
   finite lease. Test selected PROXY, unselected DIRECT and retained cached aliases
   with fresh TCP, UDP and HTTP/3 connections. Review the boot helper for the new
   config digest and test two successive real reboots.

If checks fail, preserve redacted diagnostics and stop the App. Rollback follows
the same stopped procedure using the **previous admitted immutable image and
its original pre-upgrade volume snapshot**. Do not merge newer state into it or
assume older code can read a newer schema. Verify the restored image/config,
private hashes, fresh admission and traffic before returning to service.

If verified recovery material is unavailable, preserve existing state and keep
the App disabled with the reviewed DIRECT fallback. Never reset the allocator or
reuse retained client aliases against an empty ledger. No zero-loss cutover,
established-session continuation or arbitrary schema downgrade is promised.
