# Upgrade MikroCentauri

The RC upgrade procedure is an explicit, stopped App replacement on **CHR
RouterOS 7.24.5 x86_64**. Automatic updates remain disabled. Native acceptance
used two genuinely different image configurations, a nonempty engine cache and
cached TCP/UDP/HTTP3 traffic; it did not establish compatibility with arbitrary
future state schemas. See [the acceptance report](reports/product-phase-7-hardening-completion.md).

## Prepare the replacement

1. Verify the release checksums and the image's platform, index/manifest and
   **config** digests. An index digest selects the immutable multi-platform
   image; the config digest binds stopped-container and boot identity. They are
   different values. For the accepted RC image, use the digest table in the
   [E2E report](reports/product-phase-8-e2e.md#accepted-image-identity).
2. Retain the current immutable image and its notices/source materials. Record
   the exact App/generated-container names, VETH/IP/Linux ingress interface,
   state mount, private profile, observer, startup guard and operator scheduler.
   Review the candidate's state-format compatibility before replacement.
3. Arrange exclusive administrative control and a maintenance window. Disable
   the exact operator App boot scheduler first: it is bound to the old config
   digest. Leave the independent controller startup guard in place.
4. Disable/stop the App and wait for its child to stop. Confirm that all three
   exact controlled steering targets are disabled and the dynamic UP lease is
   absent. DOWN must be observed; a failed management read is not proof of DOWN.
   Test the reviewed DIRECT fallback from a LAN client.
5. Take a complete, binary-safe, protected SFTP snapshot of the **stopped** state
   outside RouterOS-managed `state`. Include bootstrap, authentication,
   drafts/subscriptions, namespace/publication journals, verified rule sets and
   engine cache. Preserve a private file inventory and SHA256 hashes. Keep this
   snapshot unchanged through upgrade and rollback.

The UI's safe backup excludes credentials, allocator state and engine cache. It
cannot replace this full installation snapshot. Treat the latter as secret data;
never attach it to issues, release assets, diagnostics or Git.

## Recreate and review while stopped

1. Render the App YAML with the intended immutable image, using that release's
   `build.json`. The renderer checks the exact index and both platforms:

   ```sh
   python3 scripts/render-app.py \
     --image <registry>/<repository>@sha256:<release-index-digest> \
     --build <release-directory>/images/build.json \
     --out <review-directory>
   ```

   Rendering does not publish a registry image. An import archive is not evidence
   that a remote registry reference can be pulled.
2. Remove/recreate only the reviewed App, with the **same exact name**, keeping
   it disabled. Wait for the old VETH to disappear before recreating it. On the
   pinned release YAML updates/removal can clear managed `state`; neither
   `/app/update` nor editing container command strings is an accepted safe path.
3. Restore snapshot **contents** into the exact new `state` directory. Repair
   private directories/files to `0700`/`0600` with a bounded stopped-container
   operator helper. Native SFTP uploads as `0644` despite preservation flags.
   Compare every original file's bytes/hash before startup. Preserve the
   original snapshot separately; do not use `app-provision` to overwrite state.
4. Remove temporary transfer/helper mounts and all entrypoint/command overrides.
   Check the image, IP, interface, persistent mount and production defaults.
   Run fresh `app-install-plan`, review/apply only its exact native privilege
   action, then `app-install-verify` as described in the
   [installation guide](install.md#stopped-installation-review). Old or expired
   reviews cannot authorize the new container.

## Admit and verify

Enable the App after verification. Require image-default TLS liveness,
authenticated native readiness and a **fresh finite dynamic UP lease**. Verify
login/private settings and retained alias identity; run selected PROXY,
unselected DIRECT and a previously cached alias through fresh TCP, UDP and
HTTP/3 connections. API liveness alone does not admit forwarding. Account for
native convergence; no zero-loss or established-session migration is promised.

After traffic passes, render/review the boot scheduler for the new **config**
digest and exact current names. Update only that operator scheduler and test two
successive actual reboots: fresh lease, production health and the same traffic
checks on both. Keep the startup guard independent. The renderer command and
reviewed scheduler behavior are in [installation](install.md#reviewed-boot-configuration).

If any check fails, retain diagnostics without secrets, disable the App and
observe DOWN/DIRECT, then follow [rollback](rollback.md). Do not reset/reallocate
FakeIP aliases or discard the protected snapshot to make admission pass.
