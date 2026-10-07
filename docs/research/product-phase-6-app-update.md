# RouterOS App immutable image replacement

The acceptance fixture is `tests/e2e/chr_app_install.py --image-updates`. It runs on the isolated stopped-disk clone `.cache/app-schema`, RouterOS 7.24.5 stable, x86_64. It serves immutable OCI manifests from a temporary certificate-verified local TLS registry. It never calls `/app cleanup` and never changes the original CHR fixture.

## Native findings and recovery workflow

RouterOS exposes `/app update` (REST `POST /rest/app/update` with `{ ".id": "<exact App ID>" }`). `/app repull` does not exist on this pinned version. Native console inspection confirms `update`, `reset`, and `remove` commands.

Replacing `yaml` alone retains the old `container-command-lines` value. A raw setter string such as `core:https://registry:port/repository@sha256:<digest>` looks correct when read back, but repull interprets `https` as an image name at the default registry. Escaping its colons with backslashes also fails extraction. `/app reset` with a custom same-name YAML returns `cannot change name`. These paths are not admitted upgrade procedures.

**Changing App YAML also invalidates the generated container and clears its managed named-volume state in the pinned fixture, including a change limited to healthcheck metadata.** Do not treat a YAML edit as a harmless in-place update.

Removing an App record and recreating it from the new YAML correctly generates the intended immutable image reference. **Removal clears the App-managed named-volume data.** A stopped-volume backup and explicit restore are therefore mandatory for the tested recovery path; `/app cleanup` is never used.

1. Disable the exact App and wait for its generated container to stop.
2. Copy the complete named `state` directory with binary-safe SFTP to a protected, separate backup. Preserve ownership-relevant file modes and verify the snapshot before removing anything.
3. Remove the exact disabled App record and wait for its VETH to disappear before recreating the same App name from YAML containing the intended immutable HTTPS image reference, keeping `state:/data` unchanged.
4. Create the missing App namespace/state directories and restore snapshot contents into that exact state directory, including bootstrap, authentication, model, draft, preferences and cache. Preserve the literal `state/.` upload source; normalizing it to `state` nests the snapshot when the destination exists. RouterOS SFTP accepts `scp -p` but does not preserve private Unix modes. Repair directories to `0700` and regular files to `0600` inside a bounded container helper before admitting the production entrypoint. Clear both native entrypoint and command overrides afterward.
5. Enable the App and verify the actual container remote image and OCI **config** digest, production default entrypoint, unchanged IP, authenticated API and byte-equal persistent state.
6. For rollback, repeat the stopped backup/recreate/restore procedure with the prior admitted image digest.

This is an explicit operator upgrade/recovery procedure with downtime. It is not automatic App updating and not proof of zero-copy volume persistence. The fixture uses only disposable clone credentials and localhost SSH forwarding; a production operator must authenticate SSH and verify the host key.

## Fixture boundary

The initial start copies private synthetic bootstrap files through fixture-only config mounts, initializes a valid empty sing-box BoltDB once, and creates durable authentication, model, edited draft and preferences. Before image replacement the fixture removes the shell entrypoint/command and all config mounts from YAML. Subsequent starts use the production Go image entrypoint. A fixture health check refreshes private byte-comparison evidence and calls production `app-health`. After the comparison stages, the fixture performs a further snapshot-backed recreate/restore with no YAML healthcheck override and waits beyond the image default 30-second interval before admitting the default image healthcheck. After SFTP restore, the fixture first materializes the production image; private-file admission fails before authentication changes. With the App disabled, a short-lived direct container helper repairs only file permissions and writes a marker. The fixture waits for that helper to exit, clears its native command/entrypoint overrides, and starts the App with production defaults. This permission repair is separate from production launch and is not retained in admitted A/B/A stages.

A and B have genuinely different immutable OCI manifest and config digests. Unless `--candidate-oci` is supplied, B changes only an OCI config label: its executable and filesystem layer are identical to A. This proves native image replacement and volume preservation; it does not prove semantic version, schema, or FakeIP alias migration. The empty cache cannot establish preservation of existing FakeIP allocations. Native dataplane acceptance is a separate fixture.

The acceptance results retain booleans for equality of authentication/model/draft/preferences/cache bytes, never password, key, bearer token, or authentication hashes. At completion the App is disabled and any clone-only management DNAT is removed; persistent data is retained for review.

The fixture also records actual Linux link/rule/route/TUN metadata in a private proof file. RouterOS truncates the Linux interface name to 15 characters (for the tested long App name, `veth-app-mc-ins`). Its default local policy rule priority is 200, with main/default priorities 2147483646/2147483647. Profile admission must use observed Linux names and priorities rather than assume standard Linux defaults.

Reference: [official RouterOS manual](https://manual.mikrotik.com/llms-full.txt), Apps section; `/console/inspect` and the pinned CHR provide the exact native update/command parsing evidence.
