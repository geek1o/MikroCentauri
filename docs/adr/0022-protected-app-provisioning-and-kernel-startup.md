# ADR 0022: Protected App provisioning and kernel startup

Status: implemented; native acceptance is recorded separately in the Phase 6 report.

Keep first provisioning separate from normal startup. The production Go
`app-provision` command validates an allowlisted bounded private tar in temporary
staging, then publishes private bootstrap files into an empty persistent volume.
A sole real empty bootstrap directory copied from the image is allowed; existing
files, siblings, symlinks and overwrites are refused. Settings are published last.
Failure removes only newly created paths and restores existing directory modes.
The command grants neither authentication nor readiness.

Native SFTP on the pinned RouterOS release does not preserve private Unix modes.
A bounded operator helper repairs the transferred archive mode before provisioning.
Its mount and command/entrypoint overrides must be removed before read-only
installation review. Review rejects every extra mount, including executable
shadowing outside `/data`. YAML privilege hints are insufficient: keep the App
stopped, apply the exact reviewed native container privilege, then verify identity.

The default Go launcher establishes `umask0077` before creating owners or children.
The native App default was observed as `umask0000`: sing-box created a `0666` cache
and the existing engine guard correctly denied recovery. Go's explicit private
file modes do not constrain child-created files. Do not weaken that guard or use
a permanent shell wrapper. Restore the previous process mask only after owners
have shut down.

Before authentication initialization, validate the reviewed profile, observed
Linux ingress name, fixed TUN clone device and dedicated policy table/priority.
Quarantine ingress before enabling IPv4 forwarding. Refuse foreign kernel state.
The helper never creates the sing-box TUN interface or admits traffic; the existing
native owner supplies readiness, generation proof and finite RouterOS authority.
On shutdown close that owner first, then restore forwarding if this invocation
changed it from disabled to enabled.

An App YAML edit or record removal can clear managed state on RouterOS 7.24.5.
Immutable image replacement therefore uses a protected complete stopped-volume
backup, exact-name recreate, explicit restore and permission repair, followed by
fresh installation verification and default-entrypoint admission. Original bytes
must match before startup; admitted cached-alias traffic is checked afterward.
Automatic updates remain disabled. Device/release expansion and unattended
installation are not inferred from these bounded native observations.
