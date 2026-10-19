# RouterOS connection wizard and independent management startup

The first-start wizard previously offered only a check button for a preprovisioned
connection, while the App launcher required that connection and the native runtime
profile together. An automatically bootstrapped installation could not complete
connection setup through the UI.

The new authenticated form verifies a private literal-IPv4 HTTPS REST endpoint,
service-account credentials, operator-provided public certificate trust, read-only
capabilities/ownership and network reads. Test and save are separate actions.
Credentials are committed atomically in a protected mode-0600 connection record,
are reused only for the identical endpoint/account, and are restored on restart.
Responses, safe backups, diagnostics and events never contain the password or
certificate body. The client verifies certificate IP identity and refuses redirects
and proxy-environment inheritance. Private-key uploads are rejected.

Read-only connections no longer require a native routing profile. Active native
owners keep their immutable operator-selected client. The form shows distinct
connection, platform, kernel device/capability and runtime readiness checks; saving
a read-only connection does not activate packet steering or assert write rights.
The preflight installation-availability flag remains false: automatic native
profile generation/application is not implemented by this connection change.

Local acceptance includes credential redaction and restart persistence, rejection
of unsafe targets and unauthorized access, preservation on failed checks, no secret
reuse across endpoints, immutable native-owner protection, private-key rejection,
real TLS trust/IP/redirect tests and independent read-only App serve arguments.
The complete Go race suite passed; targeted new boundary tests and vet passed.
All 18 Chromium/WebKit browser scenarios passed, including first-start setup,
failed verification, check-without-save, saved-password reuse, desktop/mobile
layout and the existing policy/selector workflows. Embedded UI reproduction passed.

The observed live ARM64 container exposes /dev/net/tun and NET_ADMIN, which removes
a hardware-capability guess but does not establish native routing acceptance.
Live provisioning and deployment evidence follows when confirmed.

## Live management acceptance

The explicitly approved provisioning and upgrade were completed on RouterOS
7.23.8 long-term, ARM64. The management URL remains
`https://10.99.0.1:8443/`. Main commit
`6ba588a932f2135a6ce8bd038385e949be457674` passed GitHub run `39263747787`;
the public catalog and anonymous-pull receipt select index digest
`sha256:61d64797a7509fea39aedbfdee6684aaf58b324fd11ff37f6c0404f98d813536`.
The running ARM64 controller SHA256 matches the release manifest:
`a67ebc5d3e3821fde0dafc776bd8fd887cf3702eea2716e16fc80afe5afabbbe`.

HTTPS REST uses a dedicated public CA and IP-identified server certificate with
certificate verification enabled. The observer account is restricted to the
container IPv4 address and policy `read,api,rest-api`; write, policy, sensitive,
reboot, SSH and other interactive permissions are excluded. Two scoped rules were
added before the existing denies: container-to-router TCP 443 and container-to-WAN
new connections. Existing LAN management restrictions remain in place. A verified
HTTPS request from the container to an Internet endpoint completed successfully.
No client DNS redirection or routing steering was enabled.

The existing catalog entry rejected YAML replacement and removal as a builtin
App. Its update command retained the old immutable image. On this release, attempts
to override the image through `container-command-lines` also parsed the digest
separator as a command separator; neither adding an empty command nor a native
copy of the displayed definition corrected that representation. Reset attempts
were rejected. This is an observed limitation of this upgrade path, not proof
that arbitrary App upgrades preserve data or accept image overrides.

The effective replacement is the custom App `mikrocentauri-2`, created from the
new complete YAML with the existing secret. Its production container is
`app-mikrocentauri-2`, at the original container IPv4 address. The old catalog
entry `mikrocentauri` remains **disabled**, with no associated old container; its
experimental override is not a rollback configuration and it must not be enabled.
The original App Store URL is retained. Future catalog migration should be handled
as a separate reviewed lifecycle task rather than enabling this stale entry.

Before replacement, a full 17-member state archive was downloaded only through
certificate-verified HTTPS, encrypted locally with AES-GCM, and decrypted again
for verification. PBKDF2-HMAC-SHA256 uses the existing App login password, a random
32-byte salt and 600,000 iterations. No password or plaintext archive was saved
locally. All 11 regular files were restored and compared byte-for-byte. Private
file/directory modes were repaired with a temporary file-based helper; temporary
command and entrypoint overrides were cleared before production startup.
Model and authentication hashes match the originals, and the original App login
and secret still work. A second encrypted archive includes the saved connection.
Private backup material and local receipts remain ignored by Git.

Live authenticated acceptance verified check-without-save, successful save,
mode-0600 connection storage under a mode-0700 directory, and a successful repeat
check using stored credentials. The App supervisor restarted the production
container after a deliberate stop; login, the stored connection and a fresh
read-only RouterOS check still worked afterwards. The container reached its
native healthy state with the normal image entrypoint and command. Its binary
hash matches the ARM64 build manifest.

Preflight confirms the RouterOS connection, TUN device and NET_ADMIN. It does
**not** qualify this hardware as the reference CHR platform, supply a native
routing profile, or report routing ready. `runtime_connected`, `routing_ready`
and `automatic_install_available` remain false. A working proxy must be imported
through the panel before a separately reviewed native profile and packet-path
acceptance can proceed.
