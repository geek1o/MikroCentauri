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
