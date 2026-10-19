# RouterOS connection setup

Open **Initial setup → RouterOS connection**. The connection form is available
before any native routing profile exists. Saving it never activates packet steering.

## Prepare RouterOS once

1. Create a certificate authority and a server certificate for the router's private
   IPv4 address. Assign the server certificate to `IP → Services → www-ssl` and
   enable that service. Export only the public authority certificate as PEM.
2. Create a dedicated group with `read,api,rest-api` and a dedicated user. Limit
   that user's allowed source address to the App's container IPv4 `/32`.
3. Permit that container IP to reach the router's HTTPS REST port in the input
   firewall. Preserve the existing management and WAN policy. The controller uses
   `/rest`; enabling the separate `api-ssl` service does not enable HTTPS REST.
4. If the App's outbound traffic is blocked by a custom forward policy, explicitly
   review its Internet access separately. Subscription/list downloads need DNS
   and HTTPS; proxy transports need the chosen provider's ports. Do not grant
   general access to other LAN zones as a substitute.

Reference: [MikroTik REST API](https://manual.mikrotik.com/docs/developer-guides/rest-api/).

## Verify and save

Enter `https://<private-router-ip>/rest`, including the port when it differs from
443, and the service account's username/password. Under certificate trust, upload
the authority's public `.crt` file or paste its PEM. Verify its identity through
WinBox or another independent trusted management channel. Private keys are rejected.

**Check connection** verifies TLS certificate/name, authentication, the read-only
capability/ownership snapshot and the network projection. It does not save inputs
or test write permission. A failed check does not replace an existing connection.
**Save connection** repeats those checks and atomically saves a mode-0600 private
connection file beneath the protected API state directory. The read-only RouterOS
resources become available immediately; a container restart is unnecessary.

After reload, address, username, password-presence and certificate fingerprint
are visible. Password and certificate bodies are not returned. Blank password or
certificate values reuse stored inputs only for the identical address/account.
Changing either requires explicitly supplied credentials. Connections to public,
loopback or DNS-named destinations and cleartext HTTP are rejected. Redirects and
proxy-environment inheritance are disabled.

The saved connection loads after an application restart. Credentials are excluded
from safe backups, diagnostics and event records. Retain a protected volume backup
for installation recovery. A connection used by an active immutable native profile
is read-only in this form and requires its own reviewed change procedure.

## Routing preparation

The wizard separately reports RouterOS platform qualification, the container TUN
device and NET_ADMIN capability, the native profile and active routing readiness.
Successful REST access is not routing readiness. The tested reference profile
remains CHR x86_64 7.24.5; ARM64 device management does not by itself qualify packet
steering, reboot or proxy failure recovery. A native routing installation needs an
explicit reviewed topology and independent proxy canary, followed by the protected
runtime profile described in [native runtime](api/runtime.md).
