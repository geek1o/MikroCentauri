# Fresh-router setup and selective-routing acceptance

## Scope and source review

This run uses the freshly reset RouterOS installation and its newly imported
subscription. No configuration, authentication database, subscription cache, or
native runtime state from the previous deployment was restored.

Local change `391ce14` introduced bootstrap listener reconciliation. Review found
that independently replacing the TLS certificate and private key could leave an
unbootable pair after interruption. Commit `96d78dd` retains the existing generated
P-256 key, verifies the bootstrap identity and protected paths, commits settings
last, and refuses automatic rebinding of an installed native topology.

The released controller also rejected RouterOS package catalogue entries that
have no installed version. Commit `0a20d61` skips only explicitly available,
disabled, versionless entries; ambiguous or installed versionless records still
fail validation. The new router supplied five installed packages and thirteen
such downloadable catalogue records. Read-only inspection and the production
setup API passed after this fix.

Public main `b486c632401cf28882b2b15feb0e9e0aa80468cb` contains the reviewed
implementation and tests. GitHub Actions run `40132420774` succeeded. Its published
image is
`ghcr.io/geek1o/mikrocentauri@sha256:74fd11e0db68390fc11df1296992481d644fff62988a71aeed1f592fcdb66abb`.
The installed ARM64 controller SHA-256 was verified as
`0228ba0a28b16850c6269a9495d9f313601edd97ab1252697b920f64657780b6`.

## State preservation and access

The new SSH host key was independently confirmed before sending credentials.
Router HTTPS trust was established against the leaf fingerprint read through
that SSH connection, followed by verification of the router CA. Certificate
verification was retained for both RouterOS REST and application HTTPS.

Encrypted RouterOS and full application backups were taken before changes. The
fresh application backup includes the imported source and all seventeen nodes.
All twelve original application files retained their original hashes across the
image update. Credentials, endpoint addresses, source URLs and private runtime
files are excluded from this report and Git.

A separate container-address-restricted read-only REST account was created and
tested through the production setup API. Native reconciliation uses a different
container-restricted account with write permission. Other accounts and unrelated
LAN, WAN, IoT and management policies were preserved.

## RouterOS App update observations

On the observed RouterOS 7.23.8, App Update re-pulled the digest stored in the
installed catalogue description. It did not adopt the newly published catalogue
image. The image-and-command override splits at a colon: writing an unescaped
OCI digest there incorrectly separates the image and command. That incorrect
pull was stopped and its image container replaced, retaining the mounted data.
The replacement pulled the verified new digest successfully.

The failed override and removed child left the App manager with an obsolete
container ID (`unknown id`), despite the replacement child serving healthy HTTPS.
A stopped-controller source backup captured all twenty-eight protected source
files, including the full imported subscription, both sections and the original
TLS identity. The source-only backup incorrectly excluded the binary engine cache; the
subsequent readiness refusal exposed this operator error. See cache recovery
below. Native App
cleanup cleared the stale child association and refreshed the catalogue to the
new pinned digest. The protected source archive was staged for restoration before
production restart. No tag override is needed in the final installation.

Restarting the sole enabled App also recreates RouterOS's internal bridge. A
pre-existing egress rule retained the removed bridge ID and became invalid.
Instance-owned rules therefore use the exact App source address, router DNS
address, LAN prefix, selected destination list and WAN interface list, without
binding to the ephemeral internal bridge. No broad forwarding permission or
firewall reset was introduced.

## Native policy and acceptance boundary

The model retains all seventeen imported nodes and selects one node that passed
isolated YouTube, Telegram and HTTPS egress checks. Two other initial candidates
did not pass that qualification; this deployment does not certify every node or
automatic multi-node failover.

The enabled sections contain YouTube domain suffixes, Telegram domain suffixes
and the nine IPv4 prefixes from [Telegram's published network list](https://core.telegram.org/resources/cidr.txt). Other traffic
uses DIRECT. RouterOS FWD records learn the real addresses returned to LAN clients
through the router's existing verified HTTPS DNS resolver. That resolver remains
independent of application availability. IPv6 was already disabled and was not
changed.

Native steering uses a dedicated routing table, a LAN-source and destination-list
mangle rule, a finite volatile UP lease, a private readiness endpoint, debounce,
and a boot guard. Targets were initially installed disabled, with an operator
rollback timer armed before installation. The readiness canary verifies HTTPS
and the independently observed proxy egress address; readiness was not bypassed.

Initial physical-LAN acceptance used the Mac Ethernet interface and explicit
fresh RouterOS DNS answers, avoiding its separate VPN. YouTube returned HTTP 204,
Telegram Web returned HTTP 200, and a Telegram TCP MTProto req_pq_multi exchange
returned resPQ with the original nonce. A separately steered HTTPS trace from
that LAN client matched the qualified proxy egress and differed from the same
client's DIRECT egress. The temporary trace destination was removed afterward.

## Cache recovery

The engine cache is durable alias authority, rather than a disposable performance
cache. Restoring its alias ledger without that cache correctly caused engine
preflight to refuse recovery. Neither the ledger nor the namespace was cleared,
and no fake addresses were renumbered to work around the guard.

The three retained mappings were reproduced using the same pinned sing-box
version and the same FakeIP prefix and cache settings, without proxy credentials.
Their exact domain-to-FakeIP associations were checked, the process was stopped,
and a second process queried those names in reversed order to prove persistence
and equality to the original ledger. The regenerated binary cache was transferred
through a protected one-shot helper, checksum-verified and atomically installed.
This recovery is specific to the three fully known mappings; it is not a general
claim that arbitrary missing caches can safely be regenerated.

## Lifecycle acceptance

After exact cache restoration, RouterOS App Store reported RUNNING with no
configuration error, and the child reported HEALTHY using the default pinned
image entrypoint and command. Native readiness became true, a finite UP lease
was present, and all three physical-LAN probes passed again: YouTube HTTP 204,
Telegram Web HTTP 200, and Telegram MTProto resPQ nonce verification.

A controlled stop had already shown lease expiry and all owned steering targets
disabled, while RouterOS DNS and DIRECT HTTPS remained available. Instance-owned
firewall rules retained valid bindings across App network recreation.

The final backup includes the binary engine cache, the immutable alias ledger,
namespace, process source models, authentication, subscription and both enabled
sections. Its encrypted payload is decoded and checked before the temporary
router-side archive is removed. This supersedes the earlier source-only backup.

The complete backup contains twenty-nine files, including the binary cache.
After its graceful-stop checkpoint, the normal App was started again without
entrypoint or command overrides. App Store RUNNING, container HEALTHY, native
readiness and the finite lease were confirmed. All five physical-LAN checks passed:
YouTube generate_204, YouTube homepage, YouTube image CDN, Telegram Web and the
Telegram MTProto nonce exchange. This verifies HTTP and protocol reachability;
a full video playback session was not exercised.

A final LAN HTTPS trace matched the qualified proxy egress. Removing its temporary
steering entry returned the identical target and client to the original DIRECT
egress. The two addresses differed. Native service steering counters advanced.
The temporary test entry and the operator rollback timer were removed only after
acceptance, while the permanent readiness watchdog and boot guard remained active.
An accepted encrypted RouterOS configuration backup was then saved.

No router reboot was performed. Clients in the configured LAN must use RouterOS
DNS for domain-to-address learning. Per-client encrypted DNS or an independent
client VPN can bypass that learning and require separate policy work.
