# Scoped Linux forwarding barrier

`New(Options)` implements `coreactivation.Barrier` for a Linux RouterOS
container. It requires a dedicated routing table, a dedicated rule priority, an
exact ingress interface, a TUN interface/address, a native revocation barrier
and an actual controlled SOCKS canary. The owner must hold DNS and readiness
before calling `Quarantine`; the supervisor separately stops the child.

Typical fixture values are ingress `mc-probe`, TUN `mc-tun`, table `100`, priority
`10000`, TUN address `172.31.255.1/30`, and private mixed listener
`127.0.0.1:2080`. `LocalRulePriority` pins the kernel local-table exception;
its default is `0`. The observed RouterOS container uses local priority `200`
and main/default priorities `2147483646`/`2147483647`, so its explicit fixture
profile pins `LocalRulePriority: 200`. This accepts only the exact
`from all lookup local` row at that priority; a foreign main-table rule at
priority `201` still fails. Interface, TUN, table, ingress priority and canary
remain explicit configuration inputs.
Production callers must allocate their own isolated table and priority. The
default runner invokes `/sbin/ip` with individual arguments and no shell. The
default forwarding reader requires `/proc/sys/net/ipv4/ip_forward` to equal `1`.

`Quarantine` reads policy and table ownership before a write. It accepts only an
empty table, its default TUN route, or its blackhole default. Unknown routes,
duplicate/conflicting owned-priority rules, or an earlier non-local policy that
could bypass this ingress rule are rejected. It installs a scoped blackhole,
ensures and reads back the exact interface rule, then asks the native barrier to
prove authority revoked. It does not flush a global table or firewall.

`Verify` requires the blackhole/rule still present, IPv4 forwarding enabled, TUN
UP with the configured IPv4 address, native revocation and an end-to-end canary.
The SOCKS endpoint must be a literal loopback address. Default canary policy
requires its hostname in the model's Active selected domains. `IndependentCanary`
permits a dedicated literal unicast IPv4 echo target independent of Active;
this allows an empty active namespace without retaining an artificial user
selected domain. A separate generated proxy route must carry that canary. The
canary response's actual `remote_ip` must equal `Canary.ExpectedPeerIP`, so a
successful DIRECT fallback cannot satisfy the proof. Use a trusted HTTPS canary
outside the isolated fixture; plain fixture HTTP does not authenticate its echo.

`Release` consumes a successful Verify, then repeats quarantine, TUN and native
checks. Only then does it replace its blackhole default with the TUN default and
read back that route. A recognized failed release restores the owned blackhole
under a separate three-second cleanup context. Unknown or unavailable readback
cannot prove ownership and is left untouched; readiness must remain held and
recovery must re-establish a valid barrier. Native UP is never granted here: the
independent observer admits it only after the owner publishes readiness.

Bounds are interface names of at most 15 characters, table IDs `1..252`, rule
ingress priorities `1..32765`, local priority `0..RulePriority-1`, IPv4 TUN
prefixes, and 64 KiB accepted command readback.
Every command uses the caller's context; native waits must fit that deadline.
`Runner` and `ReadForwarding` are trusted test seams. The production native
barrier requires HTTPS and exact regenerated watchdog hooks, target identities,
disabled target state, and absent finite dynamic authority. Its explicit lab
constructor supports the pinned legacy lease fixture only. Native Quarantine
retries read-only transport unavailability under the same caller deadline, with
100 ms intervals. This covers initial native-interface/ARP warmup such as
`EHOSTUNREACH`; it never repeats a write. HTTP denial, malformed responses and
ownership/configuration mismatches fail immediately. Native Verify does not
accept an unavailable read as proof of revocation.

Tests cover ordering, foreign-policy refusal before writes, failed canaries,
missing forwarding/TUN state, selected and independent canaries, and unknown
release readback. They use an injected runner and checker. Kernel policy reads
and writes are not a global compare-and-swap transaction: a concurrent external
namespace writer can race the observations. The owner serializes its lifecycle,
keeps native authority revoked until readiness, and does not claim atomic packet
cutover or protection from arbitrary unobserved kernel edits.
