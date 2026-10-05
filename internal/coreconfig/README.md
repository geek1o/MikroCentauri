# Product core schema v2

`Decode` accepts bounded JSON with unknown fields, duplicate keys, trailing data,
and excessive nesting rejected. `Model.Validate` checks stable endpoint IDs,
enabled references, group cycles, canonical IPv4 prefixes, domain names, ports,
health intervals, and private cache paths. This is a separate product schema;
the v1 dataplane milestone model and its generator are unchanged.
At least one enabled endpoint is required. Full mode requires a proxy default;
hybrid mode can retain a DIRECT default with explicit selected-domain policies.

`Generate` / `GeneratePinned` emit sing-box 1.14.2 JSON. `GenerateWithOptions`
changes the private DNS and mixed listener ports for isolated integration tests.
Both listeners bind `127.0.0.1`; TUN does not install automatic routes. Generation
does not publish DNS, enable RouterOS rules, or authorize new FakeIP aliases.
The publication controller must use the existing finite namespace admission,
engine guard, DNS gate, and durable activation mechanisms before exposure.

Routing order is DNS interception, source DIRECT, source PROXY, terminal exact
selected-domain routes, sniff, then application rules in declared order and
the default outbound. Source lists may overlap: DIRECT has explicit precedence;
overlapping PROXY policies use declared order. Domain-only rules determine the
immutable outbound for selected aliases. Service/port/network rules run after
the terminal selected-domain rules and therefore cannot reinterpret an already
published selected alias. They classify ordinary real-DNS destinations. Exact
FakeIP domain routes precede sniff because FakeIP rewriting makes a raw CIDR
sniff exclusion insufficient (ADR0014).

DNS uses typed UDP bootstrap and FakeIP servers. Selected A responses have TTL30;
selected AAAA queries return empty NOERROR. The cache stores FakeIP state in a
clean `/data/` path. Wildcard/suffix FakeIP selection is rejected until finite
namespace admission covers it; ordinary domain-suffix route rules remain valid.
Socksify uses real DNS and does not store or expose synthetic destinations.

Groups are selector, URLTest and application fallback. sing-box has selector and
URLTest outbounds; fallback compiles to selector. `FallbackSelection` selects the
first freshly healthy member using explicit observations. `Model.Select` creates
a validated replacement model for supervisor apply; it does not switch a live
process or probe endpoints. If all members fail, callers retain the prior
revision and close traffic activation. URLTest cannot be manually pinned.

The source of sing-box behavior is the official [selector documentation](https://sing-box.sagernet.org/configuration/outbound/selector/),
[URLTest documentation](https://sing-box.sagernet.org/configuration/outbound/urltest/),
[route rules](https://sing-box.sagernet.org/configuration/route/rule/), and
[typed FakeIP DNS server](https://sing-box.sagernet.org/configuration/dns/server/fakeip/).
Actual schema compatibility is tested by the pinned binary, rather than inferred
from the latest website.

`TestPinnedMixedRuntimeRoutes` additionally launches two real pinned sing-box
processes: the generated socksify client and an isolated Shadowsocks server.
Two local HTTP targets prove that a DIRECT service rule bypasses the endpoint
and the default selector sends a request through it. Private random listener
ports and a temporary cache path keep the test isolated. This is explicit mixed
proxy TCP evidence, not RouterOS TUN, UDP, QUIC, TLS credentials, or external
FakeIP publication evidence.

`GenerateForNamespace` is the closed v2 allocator policy. It requires a committed
finite snapshot and exact agreement between the model's selected domains and
the snapshot's active list. Internal DNS allocates all historically known names,
including retired names needed to re-admit cached aliases. Active terminal domain
routes keep their chosen outbound; retired terminal domain routes use DIRECT;
both precede sniff. `ValidateForNamespace` strictly compares bounded candidate
JSON against regeneration and rejects any configuration deviation.
`ValidateNamespaceTransition` rejects removal/reordering of previously known
names, uncommitted snapshots, and inconsistent revisions. Callers must obtain
snapshots from the durable locked store; these APIs do not authenticate an
arbitrary caller-created snapshot or validate the engine cache database.

`Options.CachePath` optionally maps persistence into a trusted runtime directory.
Its caller must check private directory/file metadata; the application model
still accepts only a `/data/` cache path. Exact preflight includes this mapping.

`TestPinnedNamespaceCachedAliasBinding` runs the namespace generation with real
pinned processes and controlled bootstrap DNS. Host-only adaptation removes TUN
and assigns the test resolver's random UDP port after the original config passes
preflight. Cached synthetic destinations retain their identity across process
restart and retirement; misleading HTTP Host and TLS SNI cannot promote retired
aliases to proxy or demote active aliases to DIRECT. The TLS test trusts only
its disposable local fixture by explicitly disabling certificate verification
inside the test client. This proves engine binding on private mixed sockets;
external DNS retirement responses, native RouterOS forwarding, and publication
admission remain the responsibility of the runtime bridge and existing gates.
