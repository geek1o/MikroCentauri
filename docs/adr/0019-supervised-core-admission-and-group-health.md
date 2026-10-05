# ADR0019: supervised core admission and isolated endpoint health

Status: accepted for the bounded core contract; native platform acceptance pending.

The v2 generator and child supervisor are reusable, while historical FakeIP
admission/activation uses a finite Known/Active namespace. General configuration
apply must preserve old cached aliases and cannot open traffic merely because a
process started. Fallback probes must not temporarily select another endpoint in
the live dataplane.

Generate the private engine allocator for all Known domains. Active aliases
retain terminal selected-domain routes; retired aliases use terminal DIRECT
before sniff. External DNS retirement remains the gate's responsibility.
Regenerate the exact bounded policy for semantic preflight, then check the actual
pinned binary schema independently.

Use a persistent model registry to resolve supervisor candidates and LKG after
restart. The hook adapter owns publication hold, admission revocation, private
cache preflight and fresh alias/backend verification. Supervisor commit precedes
forwarding and DNS release. The initial adapter requires one fixed committed
namespace. It deliberately refuses changes involving a pending namespace or an
uncoordinated second journal; a future transition coordinator must prove both
durable states before release.

Probe enabled endpoints through isolated authenticated loopback sing-box
processes and fresh HTTP(S) canaries. Keep status, body, TLS trust and optional
egress identity checks explicit. Fallback chooses the first freshly healthy
member in configured order. A policy edit stages without apply; a fresh observation
is required before its supervised activation. All failed members stop the child.
A native backend failure closes readiness even when endpoint canaries succeed.

The implemented core contract has unit/composition fault tests and actual
sing-box endpoint/binding tests. These do not establish native RouterOS acceptance
for the new bridge, UDP/QUIC health, arbitrary namespace transactions or cache
repair. No transparent runtime command is exposed before those platform gates.
