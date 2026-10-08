# Traffic sections

Sections combine a traffic scope with an outbound route. They are stored in the
core model, survive restarts and safe backup/restore, and participate in the
normal validate, review, apply and rollback workflow. Saving a section never
switches the active routing configuration.

The Sections page offers community domain and IPv4/CDN lists, custom domain
suffixes, destination CIDRs, and optional source-device CIDRs. A section can
use a proxy endpoint, a manual or automatic selector, an existing WireGuard
endpoint, or DIRECT for an exception. A new selector can be created while
saving the section. The live selector panel uses the authenticated local
sing-box controller; its HTTPS delay checks are actual engine requests.
Switching a shared selector affects every section using that selector.

## Matching and precedence

Enabled sections run in their displayed order. Domain suffixes and destination
CIDRs compile into separate alternative rules. A source-device scope qualifies
both alternatives. An empty target is rejected, rather than interpreted as
routing all traffic. The explicit all-traffic option requires a nonempty device
scope and cannot be combined with destination targets.

Section-generated rules occupy priorities -1000 through -937. Existing global
source-direct/source-proxy policies still run first; advanced rules with lower
numeric priorities can also precede sections. The UI shows these conditions.
Overlap notices identify shared domain suffixes or intersecting IPv4 ranges
with intersecting device scopes; they are an explanation of possible precedence,
not a complete packet-path simulator. Advanced service and rule-set policies
remain available in the Rules page. Existing standalone list rules are retained.

Disabling preserves a section's configuration and snapshots. Copying prepares
an editable copy with a new identity. Moving, disabling, deleting and refreshing
all produce a new draft and invalidate a previously prepared apply plan.
Deleting a section does not delete a selector that may be shared elsewhere.
Unused selectors can be removed from the Selectors page after their references
are removed.

## List ownership

Each section stores reviewed list contents and their source ID, name and hash.
Source URLs stay in the private traffic-list cache and are excluded from API
policy projections and safe backups. New section references use a cached list
when available, or download a catalog source. Custom URL lists are first added
through the Lists page and then appear in the section picker. After restoring
a safe backup on another installation, cached snapshot contents can still
route; refreshing a custom source requires registering its private URL there.

Refreshing one section downloads its chosen sources and changes only its
snapshots. Another section using the same source ID retains its previous
reviewed snapshot. Invalid downloads leave the draft and last good source
intact. Downloads release the API mutation lock; a revision check prevents them
from overwriting edits or an apply that happened while a source was downloading.

Each section permits up to 32 list references and 4096 input records in total;
there are at most 64 sections. Bounds are enforced without silent truncation.
Imported DNS names are a finite set of literal roots. Previously admitted names
are retained on section removal, because other policies and immutable aliases
may still depend on them; their route is reevaluated from the remaining rules.

## Runtime boundaries

The domain-suffix policy can classify traffic already entering sing-box. It does
not authorize an unbounded native wildcard FakeIP allocator. The existing exact
DNS admission boundary still applies. IPv4/CDN rules do not, by themselves,
prove RouterOS interception of traffic to those IP ranges. Native RouterOS/CHR
acceptance is still required. The local preview uses a real SOCKS engine and
simulated RouterOS activation, without changing the host's routes.

The workflow was informed by the public
[Podkop sections documentation](https://podkop.net/docs/sections/); the controller,
model, compiler and UI implementation are specific to MikroCentauri.
