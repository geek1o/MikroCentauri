# ADR-0007: Security boundaries

Status: ACCEPTED principles. Current implementation is documented in the
product Phase 4 acceptance and ADR-0020; the prototype boundaries below record
the initial design.

No external app API in the prototype. CLI operates on local private config; RouterOS
runtime client requires HTTPS verified by configured trust. Lab-only constructor
allows HTTP for in-memory tests/disposable CHR. Redirects are refused. Parsing and
process invocation use structured values/argv, no shell interpolation. Unknown URI
options fail instead of being silently downgraded. Generated configs include secrets
and are written 0600, never printed as a default artifact.

Future controller uses separate least-privilege RouterOS account; coarse RouterOS
permissions cannot enforce ownership tags. Restrict network access. Subscriptions
require bounded downloads, DNS-rebinding-aware SSRF/redirect checks and LKG semantics
before implementation. Authenticated HTTPS, origin/socket guards, login rate limits,
credential-free safe backups and bounded diagnostics are implemented in product
Phases 4–5. A full encrypted credential backup remains outside that scope.
FakeIP AAAA suppression does not claim IPv6 leak proof.

Capability testing compares normal versus privileged, without automatically opting
into privileged. Lab probe has no router credentials and is not a product readiness
endpoint. The image must not bake secrets into its configuration.
