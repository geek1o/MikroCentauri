# Bounded DNS publication and retirement

`Config.Selected` names require the existing allocator/publication protocol:
canonical A questions go to the loopback engine and no alias escapes without
an exact verified publication receipt. Selected AAAA receives an empty answer.

`Config.Retired` names require `RealAddress`, a distinct literal real IPv4 DNS
endpoint with a valid port. Their canonical questions go exclusively to that
resolver, bypassing the FakeIP allocator and publisher. All other nonselected
questions use the same real endpoint when configured; historical fixtures with
no retired names and no real endpoint retain their internal forwarding behavior.
Every forwarded answer is checked for FakeIP A records in answer, authority and
additional sections. A leaked alias produces SERVFAIL. Normalized duplicates
and selected/retired overlap are rejected. An all-retired policy is supported.
The real endpoint must implement TCP DNS; there is no UDP exchange fallback.

Configurations are immutable after construction. `Serve(ctx, listen, handler)`
provides stable UDP/TCP listeners for a dispatcher that selects one immutable
Gate per `Handle` call. Existing TCP sessions ask the current dispatcher for each
question. Transport bounds remain 4096 bytes, two-second socket deadlines and
128 concurrent requests. `(*Gate).Serve` preserves the gate's historical bounds.
`Switcher` provides the generation boundary: `Hold()` blocks new requests,
cancels the old lifetime and increments its epoch; `Install(handler)` replaces
an immutable handler while held; `Release()` opens a new lifetime. Every request
links its own context to that lifetime and checks the captured epoch before
returning its answer. This includes nonselected and retired real-DNS requests,
which do not call the publication admission guard. An upstream that ignores
cancellation still cannot return its old result after a revision crosses that
final check. The gateway must additionally revoke the old admission generation
before activation. The check ends at `Handle` return; a subsequent transport
write is not atomic with `Hold`, and completed old responses are allowed.

Tests prove that retirement reaches real DNS without allocator or publication
calls, rejects a synthetic answer, preserves active publication, and changes
policy on an existing TCP session without replacing its listener. Switcher
tests cover old real replies crossing Hold/Install/Release, preservation of
completed replies, held startup, and cancellation of an actual retired TCP DNS
exchange.
