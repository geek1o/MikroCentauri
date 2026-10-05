# ADR 0016: policy activation and recovery coordinator

Status: accepted for the reusable core; runtime adapter and native integration open.

The namespace journal records intent and immutable name reservations, but cannot
prove that a running engine or RouterOS mapping belongs to that intent. The
Phase-7 HTTP handler embeds these transitions in a lab-specific process manager.

`internal/activation.Controller` coordinates a single namespace writer and a
runtime adapter. Apply validates revision, capacity, names and current runtime
configuration before interrupting service. It then executes:

1. Quarantine DNS/admission, gracefully stop the engine, confirm native lease absent.
2. Prepare durable namespace intent.
3. Stage the pending generation with DNS still held.
4. Verify every reserved alias and its native mapping.
5. Commit the namespace revision durably.
6. Release the verified generation through TUN/DNS readiness.

Recover always quarantines first. Pending intent is replayed forward without
aborting reservations. If intent is already committed, Stage and Verify still run:
death between Commit and Release cannot be distinguished from a normal startup
using the namespace journal alone. Disk state never suffices to open DNS.

Every failure after quarantine starts attempts quarantine again with a fresh
10-second context independent of request cancellation. Cleanup failure is joined
with the original error and must be surfaced by the supervisor. A timeout is only
effective when the adapter honors context; no claim of forcibly terminating a
hung callback is made. No background retries or readiness from a previous epoch.
The adapter must provide repeatable operations and check exact resource ownership.
It must accept only committed or pending configurations when staging, use the
stock engine allocator, reject old alias drift before allocating new names, and
prove native mappings before returning Verify success. Runtime hooks receive
copies of policy lists. There is no automatic rollback or alias reclamation.

Calls through one Controller are serialized; namespace.Store supplies its
existing exclusive process lock and durable compare-and-swap. All other runtime
lifecycle operations must share this serialization boundary. Direct Store writes
or additional Controller instances are outside this contract.

The coordinator is deliberately not connected to the Phase-7 unauthenticated
lab endpoint or the production CLI yet. Changing native startup behavior requires
a dedicated adapter and CHR crash replay. Authentication/TLS, supervision,
last-known-good handling, production deployment and hardware coverage remain open.
