# ADR 0016: policy activation and recovery coordinator

Status: accepted for reusable core and opt-in disposable gateway integration;
production controller and management remain open.

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

The coordinator now drives the opt-in namespace gateway's startup and HTTP apply.
The lab adapter separates engine admission from TUN/DNS Release and uses the same
lifecycle mutex as health/start/stop. `/control/start` in namespace mode deliberately
replays recovery even for a healthy engine; legacy non-namespace mode still rejects
an already running engine without stopping it. Startup invokes Recover once. After
a failed attempt, a repaired runtime requires another start request or process
restart; there is no background recovery loop.

Native proof covers pending recovery, death after Commit before Release, damaged
mapping refusal and native control-transport outage. The fixed native-state read
retries transport failure only under its caller deadline; state-changing requests
are not blindly retried. Test-only crash markers require MC_ACTIVATION_FAULTS=1;
the image builder does not enable it by default. See the engineering milestone8
report for pinned proof and limitations. The management API remains lab-only and
unauthenticated; the production CLI is still offline. Authentication/TLS,
supervision, last-known-good handling, production deployment and hardware coverage
remain open.
