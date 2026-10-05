# RouterOS controller CLI

Use a dedicated RouterOS account, certificate-verified HTTPS and a management
firewall restriction. The accepted write baseline is CHR x86_64 7.24.5. Other
profiles can be inspected but are not admitted for mutation. The native account
proof uses read/write/test/api/rest-api; these permissions are coarse and must
not be treated as per-object authorization. Connection JSON follows the
[staging guide](../README.md#https-staging-cli).

## Complete managed desired state

Save this structure in a regular 0600 file. `objects` is the complete managed set
for this instance; an empty array requests removal of that owned set. Native
resource names and writable fields are bounded by the controller schema.

```json
{
  "instance": "example",
  "objects": [
    {
      "path": "ip/firewall/filter",
      "place_before": "*YOUR_STATIC_ANCHOR_ID",
      "fields": {
        "comment": "mikrocentauri:example:filter:rule",
        "disabled": "true",
        "chain": "forward",
        "action": "accept",
        "src-address": "203.0.113.0/24"
      }
    }
  ]
}
```

The anchor is optional and must be an actual static rule in the same collection.
Review rule semantics and their position before requesting an active state. A
moved existing rule requires an explicit replacement plan. No user rule is moved.

```sh
mikrocentauri router-managed-plan -router-config /absolute/router.json -desired /absolute/desired.json -out /absolute/plan.json
mikrocentauri router-apply -router-config /absolute/router.json -plan /absolute/plan.json -journal /absolute/journal
mikrocentauri router-verify -router-config /absolute/router.json -plan /absolute/plan.json -journal /absolute/journal
mikrocentauri router-managed-reconcile -router-config /absolute/router.json -plan /absolute/plan.json -journal /absolute/journal
mikrocentauri router-rollback -router-config /absolute/router.json -journal /absolute/journal
mikrocentauri router-managed-recover -router-config /absolute/router.json -journal /absolute/journal
mikrocentauri router-cleanup -router-config /absolute/router.json -instance example -journal /absolute/journal
```

Exact apply uses the reviewed plan and rejects stale preconditions. Repeating the
same committed plan is a verified no-op. Reconcile uses the complete desired set,
recovers interrupted work and creates a fresh plan under the controller lock.
Rollback compensates the last committed transaction too; recover compensates only
pending work. Failed managed writes attempt bounded compensation, retaining
unresolved journals. Cleanup uses the same ownership/placement checks.

## Generated native watchdog

A private watchdog specification contains `instance`, unicast IPv4 `host`, `port`,
`interval` and `timeout` in nanoseconds, `success_threshold` from 2 to 10, and
`targets`: 1 to 16 exact owned route/NAT/mangle objects. Start with all targets disabled.
The endpoint must represent full configuration/engine/DNS/dataplane readiness; it
uses a dedicated root HTTP port. The native test uses interval 2000000000,
timeout 1000000000 and threshold 3.

```sh
mikrocentauri router-watchdog-plan -router-config /absolute/router.json -watchdog-config /absolute/watchdog.json -out /absolute/watchdog-plan.json
mikrocentauri router-apply -router-config /absolute/router.json -plan /absolute/watchdog-plan.json -journal /absolute/journal
```

This stages targets, observer and startup guard. To activate supervision, prepare
a complete desired file from the artifact's `desired` array, retain disabled
targets, and set only the generated Netwatch and scheduler `disabled` switches to
`false`. Produce a fresh managed plan, review and apply it. The native observer
owns target enabled/disabled switches thereafter. Stop the observer and wait for
its in-flight probe before editing targets or cleaning up. Raw executable hooks
are refused; preserve the generated specification and fields.

The startup guard is defense in depth. FakeIP forwarding also needs the proven
RAM readiness lease and durable per-alias cached DIRECT fallback. Neither the
CLI nor a plain HTTP200 installs or proves those core runtime prerequisites.
See [acceptance and phase boundaries](reports/product-phase-2-controller-completion.md).
