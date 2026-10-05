# ADR 0017: HTTPS discovery and disabled-object staging

Status: accepted for the verified CHR laboratory profile.

## Decision

Expose certificate-verified HTTPS discovery and a staged controller through the
CLI before enabling general traffic mutation. Keep capability GET endpoints
separate from the existing five-resource mutation allowlist. Discovery reports
facts; only the pinned CHR x86_64 7.24.5 profile admits staging.

Credentials live in private files. Artifacts bind reviewed plans and complete
desired state to a target and instance. Exact apply rejects stale preconditions;
fresh reconcile performs recovery, discovery, planning and application under one
exclusive durable transaction lock. Before, after and realized objects must all
be explicitly disabled. Recover ambiguous writes through native readback.

## Consequences

Management-plane operations can be exercised on native CHR without activating
traffic. Presence of packages or endpoints does not establish runtime readiness.
Production enabled-rule placement, rollback and watchdog provisioning require
separate implementation and proof. Ordered firewall deletion remains gated until
placement is represented in recovery state. See the
[acceptance report](../reports/product-phase-2-staged-controller.md).
