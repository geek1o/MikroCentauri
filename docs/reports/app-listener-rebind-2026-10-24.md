# App listener reconciliation after a RouterOS container address change

## Outcome

The physical RouterOS 7.23.8 long-term ARM64 management App (hAP ax^2) was
restarted onto its current App Store image
`ghcr.io/geek1o/mikrocentauri@sha256:2b39463eb1c038c04edf570de05932b30a58813b5dec6e758cc9029498e9b558`.
It now stays running, reports healthy with restart-count zero, and serves the
authenticated HTTPS UI at `https://10.99.0.1:8443/`.

The cause was not the image or the persistent volume: RouterOS had re-created the
App container on the existing state volume with a different private container
IPv4 address, while the protected bootstrap settings and self-signed management
certificate still referenced the previous address. `app-run` correctly treats
existing state as authoritative, so it tried to bind the stale listener and exited
with `HTTPS API bind failed`. The RouterOS App manager retried every few seconds.

## Observed state

- Container `app-mikrocentauri` reported `exited with status 1`; every retry logged
  `MikroCentauri startup failed: HTTPS API bind failed` before exiting.
- Persisted `/data/bootstrap/app.json` listened on the *previous* container address;
  the App environment and the veth interface carried the *current* address.
- The persisted certificate SANs matched the previous container address and the
  router access address, so rewriting only the listener would still have failed the
  certificate/listener/origin check.
- The management forward rule was absent after the firewall rework, and the
  container interface lists referenced the other App only, so the started App would
  still not have been reachable from the management LAN.
- `api/auth.json`, `bootstrap/password`, `bootstrap/model.json` and the rest of the
  protected state were intact; no application configuration data was changed by
  this failure.

## Live repair

The repair was limited to the derived bootstrap inputs; authentication, model,
draft and subscription state were preserved byte-for-byte.

1. A complete local copy of the affected protected files was taken first, and the
   original file hashes were recorded.
2. A bounded temporary entrypoint helper (the accepted pattern for stopped-volume
   work) installed a rewritten `bootstrap/app.json` and a freshly generated
   bootstrap-format ECDSA P-256 management identity. The new certificate covers the
   current container address, the previous listener address (crash safety while the
   update is committed) and the router access address. Files were written as
   regular 0600 files under the existing 0700 directories, with the settings file
   committed last as the marker.
3. The helper verified both staged and installed SHA-256 values, then removed its
   staging directory. No plaintext key, certificate, password or archive was left
   on the router or in Git.
4. The temporary command and entrypoint overrides were unset with a bounded
   RouterOS script so the container again uses the image's own entrypoint and
   healthcheck command. The script was removed immediately.
5. Three scoped firewall rules were added before the existing denies:
   LAN-to-App management HTTPS (management source list, exact container address,
   TCP 8443, destination-NAT state), container-to-router HTTPS REST (exact
   container address, router management address, TCP 443) and container-to-WAN
   egress from the App internal network. The existing management, WAN and
   default-deny policy is otherwise unchanged. No exception was added on WAN
   ingress.

## Verification

- `GET /api/v1/health/live` returns `200 {"live":true}` from the management LAN;
  `/` and the referenced JS asset return 200, and the authenticated login and
  `system` endpoints return 200.
- The certificate actually served by the listener matches the locally recorded new
  certificate, and its SANs cover the listener, the router access address and the
  previous address.
- Container health is `good`, `healthy` is `true`, restart-count remains zero and
  the container has no leftover entrypoint or command override.
- A deliberate container stop recovered without operator action: the App manager
  restarted the container, it reached `healthy` again and liveness stayed 200.
- Protected `api/auth.json`, `bootstrap/password` and `bootstrap/model.json` hashes
  still equal their pre-repair values. The rewritten listener, certificate and key
  match the intended replacement hashes.
- The firewall test counters increased only on the intended scoped rules, and the
  container egress rule is in place for subscription and rule-set work.

## Code fix for the next image

`bootstrapRouterOSApp` now reconciles an App-bootstrapped installation when the
RouterOS App container is re-created with a different private IPv4 address:

- the persisted listener is moved to the current container address, keeping the
  configured port and public origin;
- only bootstrap-owned TLS files (`<data>/bootstrap/`) are rotated; operator TLS
  material causes a clear failure instead of an unannounced rotation;
- the previous listener address stays certified so an interrupted update can still
  serve the old settings until the new settings file is committed, and the
  settings file is written last;
- the operation is idempotent and does nothing without a valid App container
  address, for a locally assigned operator listener address, or for
  operator-provisioned process startup without the App environment;
- authentication, model, draft, subscription and cache state are never touched.

Unit tests cover the address change, certificate names and validity, protected-state
preservation, repeated-start idempotence, inert operation without the App container
environment and refusal to rotate operator TLS material. The package race suite and
`go vet` pass.

The running image is unchanged by this repository commit; its state was repaired by
the live procedure above. Deploying a later image removes the manual step for the
same address-change recurrence.

## Limits

This record covers management-plane startup and reachability on the observed ARM64
device only. It does not qualify native packet steering, proxy failure recovery,
IPv6 or reboot persistence of the complete product, and it does not change the
RouterOS App manifest, which continues to pin the container address it assigns.
