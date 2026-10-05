# Production core on disposable CHR

This fixture exercises `coreactivation.Transition`, the real pinned sing-box
process, finite DNS admission, Linux ingress quarantine and the pinned native
RouterOS observer. It is an isolated acceptance fixture with public disposable
credentials, HTTP REST and private HTTP controls, not a deployment template.

Build separately with `python3 scripts/build-core-gateway-lab.py`. The default
image is `.cache/core-native/coregateway-image.tar` (`mikrocentauri-coregateway:lab`).
Its metadata JSON records the image, binary, Alpine rootfs and sing-box digests.
Use a **new** RouterOS container root directory, never the legacy gateway root.
Set an explicit container environment entry `MC_CORE_LAB=1`: the RouterOS image
importer may not preserve OCI environment defaults. The entrypoint is
`/bin/mc-coregateway`; container interface `mc-probe` must have 172.30.0.2.

All new durable files are below `/data/core-v3`: `namespace/namespace.json`,
`publication/`, `transitions/` and `process/`. The namespace pool is
198.19.0.0/16 and the shared engine cache is
`/data/core-v3/transitions/engine-cache.db`. Legacy 198.18 aliases, files and
selectors are preserved. The fixture reads the owned native observer and RAM
lease to prove DOWN before release; it does not enable the observer or replace
native policy selectors. External DNS is 172.30.0.2:5353 (UDP and TCP), engine DNS
127.0.0.1:5354, private SOCKS 127.0.0.1:2080 and heartbeat 172.30.0.2:9099.

The dedicated IP canary 10.77.0.10:8080 must observe source 10.77.0.10 through the
VLESS server. Its explicit /32 route proves the proxy independently of the active
user domain set, including after all user domains are retired. Selected policy
starts with selected.test, second.test and third.test; source .30 is DIRECT and
source .20 is whole-device PROXY. Resolver 10.77.0.20:53 supplies controlled lab
names. Periodic reconciliation, binding/backend checks and fresh canary requests
gate the heartbeat. A failed proof holds DNS and ingress until recovery.
The pinned RouterOS container uses local-table priority 200, ingress priority
10000 and table 100; ordinary Linux defaults to local priority 0. Native REST
transport warmup is retried only within the quarantine deadline; malformed or
unauthorized readback fails immediately.

The acceptance script can resume a retained namespace with additional Known
names. It never deletes reservations or reassigns an alias; fault scenarios add
or reactivate an existing name. The server fixture supplies six bounded names. Acceptance explicitly sets their
real-DNS TTL to 30 seconds through its disposable `/dns-fixture` control;
the default legacy fixture TTL remains 5 seconds. Native cleanup restores it.

Private fixture HTTP API, bound only to the lab veth:

- `GET /`: 200 only after actual admitted readiness, otherwise 503.
- `GET /status`: 200 diagnostics `{ready, namespace, process, admission}`.
- `POST /control/namespace`: `{revision, active, fault?}` using the current
  revision for compare-and-swap. Active order is retained, maximum 32 names.
- `POST /control/recover`: recover the durable pending or committed intent.
- `POST /control/crash`: kill the owned child and hold until explicit recovery.

`fault` accepts `after-verify` or `before-release`. An atomic private marker is
consumed and directory-synced before exit 77 (fully proved candidate, namespace
still pending) or exit 78 (namespace committed, ingress not released). The marker
is consumed once, so a restart cannot repeatedly trigger the same fault. Child
parent-death handling prevents an orphan sing-box after these abrupt exits.
The readiness listener starts before recovery and answers DOWN throughout it.

Run `go test -race ./lab/coregateway` and `go vet ./lab/coregateway` with the
repository Go runtime for fixture checks. Real CHR acceptance belongs to
`tests/e2e/chr_core.py`; a host compile alone does not prove native operation.
