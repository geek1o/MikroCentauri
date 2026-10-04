# Development

Tools: Go 1.27.1, sing-box 1.14.2, Python >=3.12, optional QEMU. Pins and SHA-256
for Linux/macOS arm64/amd64 are in `toolchain.lock.json`. Nothing installs globally.

```sh
make bootstrap
make check
make prototype
make cross-build
make probe
```

`make test` runs Go race tests, vet and real sing-box check of golden fixtures.
`make smoke` starts two local sing-box processes plus local HTTP/DNS targets, proves
selected-domain VLESS TCP vs nonselected DIRECT and typed DNS behavior, and tests
invalid-candidate preservation. It is not isolated-VM/RouterOS transparent E2E.

CLI `generate` accepts a local milestone config and saves a validated private
candidate. `plan` prints an **offline**, disabled hybrid RouterOS preview against
empty state. No network mutation command is exposed. `ApplyLab` exists solely for
mock/lab testing and lacks production durability/capability/order/verification.

Golden updates require `UPDATE_GOLDEN=1`; review output rather than auto-updating in
CI. Never commit real URI credentials. Lab UUIDs are public disposable fixtures.

The next lab stage is reproducible with `make dataplane-lab`; see `docs/lab.md` for
isolated Ethernet/CHR setup and explicit E2E mode order. `make quic-test` covers the
separate HTTP/3 module. CHR integration tests require a provisioned disposable VM;
they are not silently part of host-only `make check`. Small actual results and
capture hashes are committed under `docs/reports/dataplane-evidence`.
