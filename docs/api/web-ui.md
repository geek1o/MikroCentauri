# Web UI operation

The production Go API serves the embedded interface at `/` on its existing HTTPS
listener. Use its exact configured address and a trusted server certificate;
allow the actual LAN client subnet explicitly. There is no separate public web
server, CORS proxy or Node runtime on RouterOS. Initialize the administrator
password and configure the native owner using the [API guide](README.md) and
[runtime profile](runtime.md). This is the accepted operator profile; installable
RouterOS App onboarding is product Phase 6.

Login creates a 30-minute bearer session held only in memory. Reload requires a
new login; logout invalidates the token. Endpoint URIs, passwords and subscription
URLs are cleared after submission and never persisted in browser storage. The
UI is Russian; theme and IANA time zone preferences persist on the server.

Proxy/group/rule/source/DNS edits save a durable CAS draft. Enabled proxy-rule
domains join the same selected-DNS draft, preserving existing names. Validate
and inspect the plan, then explicitly apply it. Saving never activates traffic.
Stale drafts/plans fail; do not retry an expired plan as if it were a new one.
The result reloads active revision/readiness. The preserved old draft is an audit
record after a successful apply. Source policies affect traffic entering the
prepared engine path; they do not by themselves install whole-device interception.

Subscriptions refresh into private LKG caches. Inspect/select nodes and import
them to a draft before reviewing/applying. A shared interval may be disabled or
set to 1–1,440 minutes. Refresh waits its first interval and never auto-applies
cached nodes. Safe backups omit credentials/provider URLs and require matching
private records already on this installation; the scheduler setting is local.

Setup reads RouterOS version/interfaces, RAM/storage, IPv4 addresses, default
routes, DNS, FastTrack and DHCP devices. It checks FakeIP/address overlap and
uses the normal plan. It does not provision VETH, firewall, routing tables or an
arbitrary topology. Missing adapters and failed reads differ from empty data.
Suffix FakeIP publication remains unavailable without finite name admission;
the UI explains that boundary. Rule overlap analysis is bounded and advisory,
and identifies incomplete analysis rather than claiming every conflict is absent.

Fixed diagnostic buttons use the configured targets. Individual node probes
measure an active enabled node in a private temporary sing-box child; draft-only
nodes need activation first. Measurements include their timestamp/scope and
exclude startup from HTTP latency. Neither a single sample nor general readiness
is continuous per-node health. See [adapter contracts](web-ui-adapters.md).

## Development checks

Bootstrap the pinned Go/sing-box tools and provide Node 22.18+ compatible with
the locked Vite toolchain. Browser acceptance here used Node 24.19.0.

```sh
make webui
make check cross-build
python3 scripts/test-webui.py --install-browsers
```

`make check` runs Go race/vet/integration checks and the reproducible UI asset,
type, unit and size gates. Default browser acceptance runs Chromium and WebKit.
The fixture uses real TLS 1.3, API authentication/durable drafts and pinned
sing-box validation. Its runtime/router/subscription transport are explicitly
simulated; browser success is not another native CHR packet proof.

Firefox remains an optional project:

```sh
python3 scripts/test-webui.py --project firefox
python3 scripts/test-webui.py --all-browsers
```

On the current macOS host, both headless and headed Firefox failed to launch
before opening the application, with sandbox/compositor errors. That result is
recorded as an environment limitation, not a passing browser test. `--node`
selects another Node executable; `--headed` launches a disposable test window.
WebKit screenshot capture injects Playwright's transient `body {}` stylesheet;
the CSP correctly blocks it. The test attributes exactly that capture-only event
while requiring zero application CSP violations and leaving the policy unchanged.

The complete shell/assets/notices are embedded and versioned in
`internal/webui/dist`. `make webui-check` must reproduce them byte-for-byte.
No source maps or arbitrary workspace files are served. `/licenses.txt` contains
the notices for the bundled runtime/helper. The gzip budget is 100,000 bytes.
