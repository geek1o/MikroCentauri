# Check draft proxy nodes without activating routing

`mc-node-check` is an operator diagnostic tool. It reads an existing private API
draft and checks each enabled proxy through a separate, checked sing-box child.
It does not connect to RouterOS, apply the draft, create a TUN device, or share
an engine cache with the running application. Its report always has
`routing_ready: false`.

Build for the container's architecture, using the project's pinned Go toolchain:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
  -o mc-node-check ./cmd/mc-node-check
```

Transfer the binary through a trusted operator channel and verify its SHA256
before executing it. Keep the executable and temporary state in a dedicated
private directory. The API draft must be an absolute, regular mode-0600 file
under a mode-0700 directory, without symlink components. The tool accepts up to
128 proxy endpoints. WireGuard requires a separate probe peer and is deliberately
refused by this tool.

```sh
mc-node-check -draft /data/api/draft.json \
  -state /data/diagnostic/node-checks \
  -sing-box /usr/bin/sing-box -concurrency 2 -timeout 10s
```

The default test is a fresh HTTPS request expecting HTTP 204 from
`https://www.gstatic.com/generate_204`. Output contains canonical IDs, protocols,
success/failure, timestamps and latency. Latency excludes child startup. Optional
failure details use a fixed vocabulary; raw child logs, credentials, source URLs
and endpoint names are never emitted. Each child is stopped and reaped before
its temporary configuration is deleted. Disabled nodes are not checked.

Use `-node <canonical-id>` to check exactly one endpoint from the draft. This is
also suitable for execution channels that terminate background descendants when
the operator shell returns. Keep the command in the foreground and bound each
execution to one node; `nohup` is insufficient on the observed RouterOS shell.

## Observe egress without a private VPS

A verified HTTPS public trace can provide the observed peer IP. Cloudflare
[documents its managed `/cdn-cgi/` diagnostic endpoints](https://developers.cloudflare.com/fundamentals/reference/cdn-cgi-endpoint/).
Availability and the direct/proxy paths must still be tested on the actual
network. A public service may be unreachable or may change its response.

```sh
mc-node-check -direct-only \
  -url https://1.1.1.1/cdn-cgi/trace -status 200 \
  -response-format cloudflare_trace -timeout 8s

mc-node-check -draft /data/api/draft.json \
  -state /data/diagnostic/node-checks -node <canonical-id> \
  -url https://1.1.1.1/cdn-cgi/trace -status 200 \
  -response-format cloudflare_trace -timeout 8s
```

Direct observation disables proxy-environment inheritance. Proxy observation
uses the selected endpoint alone, without a DIRECT fallback. Both verify TLS,
refuse redirects, bound the response, and reject ambiguous/invalid peer fields.
A changed or missing IP response is a failure, not a latency measurement.

An operator native profile may select `canary_format: "cloudflare_trace"` and the
reviewed literal-IP HTTPS URL. The expected proxy egress IP remains mandatory;
a successful DIRECT response cannot satisfy a different expected proxy IP.
The legacy controlled JSON response (`{"remote_ip":"..."}`) remains the default.
The native platform qualification and profile-provisioning gates are unchanged.
A probe report does not authorize traffic steering or qualify ARM64 RouterOS.
