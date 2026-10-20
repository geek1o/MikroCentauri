# Subscription download diagnostics

Subscription downloads currently use the container's **direct** network path,
with DNS-pinned destinations, verified TLS and no environment proxy. A successful
proxy-node check does not change that path. A subscription URL working on a
workstation with a system tunnel does not establish direct reachability from the
container. Downloading through a chosen draft proxy is not implemented yet.

The API's subscription views and the subscription-status CLI expose an optional,
fixed `failure_code` when a download fails:

| Code | Observed stage |
| --- | --- |
| `invalid_url` | URL rejected before download |
| `dns_failed` | Destination lookup failed |
| `destination_refused` | A resolved address violates destination policy |
| `connect_failed` | No validated destination accepted the TCP connection |
| `timeout` | The bounded download timed out |
| `tls_failed` | Certificate verification failed |
| `redirect_refused` | Redirect count, URL policy or HTTPS downgrade refused |
| `http_error` | HTTP status differs from 200 |
| `body_invalid` | Response unreadable or exceeds its size bound |
| `request_failed` | Another transport failure |

These codes never contain a provider URL, query token, DNS answer, certificate
message or raw response. The frontend explains the failure and distinguishes an
empty cache from a retained last-known-good list. Unknown codes use a generic
message. Existing state without a code remains readable.

A failed refresh retains prior nodes and the last successful timestamp. A later
successful refresh clears the failure. Parser/filter failures remain distinct
from download failures and use the existing validation message. No failure
disables TLS or opens access to private/service destinations. Inspect the source
path and container connectivity before concluding that the subscription format
or its proxy servers are defective.
