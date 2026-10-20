# Subscription download diagnostics

Each subscription has an explicit download path: **direct** by default, or one
enabled proxy endpoint from the current draft (otherwise the active model).
Select the path when adding the source, or change it under the existing source's
"Download through" selector and save. Changing the path preserves the private URL;
there is no need to paste the subscription secret again. Both manual refresh and
the saved unattended schedule use this selection. A successful node check alone
does not change a subscription's path.

A proxy download starts a bounded, isolated sing-box child with one authenticated
loopback mixed listener and the selected endpoint as final outbound. It creates
no TUN, changes no live selector, applies no draft and does not need RouterOS
write access or an admitted native runtime. Endpoint and DNS bootstrap settings
are snapshotted before starting the child. The child is stopped and reaped and its
temporary private configuration removed when the operation completes or fails.

The downloader still resolves and validates all addresses for each destination
and redirect before dialing. An authenticated loopback HTTP CONNECT tunnel uses
the validated literal IP; the HTTP Host and TLS certificate identity retain the
original source hostname. Certificate checks, response bounds, Referer removal,
redirect limits and HTTPS downgrade refusal are unchanged. Environment proxies
are not inherited. See [HTTP CONNECT semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6).

There is **no direct fallback** when a proxy is selected. A missing, disabled or
unusable selected endpoint fails the refresh and preserves last-known-good nodes.
WireGuard needs a dedicated probe peer and is not offered for this operation.
The source download is not an endpoint health observation and never establishes
native routing readiness. Existing imported draft nodes remain usable as the
bootstrap source even before the dataplane is applied. If no suitable node is
available yet, import one proxy URI first or use direct access.

The authenticated `POST /api/v1/subscriptions/transport` accepts `id` and
`proxy_node` (a canonical endpoint ID, or the empty string for direct access).
`proxy_node` is also accepted on source creation, returned in source views and
retained in safe backup metadata. Arbitrary proxy URLs are not accepted.

The API's subscription views and the subscription-status CLI expose an optional,
fixed `failure_code` when a download fails:

| Code | Observed stage |
| --- | --- |
| `proxy_unavailable` | Selected endpoint/isolated adapter absent, disabled or failed before download |
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
