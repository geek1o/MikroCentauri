# Security

MikroCentauri has no independent security audit or security response SLA. Use it
on a reviewed private management network; never expose its management listener
or RouterOS REST directly to the public Internet.

The production API uses verified HTTPS, authentication, configured Host/Origin
and allowed socket peers. Sessions expire; restarts invalidate bearer sessions.
Private bootstrap/state paths require protected permissions and reject unsafe
paths. Diagnostics and ordinary backups deliberately omit secret fields.

Provide RouterOS HTTPS trust and a reviewed account/network boundary. Ownership
comments restrict application behavior but are not an authorization barrier
against another RouterOS administrator. Container privilege is reviewed while
stopped; the prepared Linux ingress and TUN profile are operator responsibilities.

Subscription/rule-set downloads are bounded and reject unapproved local/private
addresses. HTTPS is required in production import flows. Operator-granted network
exceptions and third-party content still require their own trust review.

Failure withdrawal deliberately permits reviewed DIRECT forwarding. IPv6 literal
addresses and alternate DNS can bypass selective IPv4 policy. DNS proof expiry
can return SERVFAIL while runtime readiness remains true. Do not treat this
application as a VPN kill switch, anonymity service or traffic confidentiality
guarantee; read [limitations](limitations.md).

When reporting a vulnerability, share a minimal redacted reproducer. Do not post
credentials, subscription URLs, TLS keys, full backups or private captures in a
public issue. Contact the repository owner through an available private channel
before publicly disclosing secret-bearing or exploitable material.
