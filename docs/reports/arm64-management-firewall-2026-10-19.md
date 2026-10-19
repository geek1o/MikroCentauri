# ARM64 management access through a default-deny firewall

The router reports RouterOS 7.23.8 long-term, arm64 and board hAP ax^2.
The deployed image index is
sha256:4bc02b49bef820eb687778d219718aba95f3ab8d1f0d456c5d7d5ee0b8c77203.
The App was running, the container's certificate-checked internal healthcheck was
good, and restart-count was zero. RouterOS had installed the declared 8443 TCP
mapping, but access through the router's management address timed out.

## Causal evidence

A bounded connection attempt increased both the App destination-NAT counter and
the final forward-drop counter by exactly two packets. No applicable forward allow
covered management LAN to the App's internal bridge. The fault was firewall
admission after destination NAT, not bootstrap or process startup.

After explicit operator approval, one static forward accept was inserted before
the existing deny. It is bounded by the management LAN interface, existing
management source address-list, internal App bridge, exact container IPv4,
TCP 8443, new connections and destination-NAT state. No other filter definition
changed; an exact baseline comparison excluded only packet/byte counters.
No container restart, routing, DNS, proxy configuration or WAN exposure change
was needed. Site addresses, credentials and private raw evidence are omitted.

## Verification

- HTTPS root and `/api/v1/health/live` returned 200; liveness was true.
- The actual JS and CSS assets returned 200 with appropriate content types.
- TLS 1.3 certificate and access-IP identity verified against the public certificate
  retrieved through the independent authenticated RouterOS file interface.
- Container health remained good and restart-count remained zero.
- The scoped allow counted the test connections; existing filter definitions
  matched the saved baseline exactly.

RouterOS's built-in fetch failed TLS negotiation with this TLS-1.3-only listener.
That probe failure does not establish an application outage: the independent
certificate-verified client succeeded after firewall admission.

This establishes management-plane operation on the observed ARM64/7.23.8 device.
It does not qualify native selective-routing packets, forwarding privileges,
alpha/beta releases, image upgrades or reboot persistence of the complete product.
