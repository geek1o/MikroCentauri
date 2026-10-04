# Security status

Prototype: private file-based config; strict VLESS/TCP options; no shell expansion;
HTTPS REST constructor, bounded responses, no redirects, redacted errors; exact owned
object matching; disabled plan; no externally listening application API.

Local lab probe listens internally without auth and must run only in isolated CHR.
Generated sing-box listeners currently bind 0.0.0.0 for the lab container; never put
that candidate directly on a LAN/WAN without scoped firewall. The mixed listener
is for prototype/Socksify comparison and has no authentication configuration yet.

Not implemented: product auth/CSRF/rate limits, subscription SSRF defenses, encrypted
backup, safe diagnostics export, durable router journaling, full IPv6 policy and native
watchdog. These are tracked requirements, not claims that the system is hardened.
