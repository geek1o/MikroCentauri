# Real DNS publication leases

This package is a bounded DNS stub resolver. It sends one recursive IN A query
over a fresh TCP connection to a configured literal IP:port. It checks transaction
ID, question, response flags, framing and compressed names. Responses are limited
to 4096 bytes and 256 records. Context cancellation closes the connection.

Only the question owner's answer A records, or the terminal answer A RRset reached
through at most eight answer CNAME links, supply addresses. Authority and additional
records are parsed for structural validity but never supply addresses or TTLs.
Unrelated answer records cannot influence the result. CNAME loops, inconsistent
targets, CNAME and A at the same owner, malformed names, unsafe terminal addresses,
truncated or unsuccessful responses, zero TTL and the reserved high TTL bit fail
closed. TTL is the minimum of all relevant CNAME and A records; duplicate A records
are deduplicated and addresses sorted. Private IPv4 addresses are deliberately
allowed for the isolated lab.

A response containing only CNAME links is rejected; this implementation does not
issue follow-up queries. It does not perform iterative authoritative resolution,
DNSSEC validation, encrypted transport, negative caching or retries. Upstream DNS
must be trusted and return the complete positive chain. TCP alone does not
authenticate the upstream. The positive TTL is obtained from the DNS wire response,
not invented by an OS lookup wrapper. Lease storage and router updates belong to
the publisher, not this package.

Wire format, compression, resource record TTL and TCP framing follow
[RFC 1035](https://www.rfc-editor.org/rfc/rfc1035); CNAME alias handling is based on
[RFC 1034](https://www.rfc-editor.org/rfc/rfc1034). TTL range and minimum RRset TTL
follow [RFC 2181](https://www.rfc-editor.org/rfc/rfc2181), sections 8 and 5.2:
a high-bit TTL is unusable as a positive lease. The bounded chain, zero TTL refusal
and rejection of partial answers are local publication safety policies.
