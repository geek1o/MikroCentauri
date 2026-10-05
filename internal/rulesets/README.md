# Verified local rule-set artifacts

The manager accepts modern sing-box source JSON (versions 1–5) and SRS binary
input supported by pinned sing-box 1.14.2. It validates a bounded flat headless
subset: exact domain, suffix, destination/source CIDR, ports and TCP/UDP network.
Unknown predicates, legacy GeoIP/GeoSite, regex, unconditional rules, malformed
lists and excessive sizes are rejected. Source files normalize to version 5.
SRS wire version can be lower because the pinned compiler chooses the minimum
needed version; the binary header is checked independently of source version.
Binary imports are expansion-bounded, decompiled with the actual pinned binary,
validated against the same subset, then recompiled. Process timeouts are bounded.

`New(directory, binary, policy)` requires a private directory without symlink
ancestors. `Import` supports local source/binary data; `Refresh` downloads a spec's
URL; `Load` returns the verified LKG artifact. Artifact filenames are immutable
SHA-256 identities with `.srs` suffix, private 0600 mode, and hash validation.
Each ID's private manifest changes only after real binary compile and actual
engine config loading checks succeed. Invalid candidates leave the existing
manifest untouched. An uncertain durable write poisons further imports until
the manager is reopened. File locks serialize independent managers.

Remote downloads require HTTPS and verified TLS. Environment proxies are
disabled. Every DNS result must pass the public-address policy before dial uses
that exact address; redirects repeat validation and cannot downgrade TLS.
Bodies and headers are bounded. Explicit trusted policies can admit an isolated
lab CIDR and certificate authority; application models cannot set that policy.
Download errors omit URLs and response bodies.

Generation uses local binary rule-set references only. The engine never fetches
remote sets. Callers resolve application IDs using this manager; serialized
artifact handles are trusted controller state, not user-supplied paths. Artifact
hashes prove integrity, not the provenance of arbitrary caller-created handles.
The runtime bridge must apply changed resolved artifacts through its candidate,
validation and activation transaction. It must not replace an engine file in place.

Official sources: [rule-set configuration](https://sing-box.sagernet.org/configuration/rule-set/),
[source version and compile format](https://sing-box.sagernet.org/configuration/rule-set/source-format/),
and [pinned SRS reader/writer](https://github.com/SagerNet/sing-box/blob/v1.14.2/common/srs/binary.go).
Tests validate HTTPS restrictions, binary/source imports, invalid candidate LKG
preservation, hash tampering, and actual rules routing using the pinned binary.
