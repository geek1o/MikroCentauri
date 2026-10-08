# Cloud-independent management bootstrap — 2026-10-08

RouterOS documents that App use-https depends on Cloud availability, while x86
has no Cloud service. This is independent of the application's own TLS listener.
The previous automatic bootstrap required optional web access placeholders even
though the App manifest maps 8443 as api-secure rather than web.

The production manifest now explicitly opts into direct TLS with a declared
external TCP port. Bootstrap resolves a private access IP or uses its private
container IP, independently of the optional Cloud accessPort value. Public IPs
remain rejected. Existing protected installations win before environment parsing.
The launcher prints sanitized startup failures to stdout as well as stderr so
RouterOS container logs expose the failure reason. Successful startup prints the
public management origin, never credentials.

Host regression cases cover missing/unresolved placeholders, Cloud hostnames,
private access IPs, explicit port remapping, unsafe inputs and restart preservation.
A subprocess uses generated bootstrap TLS/authentication and the production API
serve argv, verifying certificate-checked HTTPS liveness on two starts. Only the
listener is relocated for the host test; it is not native RouterOS acceptance.
The setup guide describes use-https=no, HTTPS access and manifest/image updates
without cleaning the persistent volume.

The complete command-package race suite and vet passed. The generated TLS API
became live twice without Cloud accessPort, retaining authentication. Standard
older manifests also select direct port 8443 without requiring new environment
variables; custom mappings remain explicit. Native deployment of this precise
revision on the reporting router remains unverified until that router is updated.

## Published build

Main commit: 2806a5a405b94fd89b9e3a1e7a32ad2be06b6150.
Build and publish succeeded:
https://github.com/geek1o/MikroCentauri/actions/runs/37777037960

Release:
https://github.com/geek1o/MikroCentauri/releases/tag/build-2806a5a405b94fd89b9e3a1e7a32ad2be06b6150

The live App Store manifest and catalog matched the new immutable image:
ghcr.io/geek1o/mikrocentauri@sha256:4bc02b49bef820eb687778d219718aba95f3ab8d1f0d456c5d7d5ee0b8c77203

The receipt confirms anonymous image/source access. The retrieved manifest
includes direct HTTPS mode and explicit mapped port 8443. The release contains
both architecture import archives, OCI transport, corresponding sources,
checksums, SBOM and provenance. Startup failure visibility was additionally
checked against the built CLI: stdout/stderr include the sanitized reason and
the process retains exit status 1.
