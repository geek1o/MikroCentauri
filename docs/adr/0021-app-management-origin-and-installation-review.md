# ADR 0021: Explicit App management origin and stopped installation review

Status: accepted for implementation; native installation admission remains open.

An App API binds its private VETH address. RouterOS can expose the management
port at a different host/port. The browser's actual Host/Origin therefore need
not equal the listener. Deriving the accepted origin from the listener prevents
legitimate mapped access; trusting forwarded headers would weaken the boundary.

Use one operator-provided `public_origin`, canonicalized as a credential-free
HTTPS origin. Without it, retain the literal listener origin. The API accepts
only the resulting exact Host and optional exact Origin, together with real TLS
and the actual socket client CIDR. Forwarded headers confer no trust. The TLS
certificate must cover both the listener IP and advertised hostname. Internal
liveness verifies the listener certificate and sends the advertised Host.

Installation review uses a protected local bundle representing remote `/data`.
Read only four bounded RouterOS resource projections. Require a disabled App,
stopped generated container, exact immutable image/config digest, production
entrypoint, static VETH and persistent state mount. Bind the review to protected
inputs, operator connection/CA and exact observed identity for ten minutes.
Reject pending App command overrides even if the stopped container has no cmd.

The operator applies only the exact reviewed container privilege flag under
exclusive administrative control, while the App stays disabled. Verification
rereads identity and inputs; neither command starts the App nor steers traffic.
RouterOS offers no atomic compare-and-set for this manual operation. Kernel/TUN,
installed private bytes, native owner readiness and packets need separate proof.
The review always reports readiness false.
