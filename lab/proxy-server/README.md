# Local proxy target

`tests/integration/smoke.py` starts a local sing-box VLESS server with a disposable
fixture UUID, local DNS and HTTP target. No user VLESS credentials are required.
This is a process-level smoke; isolation into a separate lab VM/container and a
separate egress identity are required for CHR E2E and are not implemented yet.
No TLS-none configuration from this test is a production deployment recommendation.
