# ADR-0006: Go core and no early frontend

Status: ACCEPTED.

Use Go 1.27.1 with standard library for the first core/CLI, static linux/amd64 and
linux/arm64 builds. Python is development/lab tooling only. Product orchestration
will depend on a platform adapter; HTTP/RouterOS logic stays inside the RouterOS
package. The declared PlatformAdapter is a future contract, not a completed adapter.

No production Node/Python runtime or frontend before accepted dataplane. Later
static TypeScript UI will use versioned API, not direct RouterOS credentials.
