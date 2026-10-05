# Endpoint health and ordered fallback

`NewProber` checks the pinned sing-box executable and runs one disposable
SOCKS/HTTP profile per endpoint. The profile has only a randomly allocated
loopback mixed listener with a random authentication secret. It has no TUN,
Clash API, cache file or active-process selector operations. Configurations are
private (0700 directory, 0600 files), and process groups and temporary files are
removed after every observation. Linux children also have a parent-death signal.

A successful observation requires an HTTP(S) canary response through that proxy:
exact successful status, bounded complete body and, when configured, an exact
plain-text egress IP. HTTPS uses normal certificate validation; a private CA pool
can be supplied without disabling verification. Redirects are refused and
HTTP_PROXY/HTTPS_PROXY environment variables cannot alter the probe path.
Latency measures the canary round trip, excluding process startup. Process
existence or an open local listener is never a healthy result. A successful TCP
canary does not establish UDP payload forwarding or transparent RouterOS routing.

`New` creates a fallback controller with mandatory `Probe`, `ApplyModel` and
`Quarantine` callbacks. `Tick` probes group members and uses
`coreconfig.FallbackSelection` to choose the first freshly healthy endpoint in
group order. It does not rank latency. `ApplyModel` must generate and apply the
replacement through the supervisor and the application's traffic activation
barriers. This package does not provide a substitute for those barriers.

The controller preserves selection after failed apply. No healthy member closes
gates through the mandatory quarantine callback. Recovery re-applies the chosen
model before it can report ready. `UpdateModel` cancels stale observations and quarantines before staging the
replacement policy in memory. It never calls apply or changes the recorded
active selection. A fresh tick must prove the new policy before apply.
All callbacks must honor context deadlines. Generation checks prevent canceled
or superseded observations from changing a later selection. Calls are serialized
at apply; only one tick may run concurrently per controller.

The current controller accepts fallback groups containing enabled endpoint IDs.
Nested groups and `direct` members require a separate health contract and are
rejected. Each fallback group is limited to 32 members and every tick has a
bounded overall deadline. Health observations are memory state; durable configuration ownership
and last-known-good process recovery belong to the supervisor.

Run the genuine local Shadowsocks health, failure-switch and recovery proof with
`SING_BOX_BINARY=/absolute/path/to/sing-box go test -race ./internal/grouphealth`.
The fixtures also prove wrong credentials cannot pass via a direct bypass,
HTTPS trust is checked, unhealthy responses/redirects/oversized bodies fail and
all failed endpoints quarantine the current selection.

`Close` cancels and supersedes ticks, serializes against apply and quarantines.
Further ticks, model updates and periodic runs are refused after close.
