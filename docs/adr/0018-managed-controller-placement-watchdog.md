# ADR 0018: managed controller, placement and native supervision

Status: accepted for product Phase 2 on CHR 7.24.5 x86_64.

Keep the disabled staging constructor and expose a separate HTTPS managed
constructor with active owned state, Verify, Rollback and CleanupManaged. Persist
intent before writes, read back outcomes, attempt bounded compensation on failure
and refuse conflicts rather than replacing external edits. Exact repeated committed
Apply is a verified no-op retaining the previous rollback journal.

Represent new firewall placement as an explicit static native anchor. Refuse a
moved existing rule without a reviewed replacement. Before deletion, journal the
ordered table IDs/keys/configuration digests; compensate only if surviving order
and configuration still match. Restore via place-before and verify again.

Allow native executable hooks only when regenerated from their bounded structured
specification. Extend managed resources narrowly with the generated startup
scheduler. Netwatch probes its dedicated readiness endpoint, checks its own tuple
and exact target configuration, disables immediately on failure and enables after
three successful probes. Debounce lives in an exact finite dynamic RAM address-list
entry; static/foreign/duplicate state denies readiness. Generated scripts preserve
foreign counter blockers and avoid repeated writes to already-correct switches.

The observer owns target disabled switches while active. Quiesce it before
configuration changes. The process lock cannot serialize external RouterOS
administrators or native scripts. The startup scheduler is defense in depth, not
proof before the first LAN packet. FakeIP still requires the separately proved
volatile lease and cached-alias fallback. Core readiness/supervision, whole-app LKG,
installation and broad hardening remain later-phase work.

This decision supersedes controller capability/placement/native-installation open
items in ADRs 0004 and 0017 for this profile. See the
[completion report](../reports/product-phase-2-controller-completion.md).
