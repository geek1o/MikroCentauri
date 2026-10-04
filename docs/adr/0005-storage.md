# ADR-0005: Initial storage

Status: ACCEPTED for CLI prototype; application LKG lifecycle deferred.

Start with versioned JSON files to keep the dependency/runtime footprint small.
Write private candidate, validate, write temp with mode 0600, fsync, rename, fsync
parent directory. The generator never replaces a validated output on input/check
failure. Application config itself contains secrets and is not a safe-export format.

Full product requires separate draft/active/LKG generations, migrations, locked
writers, backups with redaction, crash recovery and router apply journals. Revisit
SQLite when history/concurrent operations justify it. A private sing-box cache DB
belongs in the persistent data volume. Router ownership remains rediscoverable even
if local metadata is lost; instance identity recovery must never adopt another install.
