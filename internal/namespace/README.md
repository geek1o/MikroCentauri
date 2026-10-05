# Durable finite namespace

`Store` keeps an ordered `Known` history and an `Active` subset. `Known` includes
retired and aborted additions forever: a later policy change cannot recycle an
engine alias position. Reactivation retains the original position. Retirement
only changes `Active`, which may become empty. `Known` must remain nonempty.
Capacity defaults to 32 and is fixed on disk; the configurable maximum is 4096.

`New(Config{Directory, Initial, Capacity})` creates revision 1 with canonicalized
initial names, or reopens an existing store. Initial is creation-only. Names are
canonical ASCII DNS names, using the publication ledger's normalization. Duplicate
canonical names are rejected. Snapshot and transition results are independent
copies. All methods except `Close` return an error when closed or poisoned.

Use `Preview(committedRevision, desiredActive)` to validate a candidate before
stopping a healthy dataplane. It returns a proposed pending snapshot without
writing or reserving a revision. `Prepare` repeats the same validation and CAS,
so a preview never authorizes a stale transition.

Call `Prepare(committedRevision, desiredActive)` before allocating any new engine
names. It writes a pending revision with append-only reservations, leaving the
committed active policy intact. Independently reconcile and verify the engine and
publication receipt, then `Commit(pendingRevision)`. The store only compares the
receipt revision; it does not verify external engine state itself. On failure,
`Abort(pendingRevision)` retains every pending reservation, restores the old active
policy and consumes the pending revision to reject replay. These operations return
`(Snapshot, error)`. An unresolved pending candidate blocks subsequent preparation.
Restart exposes the same pending state; recovery must explicitly commit or abort.

The directory must be mode 0700 without symlinks in any ancestor. The namespace
journal and exclusive nonblocking process lock are mode 0600. Writes use a private
temporary file, file fsync, atomic rename and directory fsync; directory creation
also syncs ancestors. Loading refuses symlinks, nonregular files, oversized files,
unknown or duplicate JSON members, invalid state and capacity changes. Any failed
durable transition poisons the open handle until it is closed and reopened, since
rename or fsync completion may be uncertain. The caller must not issue a new DNS
answer or enable readiness before durable preparation and external verification.

This package never mutates the FakeIP publication ledger or sing-box cache. Its
reservation history only supplies generation inputs to those separate components.
