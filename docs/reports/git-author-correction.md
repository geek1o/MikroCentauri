# GitHub attribution correction

All17 initially published commits used macOS-inferred author and committer
`Илья Овсянников <geekio@Air--Ilya.lan>`, which GitHub did not associate with the
account. Repository-local Git identity now uses `Ilya Ovsyannikov` and the verified
account-derived noreply address `11626397+geek1o@users.noreply.github.com`.

The user explicitly approved replacement of the published history. Every commit
was recreated with the same tree, message, author/committer timestamp and parent
ordering. Only identity fields and the consequent commit/parent hashes changed.
The push used an explicit `--force-with-lease` expected old main SHA. GitHub API
readback verified all17 commits' author and committer logins as `geek1o`.
See [old-to-new map and verification](git-author-correction.json).

Original history remains in the local `before-author-fix` branch and ignored
`.cache/git-authorship/before-author-fix.bundle`. Historical reports retain their
original implementation SHA as provenance; use the mapping above for the
corresponding rewritten commit. New development uses the corrected identity.
No global Git configuration or unrelated repository was changed.

GitHub links commits by email; see official
[commit email configuration](https://docs.github.com/en/account-and-profile/how-tos/email-preferences/setting-your-commit-email-address)
and [noreply address format](https://docs.github.com/en/account-and-profile/reference/email-addresses-reference).
