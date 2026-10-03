# ADR-0012: Membership is the `.amaga/users/` directory

**Status:** Accepted

## Context
The tool needs a committed, reviewable list of members and their keys, supporting several
devices per person and both age and GPG keys.

## Decision
- A member is `.amaga/users/<name>.txt` (age recipients file: one `age1…` per line, `#`
  comments) and/or `<name>.asc` (one OpenPGP key, ADR-0005). The set of files *is* the
  membership; there is no other pointer and no user UUIDs (plan.md §5.1).
- Names match `[a-z0-9][a-z0-9._-]{0,63}`: lowercase, so they cannot collide on
  case-insensitive filesystems.
- Duplicate keys across members, members without keys, unknown files, or no members at all
  are errors.
- Key changes for an existing member: edit or replace the file, then `rotate`
  (plan.md §2 decision 5).

## Consequences
- Readable in diffs and usable directly with `age -R`; multi-device support comes free.
- Concurrent membership changes touch different files and normally merge cleanly; `status`
  then reports stale secrets until someone runs `rotate`.
- Any removed key counts as exposure, even a routine device swap (ADR-0006).

## Alternatives considered
- One members file with UUIDs: merge conflicts and opaque diffs.
- A `user key add/remove` subcommand that skips exposure marking: deferred (plan.md §13).
