# ADR-0012: Membership is the `.amaga/users/` directory

**Status:** Accepted; amended by ADR-0015 (epochs), ADR-0016 (`dismiss`) and ADR-0017
(partition member lists)

## Context
The tool needs a committed, reviewable list of members and their keys, supporting several
devices per person and both age and GPG keys.

## Decision
- A member is `.amaga/users/<name>.txt` (age recipients file: one `age1…` per line, `#`
  comments) and/or `<name>.asc` (one OpenPGP key, ADR-0005). The set of files *is* the
  membership; there are no user UUIDs (plan.md §5.1). The current epoch records which of
  these keys it is wrapped to; when the two differ the repository is stale (ADR-0015).
- Names match `[a-z0-9][a-z0-9._-]{0,63}`: lowercase, so they cannot collide on
  case-insensitive filesystems.
- Duplicate keys across members, members without keys, unknown files, or no members at all
  are errors.
- `.amaga/users/` holds keys. Access comes from the partition member lists,
  `.amaga/partitions/<p>/members` (ADR-0017). A listed name without a user file grants nothing;
  `status` warns about it.
- Key changes for an existing member: edit or replace the file, then `rotate`
  (plan.md §2 decision 5). If the old key is known to be safe, `dismiss --user <name>`
  clears the resulting flags (ADR-0016).

## Consequences
- Readable in diffs and usable directly with `age -R`; multi-device support comes free.
- Concurrent membership changes touch different files and normally merge cleanly; `status`
  then reports stale secrets until someone runs `rotate`.
- A hand edit of `.amaga/users` makes the epoch stale: `add`, `seal`, `user add` and
  `dismiss` refuse until `rotate`.
- Any removed key counts as exposure, even a routine device swap (ADR-0006).

## Alternatives considered
- One members file with UUIDs: merge conflicts and opaque diffs.
- A `user key add/remove` subcommand that skips exposure marking: replaced by `dismiss`.
