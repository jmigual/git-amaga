# ADR-0007: No transaction journal; `rotate` is the recovery command

**Status:** Accepted

## Context
`user add`, `user remove` and `rotate` rewrite every secret, and a run can be interrupted
midway. The original design had a local journal and a `recover` command.

## Decision
Re-encrypt-all (plan.md §7.1): decrypt every secret into memory first (abort before writing
if any fails), then change membership, then rewrite each secret atomically. `rotate` is
idempotent, so rerunning it finishes an interrupted run. No journal, no `recover`.

## Consequences
- After an interruption `status` reports "stale recipients" and `rotate` completes the work;
  exposure stays correct because it comes from each file's own header (ADR-0006).
- Git already holds the previous state for anything else.
- No clean-tree precondition: unsealed local edits are unaffected.
- Ceiling: all secrets are held in memory at once; stream per file if large files appear.

## Alternatives considered
- Transaction journal + `recover`: more state to get wrong, and it lives under `.git`, which
  is a file in worktrees and submodules.
