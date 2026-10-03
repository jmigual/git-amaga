# ADR-0007: No transaction journal; `rotate` is the recovery command

**Status:** Accepted; amended by ADR-0015 (new epoch, pointer moved last)

## Context
`user add`, `user remove` and `rotate` change membership or keys across several files, and a
run can be interrupted midway. The original design had a local journal and a `recover` command.

## Decision
- Re-encrypt-all (`user remove`, `rotate`; plan.md §7.1): decrypt every secret into memory
  first (abort before writing if any fails), then change membership, write the new epoch file,
  rewrite each secret atomically, and move `.amaga/current-epoch` last.
- `user add` writes the member file before re-wrapping the epoch, so an interruption leaves
  "members missing from the epoch", never an epoch wrapped to a non-member.
- `rotate` always finishes the job: it reads secrets under any epoch the actor holds. No
  journal, no `recover`.

## Consequences
- After an interruption `status` reports "stale recipients" and `rotate` completes the work;
  exposure stays correct because it comes from each file's own header and the members of the
  epoch that decrypted it (ADR-0006).
- An interrupted run can leave an epoch file that no secret uses; it is kept, harmlessly.
- Git already holds the previous state for anything else.
- No clean-tree precondition: unsealed local edits are unaffected.
- Ceiling: all secrets are held in memory at once; stream per file if large files appear.

## Alternatives considered
- Transaction journal + `recover`: more state to get wrong, and it lives under `.git`, which
  is a file in worktrees and submodules.
- Moving the pointer first: equally recoverable, but the pointer would name an epoch before
  any secret uses it.
