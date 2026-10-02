# ADR-0009: Three-way plaintext state with per-worktree base hashes

**Status:** Accepted

## Context
Comparing only local plaintext with ciphertext cannot tell a local edit from an upstream
change. Bug in the original design: after `git pull` brings in a rotated credential, `seal` of
the stale local copy would write back the old value and clear the needs-rotation flag.

## Decision
- Store a base hash (SHA-256 of the body the plaintext was last synced with) per secret in
  `$(git rev-parse --git-path amaga-base)`, which is per worktree (plan.md §5.5).
- Classify with a pure function `plaintext_state(P, C, B)` into `Closed`, `InSync`,
  `Modified`, `Outdated`, `Conflict` (plan.md §6.2). `seal` writes only `Modified`;
  `open` writes only `Closed`/`Outdated`; `--force` overrides, with a warning when it clears
  `exposed_to`.

## Consequences
- Pulling a rotated credential makes the local copy `Outdated`; `seal` refuses it.
- Linked worktrees keep independent base files.
- A discarded uncommitted `.amaga` makes the plaintext `Outdated` although it is the only
  copy: the README tells users to `seal --force` it (plan.md §8).

## Alternatives considered
- Two-way compare (original design): the stale-plaintext bug above.
- Base hashes committed, or under `.git/amaga/`: shared across worktrees, or wrong when
  `.git` is a file.
