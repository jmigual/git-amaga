# ADR-0008: Audit log is plain JSONL with `merge=union`, no hash chain

**Status:** Accepted (plan.md §2 decisions 6 and 7 can flip it)

## Context
The goal names an audit log. The original design hash-chained entries with `seq` and offered
`audit verify`/`audit show`.

## Decision
`.amaga/audit.jsonl`: one JSON object per line (`time`, `actor`, `event`, optional fields),
written by the tool and never parsed by it (plan.md §5.3). `.gitattributes` sets
`merge=union`. No `seq`, no hash chain, no `audit` subcommands.

## Consequences
- Two branches that both append merge without conflict (verified with git 2.x); lines are
  ordered by side, not time.
- The log is informational: unsigned and editable. Its integrity is whatever Git history
  (and signed commits) give you.
- `secret.updated` means the plaintext changed; re-encryption never writes it.

## Alternatives considered
- Hash chain: breaks whenever two branches append (both get `seq` N+1 with the same
  `prev_hash`), and a writer who can rewrite history can recompute it anyway. Restoring it
  needs either no parallel security changes or a merge-repair command.
- `git log` only: loses the domain events the goal asks for.
