# ADR-0001: Explicit `*.amaga` files next to ignored plaintext, no Git filters

**Status:** Accepted

## Context
Secrets must live in the repository encrypted, while members edit them as normal files.
Filter-based tools (git-crypt, transcrypt) encrypt transparently on stage, so `git status`
and `git diff` do not show what is actually committed, and a missing filter config commits
plaintext.

## Decision
- Each secret is two files: `path` (plaintext, git-ignored, never staged by the tool) and
  `path.amaga` (ciphertext, tracked). See plan.md §3 and §5.
- Users move between them with explicit commands: `add`, `seal`, `open`, `close`, `remove`.
  The decrypt command is `open` (not `unlock`) so it pairs with `seal`/`close`
  (plan.md §2, decision 8).
- `.gitattributes` marks `*.amaga binary`, so autocrlf cannot rewrite age headers and merges
  never write conflict markers into ciphertext (plan.md §1, change 8).
- Whole-file semantics: exposure and "changed" are per file, never per value.

## Consequences
- `git status` always shows exactly what will be committed.
- Users must remember to `seal` after editing; `status` reports unsealed edits (ADR-0009).
- Plaintext safety depends on `.gitignore`, so the tool checks it on every command (ADR-0011).

## Alternatives considered
- Git clean/smudge filters: transparent but invisible, and fail open when unconfigured.
- Per-value encryption inside structured files (sops): needs a parser per format.
