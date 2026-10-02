# ADR-0011: Append-only managed `.gitignore` block, merged with `merge=union`

**Status:** Accepted

## Context
Plaintext safety depends on every managed plaintext path being ignored. Deleting ignore
entries can un-ignore a teammate's plaintext after they pull; renames (`git mv`) and parallel
`add`s on two branches must also stay safe.

## Decision
- `init` creates a `# BEGIN git-amaga` / `# END git-amaga` block in the root `.gitignore`
  containing `*.amaga-tmp`. `add`, `seal` and `open` insert a root-anchored, escaped entry
  only if `git check-ignore -q --no-index` says the path is not ignored, then re-check
  (plan.md §5.4).
- The block is append-only: no command deletes entries. Lines outside it are kept
  byte-for-byte; the tool never parses the block.
- `.gitattributes` sets `.gitignore merge=union`.

## Consequences
- A teammate's plaintext stays ignored after pulling a `remove`; stale entries are harmless.
- Parallel `add`s on two branches merge cleanly (verified). Union also applies to the user's
  own lines, which is acceptable for an ignore file.
- If a hosting platform ignores `merge=union`, resolve by keeping both sides' lines.

## Alternatives considered
- Rewriting the block from the current secret list: un-ignores plaintext after pulls.
- Per-directory `.gitignore` files: more files to merge, same deletion problem.
