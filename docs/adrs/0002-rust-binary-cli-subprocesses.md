# ADR-0002: Single Rust binary; `git` and `gpg` run as CLI subprocesses

**Status:** Accepted

## Context
The tool should install as one file and run on Linux and Windows. It needs Git queries
(toplevel, ignore checks, ls-files) and, for GPG members, decryption through the user's
gpg-agent and smartcards.

## Decision
- One Rust crate (library + thin `main.rs`), edition 2024. Static musl binary on Linux,
  `+crt-static` on Windows (plan.md §10.3).
- Run `git` and `gpg` as subprocesses with argument vectors: never through a shell, `--`
  before paths, `-z` output where available. No libgit2, no gpgme.
- `keygen` generates age identities in-process, so nobody needs the `age` CLI.
- No traits of our own, no async, no daemon (plan.md §3).

## Consequences
- Runtime dependencies are just `git`, plus `gpg` 2.1+ for members who decrypt with GPG.
- The tool sees exactly what the user's `git` sees (worktrees, config scopes, `git -c`).
- One process spawn per query; acceptable at the scale of a secrets directory.

## Alternatives considered
- libgit2 / gpgme bindings: C dependencies break the static build and can disagree with the
  user's installed git/gpg.
- sequoia-openpgp: LGPL, and still cannot talk to gpg-agent smartcards.
