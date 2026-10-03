# ADR-0014: A core library crate and a CLI crate

**Status:** Accepted (implementation: plan.md §14)

## Context
Requested: others should be able to build on git-amaga without the CLI. Today one package holds
a library that prints from inside its commands (~20 `println!`/`eprintln!` sites), so a caller
cannot use a command without it writing to the terminal.

## Decision
- A virtual Cargo workspace: `crates/core` (package `git-amaga-core`: crypto, gpg, members,
  one function per command, `Error`) and `crates/cli` (package `git-amaga`: clap, every line
  of output, exit codes, binary `git-amaga`). Shared versions live once in
  `[workspace.dependencies]`; the release profile is in the root manifest.
- The core never prints. Each command returns typed data: changed paths, `Warning`s, the
  re-encrypted secrets and who each is exposed to, the resolved GPG key, a `StatusReport`.
  The CLI turns that into today's text: same lines, same stream, same exit codes.
- Status problems are data (`StatusReport::error_count`), not an `Error`; the CLI exits 1.
- Wording of problems stays in the core (`Error` and `Warning` `Display`, status messages);
  the CLI owns progress lines, the `error:`/`warning:` prefixes, the stream and the exit code.
- Commands keep resolving the repository from the process's current directory, like git.
- The integration tests stay in the CLI crate as the output regression net; only their crate
  path (`git_amaga::` → `git_amaga_core::`) and fixture paths change.

## Consequences
- A library caller gets results without terminal output, and the CLI output is unchanged.
- Results arrive when a command finishes. When a multi-file command fails part-way, the lines
  for files already written (and earlier warnings) are no longer shown; only the error is.
  Rerunning is safe (ADR-0007), and `git status` shows what changed.
- `git`, `paths`, `audit`, `commands`, `membership` become private: the public surface is the
  command functions, their result types, `Error`, and `secret`, `gpg`, `identity`, `users`.
- The core needs the process cwd; a caller that works on several repositories must set it.

## Alternatives considered
- One package with a lib and a bin (today): the library still prints.
- A progress callback (`FnMut(Event)`) per command: keeps partial output on failure, but adds an
  event type and a callback to every signature for a case rerunning already covers.
- A `repo: &Path` argument on every command: the cwd also drives the path prefix, relative
  `KEY` files and the `keygen` path, so threading it through is a separate change.
