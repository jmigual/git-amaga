# git-amaga: agent guide

Rust CLI that stores whole secret files in Git as explicit `*.amaga` age files next to ignored
plaintext. Members hold age keys or GPG keys (a custom `pgp` age stanza).

## Where to look
- `docs/adrs/plan.md`: the v1 spec (formats, commands, tests, implementation steps). Read the section you need.
- `docs/adrs/README.md`: decision index. Read it first; open only the relevant ADRs.
- Workspace (ADR-0014): `crates/core` is package `git-amaga-core` (the library) and `crates/cli`
  is package `git-amaga` (the binary). The core never prints; the CLI owns output and exit codes.
- CLI: `crates/cli/src/main.rs` clap, dispatch and rendering of the core's results.
- Core, under `crates/core/src/`: `lib.rs` module list and re-exports · `commands.rs` one `cmd_*`
  per subcommand · `status.rs` `status` · `dismiss.rs` `dismiss` · `epoch.rs` epoch files,
  wrap/unwrap · `partition.rs` `.amaga/partitions/` (members, `current-epoch` pointers, the
  `amaga-partition` attribute) · `membership.rs` `rotate`, `user add` and `user remove`, and the
  shared re-encrypt · `partition_commands.rs` the `partition` commands · `import.rs`
  `import-git-crypt` (pure helpers in `gitcrypt.rs`) · `remove.rs` `remove` ·
  `selection.rs` which secrets a command acts on · `files.rs` repo file helpers ·
  `outcome.rs` the result types (`Outcome`, `Warning`, `StatusReport`, …) · `context.rs`
  per-command `Context` (partitions, epochs, decrypt) · `secret.rs` header, partition label,
  age encrypt/decrypt, `next_header`, `plaintext_state`, base file · `gpg.rs` `.asc` validation,
  `pgp` stanza, gpg subprocess · `users.rs` `.amaga/users/` loading · `keyring.rs` `KEY`
  resolution and gpg keyring lookup · `identity.rs` keygen,
  identity, actor · `paths.rs` path mapping, `.gitignore` block, atomic write · `git.rs` git
  subprocess helpers · `audit.rs` JSONL events · `error.rs` the `Error` enum.
- Tests: unit tests beside the code; integration tests in `crates/cli/tests/cli.rs` and
  `crates/cli/tests/membership.rs`, `crates/cli/tests/partitions.rs`,
  `crates/cli/tests/import_git_crypt.rs` and `crates/cli/tests/repo_dir.rs` (`-C`; helpers in
  `crates/cli/tests/common/`); `crates/core/tests/directory.rs` (the `dir` parameter); key
  fixtures in `crates/core/tests/fixtures/`.

## Build and test (all must pass before each commit)
`cargo fmt --check` · `cargo clippy --workspace --all-targets -- -D warnings` ·
`cargo test --workspace` · `GIT_DIR=/nonexistent cargo test --workspace`

## Keep the code LLM-friendly
- Doc comments only on public items, and only for non-obvious behaviour or invariants (1–3 lines).
- No comments that restate the code. No multi-paragraph rationale in code: write an ADR and
  reference it as `ADR-NNNN` (or a plan section as `plan 5.1`).
- Keep files focused: split a module once it passes ~400 lines excluding tests.
- One `Error` variant per user-actionable failure; unit tests assert on variants, not message text.
  Integration tests may assert on stable stderr tokens (the binary exits 1 for every error).

## Test isolation
- Never touch the real git config, `HOME` or `~/.gnupg`. Integration tests set
  `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_NOSYSTEM=1` and a temp `HOME`.
- gpg tests use a short temp `GNUPGHOME` under `/tmp` (agent socket path limit), passed only to
  child processes (never `set_var`), skip with a notice when gpg is absent, and kill the agent on drop.
- git-crypt: only the end-to-end import test needs the real `git-crypt`; it skips with a notice
  when it is absent, unless `AMAGA_REQUIRE_GIT_CRYPT=1` (set on Linux CI), which makes it fail. Unit tests never run git (the checks set `GIT_DIR=/nonexistent`).

## Commits
Small, signed, one logical unit each; every commit builds and passes the checks above.
Never add `TODO`/`FIXME` or placeholder stubs.
