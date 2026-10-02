# git-amaga: agent guide

Rust CLI that stores whole secret files in Git as explicit `*.amaga` age files next to ignored
plaintext. Members hold age keys or GPG keys (a custom `pgp` age stanza).

## Where to look
- `plan.md`: the v1 spec (formats, commands, tests, implementation steps). Read the section you need.
- `docs/adrs/README.md`: decision index. Read it first; open only the relevant ADRs.
- Modules: `main.rs` clap CLI → `lib.rs` module list and re-exports · `commands.rs` one `cmd_*` per
  subcommand · `context.rs` per-command `Context` and file helpers · `secret.rs` header,
  age encrypt/decrypt, `next_header`, `plaintext_state`, base file · `gpg.rs` `.asc` validation,
  `pgp` stanza, gpg subprocess · `users.rs` `.amaga/users/` loading · `identity.rs` keygen,
  identity, actor · `paths.rs` path mapping, `.gitignore` block, atomic write · `git.rs` git
  subprocess helpers · `audit.rs` JSONL events · `error.rs` the `Error` enum.
- Tests: unit tests beside the code; integration tests in `tests/cli.rs` (helpers in
  `tests/common/`, key fixtures in `tests/fixtures/`).

## Build and test (all must pass before each commit)
`cargo fmt --check` · `cargo clippy --all-targets -- -D warnings` · `cargo test`

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

## Commits
Small, signed, one logical unit each; every commit builds and passes the checks above.
Never add `TODO`/`FIXME` or placeholder stubs.
