# Architecture decision records

Agents: read this table, then open only the ADRs relevant to your task. The full spec is
[`plan.md`](../../plan.md).

| ADR | Title | Status | Decision |
|-----|-------|--------|----------|
| [0001](0001-explicit-amaga-files.md) | Explicit `*.amaga` files, no Git filters | Accepted | Ignored plaintext next to tracked `path.amaga`; explicit `add`/`seal`/`open`/`close`; `*.amaga binary`. |
| [0002](0002-rust-binary-cli-subprocesses.md) | Single Rust binary, CLI subprocesses | Accepted | One static binary; `git`/`gpg` run as subprocesses (no shell, no libgit2/gpgme); built-in `keygen`. |
| [0003](0003-per-file-age.md) | Per-file age instead of epoch keys | Accepted | Each secret is one standard age file to all member keys; no custom crypto composition. |
| [0004](0004-gpg-pgp-age-stanza.md) | GPG via a custom `pgp` age stanza | Accepted | GPG members get a `pgp` stanza; rPGP encrypts in-process, `gpg --decrypt` unwraps (one call per file). |
| [0005](0005-gpg-member-keys.md) | GPG member key rules | Accepted | Export-minimal `.asc`; identified by encryption-subkey fingerprint; expiry checked only when adding. |
| [0006](0006-exposure-tracking.md) | Exposure tracking via `exposed_to` | Accepted | Header records recipients; dropping one without a plaintext change adds it to `exposed_to`. |
| [0007](0007-no-transaction-journal.md) | No transaction journal | Accepted | Decrypt all, change membership, rewrite; interrupted runs are finished by rerunning `rotate`. |
| [0008](0008-audit-log-jsonl.md) | Audit log as plain JSONL | Accepted | Append-only `audit.jsonl` with `merge=union`; informational, no hash chain. |
| [0009](0009-three-way-plaintext-state.md) | Three-way plaintext state | Accepted | Per-worktree base hashes distinguish local edits from upstream changes; `seal` refuses stale plaintext. |
| [0010](0010-local-config-and-actor.md) | Local config and actor | Accepted | Identity path from `git config amaga.identity`; actor is the member whose key matches. |
| [0011](0011-append-only-gitignore.md) | Append-only `.gitignore` block | Accepted | Managed block only grows, `merge=union`; `check-ignore` is the source of truth. |
| [0012](0012-membership-directory.md) | Membership is `.amaga/users/` | Accepted | `<name>.txt` (age) and/or `<name>.asc` (GPG); lowercase names; key change = edit + `rotate`. |
| [0013](0013-gpg-key-lookup.md) | GPG key lookup from the local keyring | Accepted | `KEY` that is not `age1…` or an `.asc` file is exported from local gpg (export-minimal); `keygen` prints the `user add` line. |
| [0014](0014-core-and-cli-crates.md) | Core library crate and CLI crate | Accepted | Workspace: `git-amaga-core` returns typed results and never prints; `git-amaga` (CLI) renders today's output and exit codes. |
