# git-amaga

Encrypted secret files in Git, shared with a team through age or GPG keys.

[![CI](https://github.com/jmigual/git-amaga/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jmigual/git-amaga/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/jmigual/git-amaga)](https://github.com/jmigual/git-amaga/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV 1.88](https://img.shields.io/badge/MSRV-1.88-orange.svg)](Cargo.toml)

> **Status: 0.1.0, not audited.** The on-disk formats and commands may still change before 1.0.
> Read [Security model and limitations](#security-model-and-limitations) before trusting it with
> production secrets.

## Contents

- [Why git-amaga](#why-git-amaga)
- [How it works](#how-it-works)
- [Install](#install)
- [Quick start](#quick-start)
- [Team workflow](#team-workflow)
- [Command reference](#command-reference)
- [GPG notes](#gpg-notes)
- [Removing a member and rotating credentials](#removing-a-member-and-rotating-credentials)
- [Branches and merge conflicts](#branches-and-merge-conflicts)
- [Security model and limitations](#security-model-and-limitations)
- [Using the library](#using-the-library)
- [Development](#development)
- [Reporting security issues](#reporting-security-issues)
- [License](#license)

## Why git-amaga

- **Explicit file pairs, no Git filters.** Each secret is a plaintext file that Git ignores and
  an encrypted `.amaga` file next to it that you commit, so `git status` shows exactly what
  will be committed.
- **age or GPG members.** GPG keys, including smartcards and YubiKeys through gpg-agent, work
  alongside age keys.
- **Offboarding that tracks exposure.** Removing a member re-encrypts every secret without
  their keys and flags each secret they could read until its real credential is rotated.

```text
secrets/prod.env         plaintext, git-ignored, never committed by the tool
secrets/prod.env.amaga   age ciphertext, tracked and committed
```

## How it works

Each `*.amaga` file is a standard [age](https://age-encryption.org) file encrypted to every
member's key. Its encrypted header records who it was encrypted to and who it has been exposed
to. Members are the files in `.amaga/users/` (`<name>.txt` for age keys, `<name>.asc` for GPG),
events are appended to `.amaga/audit.jsonl`, and plaintext paths are kept in a managed
`.gitignore` block.

**Escape hatch for age members:** the tool is not needed to read a secret.

```sh
age -d -i ~/.config/git-amaga/identity.txt secrets/prod.env.amaga | tail -n +2 > secrets/prod.env
```

`tail` drops the one-line JSON header. GPG members need the tool, because the `pgp` age stanza
is specific to it.

Design decisions are in [`docs/adrs/`](docs/adrs/README.md) and the full specification (formats,
commands, threat model) is in [`plan.md`](plan.md).

## Install

Runtime requirements: `git`, and `gpg` 2.1+ only for members who use a GPG key.

**Prebuilt binaries** (static, from the latest [release](https://github.com/jmigual/git-amaga/releases/latest)):

```sh
# Linux x86_64
curl -fL -o git-amaga https://github.com/jmigual/git-amaga/releases/latest/download/git-amaga-x86_64-unknown-linux-musl
chmod +x git-amaga && sudo mv git-amaga /usr/local/bin/
```

```powershell
# Windows x86_64: put the file in a folder on your PATH
Invoke-WebRequest -OutFile git-amaga.exe https://github.com/jmigual/git-amaga/releases/latest/download/git-amaga-x86_64-pc-windows-msvc.exe
```

**From source** (Rust 1.88+):

```sh
cargo install --locked --git https://github.com/jmigual/git-amaga git-amaga
```

With `git-amaga` on your `PATH`, `git amaga <command>` works too.

## Quick start

Run this inside a Git repository.

```sh
git amaga keygen                    # creates your age identity, prints your public key
git amaga init alice                # you become the first member
git amaga add secrets/prod.env      # encrypts it and git-ignores the plaintext
git add -A && git commit -m "Add prod secrets"
```

Edit a plaintext, then `git amaga seal` and commit the changed `.amaga` file.

## Team workflow

A second member joins:

```sh
git amaga keygen                    # bob: prints a "git-amaga user add <name> age1…" line on stderr; send it
git amaga user add bob age1…        # alice: adds bob, re-encrypts everything
git add -A && git commit -m "Add bob" && git push
git pull && git amaga open          # bob: decrypts the secrets to local plaintext
```

A member with a GPG key is added by key ID, fingerprint or email from your local keyring, or by
an exported `.asc` file:

```sh
git amaga user add carol carol@example.org
```

## Command reference

Use `git amaga <command>` or `git-amaga <command>`.

| Command | What it does |
|---------|--------------|
| `keygen [PATH]` | Create an age identity (default `~/.config/git-amaga/identity.txt`) and print its public key |
| `init <name> [KEY…]` | Set up the repository with you as the first member; without a `KEY` it uses your age identity |
| `add [--force] <path>…` | Encrypt a new secret and make sure its plaintext is ignored |
| `seal [--force] [<path>…]` | Re-encrypt local edits |
| `open [--force] [<path>…]` | Decrypt secrets to local plaintext |
| `close [<path>…]` | Delete local plaintext that is already sealed |
| `status` | Members, per-secret state, problems and secrets that need rotation; exits 1 on errors |
| `user add <name> <KEY>…` | Add a member and re-encrypt every secret |
| `user remove <name>` | Remove a member, re-encrypt, flag exposed secrets |
| `rotate` | Re-encrypt everything with fresh keys; also finishes an interrupted run |
| `remove <path>…` | Stop managing a secret: deletes the `.amaga` file only, and the plaintext must be open and in sync so you keep a copy |

Global option: `-C <path>` (`--repo <path>`) runs any command as if started in `<path>`, like
`git -C`; relative paths and `KEY` files then resolve against it.

A `KEY` is an `age1…` public key, an exported `.asc` OpenPGP key file, or a GPG key ID,
fingerprint or email that the tool exports from your local keyring. `seal` and `open` refuse to
overwrite diverged files unless `--force` is given.

If a sealed but uncommitted `.amaga` is discarded with `git checkout` or `git reset`, the
plaintext shows as outdated and is the only copy of that content: run `seal --force`, not
`open --force`.

## GPG notes

- `init` and `user add` export the key from your keyring with `gpg --export-options
  export-minimal`; an `.asc` file works too. An email matching several keys is refused: pass a
  fingerprint.
- The tool encrypts to GPG members itself and only calls `gpg` to decrypt. Age members can seal
  for GPG members without having gpg installed.
- Decryption may prompt for a PIN or card. If there is no prompt, run `export GPG_TTY=$(tty)`.
  Smartcards and YubiKeys work through gpg-agent.
- A key is identified by its encryption subkey. Replacing the subkey makes secrets stale, and
  `rotate` then flags them as exposed to the old one.
- On Windows, install [Gpg4win](https://www.gpg4win.org) or a native GnuPG and make sure `gpg` is
  on your `PATH`.

## Removing a member and rotating credentials

1. Revoke their repository access at the hosting provider.
2. `git amaga user remove charlie`, review `git status`, commit everything in one commit.
3. `git amaga status` lists every secret marked `NEEDS ROTATION`.
4. Rotate each real credential, edit the plaintext, `seal` and commit until nothing is flagged.

If a `.amaga` file is corrupt or not encrypted to you, `remove` cannot read it; drop it with
`git rm <path>.amaga`.

## Branches and merge conflicts

Every command that works on secrets, except `status`, refuses while a `*.amaga` is unmerged.
Resolve a conflict with `git checkout --ours|--theirs -- f.amaga && git add f.amaga`, then
`git amaga open --force f` and re-apply your edit. Concurrent membership changes normally merge
cleanly; `status` then reports stale secrets until someone runs `rotate`. Details are in
[plan.md](plan.md) section 8.

## Security model and limitations

- People with read access to the repository but no member key cannot decrypt current secrets.
- A new member cannot decrypt history from before they joined.
- A removed member keeps whatever they already saw and can still decrypt old commits. Only
  rotating the real credential fixes that; the tool flags which secrets need it. A compromised
  member key exposes everything that member can read.
- age has no sender authentication: anyone with write access can replace member files or
  ciphertext. Use branch protection, review and signed commits.
- The audit log is informational; its integrity is whatever your Git history gives you.
- Plaintext that is tracked or not ignored is reported as critical by `status`.
- GPG keys come only from the committed `.asc` files; nothing is fetched from a keyserver. A
  revocation or new subkey takes effect once the member commits a re-exported `.asc` and someone
  runs `rotate`. A key that expires after `user add` is still encrypted to.
- GPG decryption trusts the `gpg` on your `PATH` and its agent, and costs one `gpg` call per
  secret, so a card set to touch-always needs one touch per file.
- Merging a branch that predates a removal brings back the removed member's key in those files;
  `status` reports them as stale and `rotate` flags them.
- The full threat model is in [plan.md](plan.md) section 4.

## Using the library

The `git-amaga-core` crate (`crates/core`) has one function per command. It takes the directory
to run in, returns typed results and never prints. It is not published on crates.io; depend on it
from Git:

```toml
git-amaga-core = { git = "https://github.com/jmigual/git-amaga" }
```

```rust
use std::path::Path;

use git_amaga_core::cmd_status;

fn main() -> Result<(), git_amaga_core::Error> {
    let report = cmd_status(Path::new("."))?;
    println!("members: {}", report.members);
    for secret in &report.secrets {
        println!("{:?} {}: {}", secret.level, secret.path, secret.messages.join("; "));
    }
    if report.error_count() > 0 {
        std::process::exit(1);
    }
    Ok(())
}
```

## Development

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The workspace has two crates: `crates/core` (library `git-amaga-core`) and `crates/cli` (binary
`git-amaga`). GPG tests skip with a notice when `gpg` is not installed. Contributor and agent
conventions are in [`CLAUDE.md`](CLAUDE.md), design decisions in
[`docs/adrs/`](docs/adrs/README.md) and the specification in [`plan.md`](plan.md).

## Reporting security issues

Report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/jmigual/git-amaga/security/advisories/new)
(see [SECURITY.md](SECURITY.md)), not in a public issue.

## License

MIT, see [LICENSE](LICENSE).
