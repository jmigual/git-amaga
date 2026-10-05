# git-amaga

Encrypted secret files in Git, shared with a team through age or GPG keys.

[![CI](https://github.com/jmigual/git-amaga/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jmigual/git-amaga/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/git-amaga.svg)](https://crates.io/crates/git-amaga)
[![Latest release](https://img.shields.io/github/v/release/jmigual/git-amaga)](https://github.com/jmigual/git-amaga/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jmigual/git-amaga/blob/main/LICENSE)
[![MSRV 1.88](https://img.shields.io/badge/MSRV-1.88-orange.svg)](https://github.com/jmigual/git-amaga/blob/main/Cargo.toml)

> **Status: 0.3.1, not audited.** The on-disk formats and commands may still change before 1.0.
> 0.2.0 and later (format version 2) cannot read repositories written by 0.1.0.
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
- [Migrating from git-crypt](#migrating-from-git-crypt)
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

Secrets belong to **partitions**: named member lists such as `default`, `production` or
`staging`. Each `*.amaga` file is a standard [age](https://age-encryption.org) file encrypted to
the current **epoch** key of its partition, an age X25519 key pair. The epoch's secret key is
itself an age file, `.amaga/epochs/<public key>.age`, encrypted to the keys of the partition's
members. A partition is the directory `.amaga/partitions/<p>/`, with `members` (member names,
one per line) and `current-epoch` (the current epoch's public key). `init` creates `default`.
A command unwraps the epoch of each partition it touches once (one `gpg` call per partition for
a GPG member) and then decrypts that partition's secrets in-process. A member who is not in a
partition cannot unwrap its epoch, so access is enforced by the encryption.

Each secret's age header carries a readable label, `-> amaga-partition <p>`. The label is
authenticated by the header MAC, and age tools ignore it. It is the truth about a secret's
partition: it is chosen when the secret is added (`add --partition <p>`, else the
`amaga-partition` git attribute of the plaintext path, else `default`) and changed only by
`partition move`. Each secret's encrypted header also records who it has been exposed to, and
each epoch file records which member keys it is wrapped to.

Members are the files in `.amaga/users/` (`<name>.txt` for age keys, `<name>.asc` for GPG),
events are appended to `.amaga/audit.jsonl`, and plaintext paths are kept in a managed
`.gitignore` block. `user remove`, `rotate` and `partition remove` create new epochs and
re-encrypt the secrets of the partitions they cover; `user add` and `partition add` only re-wrap
a current epoch. Epoch files are never deleted.

This is format version 2 (since 0.2.0). It cannot read repositories written by 0.1.0 (format version
1): open the secrets with 0.1.0, then run `init` anew.

**Escape hatch for age members:** the tool is not needed to read a secret. Two `age -d`
commands. The epoch key goes to a temporary file outside the repository (`mktemp` makes it
private), so it can never be committed; delete it afterwards.

```sh
k=$(mktemp)
age -d -i ~/.config/git-amaga/identity.txt ".amaga/epochs/$(cat .amaga/partitions/default/current-epoch).age" | tail -n +2 > "$k"
age -d -i "$k" secrets/prod.env.amaga | tail -n +2 > secrets/prod.env
rm "$k"
```

`tail` drops the one-line JSON header of each payload. A secret in another partition needs that
partition's `current-epoch` (its name is the secret's label, visible with
`grep -a amaga-partition <file>.amaga`), and a secret under an older epoch needs that epoch's
file instead. GPG members need the tool, because the `pgp` age stanza is specific to it.

Design decisions are in [`docs/adrs/`](https://github.com/jmigual/git-amaga/blob/main/docs/adrs/README.md) and the full specification (formats,
commands, threat model) is in [`plan.md`](https://github.com/jmigual/git-amaga/blob/main/docs/adrs/plan.md).

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

**With [cargo-binstall](https://github.com/cargo-bins/cargo-binstall)** (downloads the prebuilt binary):

```sh
cargo binstall git-amaga
```

**From crates.io** (Rust 1.88+):

```sh
cargo install --locked git-amaga
```

**From source** (Rust 1.88+):

```sh
cargo install --locked --git https://github.com/jmigual/git-amaga git-amaga
```

With `git-amaga` on your `PATH`, `git amaga <command>` works too.

The library is published as [`git-amaga-core`](https://docs.rs/git-amaga-core).

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
git amaga user add bob age1…        # alice: adds bob (re-wraps the epoch key to bob)
git add -A && git commit -m "Add bob" && git push
git pull && git amaga open          # bob: decrypts the secrets to local plaintext
```

`user add` rewrites no secret, so bob can read every version committed under the current
epoch, back to the last `rotate` or `user remove`. To keep that history from a newcomer, run
`git amaga rotate` and commit before `user add`.

A member with a GPG key is added by key ID, fingerprint or email from your local keyring, or by
an exported `.asc` file:

```sh
git amaga user add carol carol@example.org
```

### Restricting who reads what

Some members may read only some secrets, for example `production` and `staging`:

```sh
git amaga partition create production alice          # a partition that only alice reads
git amaga add --partition production secrets/prod.env
git amaga user add dave age1… --partition staging    # dave joins `staging` and not `default`
git amaga partition add production bob               # later: re-wraps production's key to bob
```

Commands without paths skip the secrets of partitions you are not in, and `status` lists them as
`not a member`. A path in a partition you are not in fails with that partition's name. Putting
`prod/** amaga-partition=production` in `.gitattributes` makes `add` pick that partition for
those paths; the attribute is read only at `add`, and `status` fails if it later disagrees with
a secret's label (`partition move <p> <path>…` fixes that). A secret is in one partition; for
a secret several groups read, make a partition whose members are the union.

## Command reference

Use `git amaga <command>` or `git-amaga <command>`.

| Command | What it does |
|---------|--------------|
| `keygen [PATH]` | Create an age identity (default `~/.config/git-amaga/identity.txt`) and print its public key |
| `init <name> [KEY…]` | Set up the repository with you as the first member; without a `KEY` it uses your age identity |
| `add [--force] [--partition <p>] <path>…` | Encrypt a new secret and make sure its plaintext is ignored; the partition is `--partition`, else the `amaga-partition` attribute, else `default` |
| `seal [--force] [<path>…]` | Re-encrypt local edits (alias `lock`) |
| `open [--force] [<path>…]` | Decrypt secrets to local plaintext (alias `unlock`) |
| `close [<path>…]` | Delete local plaintext that is already sealed (alias `shred`; deletes, does not overwrite) |
| `status` | Members, partitions, per-secret state, problems and secrets that need rotation; exits 1 on errors |
| `user add [--partition <p>]… <name> <KEY>…` | Add a member to `default`, or to the given partitions: re-wrap their current epoch keys to them; no secret is rewritten |
| `user remove <name>` | Remove a member from every partition, re-encrypt the partitions you are in, flag exposed secrets; other partitions are reported |
| `rotate [--partition <p>]…` | Re-encrypt the named partitions (default: every partition you are in) under new epochs; also finishes an interrupted run |
| `partition create <p> <member>…` | Create a partition with a new key, wrapped to those members (you need not be one) |
| `partition add <p> <member>…` | Add members to a partition: re-wrap its current epoch key; no secret is rewritten |
| `partition remove <p> <member>…` | Remove members from a partition, re-encrypt its secrets, flag exposed ones; the last member cannot be removed |
| `partition move <p> <path>…` | Move secrets into partition `p`, flagging members of the old key that `p` lacks |
| `import-git-crypt [--name <FPR>=<name>]…` | Migrate an unlocked git-crypt repository (see [Migrating from git-crypt](#migrating-from-git-crypt)) |
| `dismiss [--user <name>]… [<path>…]` | Clear `NEEDS ROTATION` for those members (default all) and secrets (default all) without changing the plaintext; needs a path or `--user`; recorded in the audit log |
| `remove <path>…` | Stop managing a secret: deletes the `.amaga` file only, and the plaintext must be open and in sync so you keep a copy |

Global option: `-C <path>` (`--repo <path>`) runs any command as if started in `<path>`, like
`git -C`; relative paths and `KEY` files then resolve against it.

A `KEY` is an `age1…` public key, an exported `.asc` OpenPGP key file, or a GPG key ID,
fingerprint or email that the tool exports from your local keyring. `seal` and `open` refuse to
overwrite diverged files unless `--force` is given. A command that writes into a partition
(`add`, `seal`, `user add`, `dismiss`, `partition add`, `partition move`) refuses while that
partition's current epoch is not wrapped to exactly the keys of the users its `members` file
lists (for example after a hand-edited or merged membership change): run
`rotate --partition <p>` first.

If a sealed but uncommitted `.amaga` is discarded with `git checkout` or `git reset`, the
plaintext shows as outdated and is the only copy of that content: run `seal --force`, not
`open --force`.

## GPG notes

- `init` and `user add` export the key from your keyring with `gpg --export-options
  export-minimal`; an `.asc` file works too. An email matching several keys is refused: pass a
  fingerprint.
- The tool encrypts to GPG members itself and only calls `gpg` to unwrap the epoch file, once
  per command. Age members can seal
  for GPG members without having gpg installed.
- Decryption may prompt for a PIN or card. If there is no prompt, run `export GPG_TTY=$(tty)`.
  Smartcards and YubiKeys work through gpg-agent.
- A key is identified by its encryption subkey. Replacing the subkey makes secrets stale, and
  `rotate` then flags them as exposed to the old one.
- On Windows, install [Gpg4win](https://www.gpg4win.org) or a native GnuPG and make sure `gpg` is
  on your `PATH`.

## Removing a member and rotating credentials

1. Revoke their repository access at the hosting provider.
2. `git amaga user remove charlie`, review `git status`, commit everything in one commit. If a
   warning names a partition you are not in, one of its members must run
   `git amaga rotate --partition <p>` and commit; until then that partition is stale and
   charlie's key still opens it.
3. `git amaga status` lists every secret marked `NEEDS ROTATION`.
4. Rotate each real credential, edit the plaintext, `seal` and commit until nothing is flagged.
5. If their keys are known to be destroyed, or a secret needs no rotation, run
   `git amaga dismiss --user charlie [<path>…]` instead of step 4 and commit. The audit log
   records who dismissed it.

If a `.amaga` file is corrupt or not encrypted to you, `remove` cannot read it; drop it with
`git rm <path>.amaga`.

## Migrating from git-crypt

`import-git-crypt` turns an unlocked git-crypt repository into a git-amaga one:

1. `git-crypt unlock`, so every file is plaintext in your working tree.
2. `git amaga init <name>` (you become the first member) and commit.
3. `git amaga import-git-crypt`. Every tracked file with a git-crypt `filter` attribute becomes a
   secret. git-crypt key `default` maps to partition `default` and key `<key>` to partition
   `<key>` in lowercase. The key holders in `.git-crypt/keys` become members through your local
   gpg keyring, named from their email (or with `--name <FPR>=<name>`), and each partition's
   members are its key's holders plus you. A holder whose key cannot be exported is skipped with
   a warning.
4. Review `git status`, then commit. The command untracks the plaintexts (`git rm --cached`),
   removes the git-crypt tokens from `.gitattributes` files and deletes `.git-crypt/`. Teammates
   run `git amaga open` after pulling.

**git-crypt history stays readable.** Everyone who ever held a git-crypt key, including anyone
given an exported symmetric key, can still read the old versions, so treat those credentials as
exposed. The local git-crypt config (`filter.git-crypt.*`) and `.git/git-crypt/` are left alone, so
old commits still check out decrypted. It refuses if the repository already has secrets, if a
file is still locked, or if an imported file has staged changes, and then writes nothing.

## Branches and merge conflicts

Every command that works on secrets, except `status`, refuses while a `*.amaga` is unmerged.
Resolve a conflict with `git checkout --ours|--theirs -- f.amaga && git add f.amaga`, then
`git amaga open --force f` and re-apply your edit. Concurrent membership changes normally merge
cleanly; `status` then reports stale secrets until someone runs `rotate`.

Epoch files are named by their public key, so branches never collide on them. Two branches that
each run `rotate` or `user remove` conflict on a partition's `current-epoch`
(`.amaga/partitions/<p>/current-epoch`), and two that each run `user add` conflict on the epoch
file. Two branches that edit the same `members` file can conflict as text, and two that
`partition create` the same name conflict on both files. Every command, `status` included,
refuses until you take either side (`git checkout --ours -- <paths> && git add <paths>`, or edit
a `members` file and `git add` it) and run `git amaga rotate`. A secret's label travels with its
file, so `git mv` keeps its partition.
Details are in [plan.md](https://github.com/jmigual/git-amaga/blob/main/docs/adrs/plan.md) section 8.

## Security model and limitations

- People with read access to the repository but no member key cannot decrypt current secrets.
- A member can read exactly the secrets of the partitions that list them, because only those
  partitions' epoch keys are wrapped to them. Partition names, member lists and the label of each
  secret are readable by anyone with the repository.
- A new member can decrypt every version committed under the current epoch of their partition,
  including from before they joined. `rotate` before `user add` prevents that.
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
  command (plus one per older epoch a secret is still under), so a card set to touch-always
  needs one touch per command.
- Anyone holding an epoch's secret key reads every secret under it; `rotate` moves to a new one.
- After `user remove`, a partition you are not in stays stale until one of its members runs
  `rotate --partition <p>`; until then the removed key can still open its current epoch.
- Importing from git-crypt does not remove the old ciphertext from history: everyone who held a
  git-crypt key can still read it.
- Merging a branch that predates a removal brings secrets that are still under an older epoch;
  `status` reports them as stale and `rotate` flags every key of that epoch the new one lacks.
- `dismiss` is a human assertion recorded in the audit log, not a check.
- The full threat model is in [plan.md](https://github.com/jmigual/git-amaga/blob/main/docs/adrs/plan.md) section 4.

## Using the library

The `git-amaga-core` crate (`crates/core`) has one function per command. It takes the directory
to run in, returns typed results and never prints. It is published on
[crates.io](https://crates.io/crates/git-amaga-core):

```toml
git-amaga-core = "0.2"
```

```rust
use std::path::Path;

use git_amaga_core::cmd_status;

fn main() -> Result<(), git_amaga_core::Error> {
    let report = cmd_status(Path::new("."))?;
    println!("members: {}", report.members);
    for secret in &report.secrets {
        println!("{:?} {} ({}): {}", secret.level, secret.path, secret.partition, secret.messages.join("; "));
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
GIT_DIR=/nonexistent cargo test --workspace
```

The workspace has two crates: `crates/core` (library `git-amaga-core`) and `crates/cli` (binary
`git-amaga`). GPG tests skip with a notice when `gpg` is not installed, and the git-crypt
end-to-end test when `git-crypt` is not. Contributor and agent
conventions are in [`CLAUDE.md`](https://github.com/jmigual/git-amaga/blob/main/CLAUDE.md), design decisions in
[`docs/adrs/`](https://github.com/jmigual/git-amaga/blob/main/docs/adrs/README.md) and the specification in [`plan.md`](https://github.com/jmigual/git-amaga/blob/main/docs/adrs/plan.md).

## Reporting security issues

Report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/jmigual/git-amaga/security/advisories/new)
(see [SECURITY.md](https://github.com/jmigual/git-amaga/blob/main/SECURITY.md)), not in a public issue.

## License

MIT, see [LICENSE](https://github.com/jmigual/git-amaga/blob/main/LICENSE).
