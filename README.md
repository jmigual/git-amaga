# git-amaga

> **Status: in development.** Formats and commands may still change. Do not rely on it for
> production secrets yet.

`git-amaga` keeps secret files in a Git repository, encrypted with [age](https://age-encryption.org).
Every secret is an explicit file pair: the plaintext stays on your disk and is ignored by Git,
and the ciphertext next to it is what you commit.

```text
secrets/prod.env         plaintext, git-ignored, never committed by the tool
secrets/prod.env.amaga   age ciphertext, tracked and committed
```

There are no Git filters, so `git status` always shows exactly what will be committed. Members
can use an **age** key or a **GPG** key (including smartcards through gpg-agent). Removing a
member re-encrypts every secret without their keys and flags each secret they could read until
its real credential has been rotated.

## Install

The binary is self-contained. Its only runtime dependency is `git`; `gpg` 2.1+ is needed only by
members who use a GPG key.

- **Prebuilt binaries:** static Linux (`x86_64-unknown-linux-musl`) and Windows
  (`x86_64-pc-windows-msvc`) binaries are attached to each
  [GitHub release](https://github.com/jmigual/git-amaga/releases). Put the file on your `PATH` as
  `git-amaga` (`git-amaga.exe` on Windows); on Linux also `chmod +x git-amaga`.
- **From source** (Rust 1.88+):

  ```sh
  cargo install --locked --git https://github.com/jmigual/git-amaga
  ```

  A static Linux build: `rustup target add x86_64-unknown-linux-musl`, then
  `cargo build --release --target x86_64-unknown-linux-musl`.

With `git-amaga` on your `PATH`, `git amaga <command>` works too.

## Quick start

Run this inside a Git repository.

```sh
git amaga keygen                    # creates your age identity, prints your public key
git amaga init alice                # you become the first member
git amaga add secrets/prod.env      # encrypts it and git-ignores the plaintext
git add -A && git commit -m "Add prod secrets"
```

A second member joins:

```sh
git amaga keygen                    # bob: prints a "git-amaga user add <name> age1…" line on stderr; send it
git amaga user add bob age1…        # alice: adds bob, re-encrypts everything
git add -A && git commit -m "Add bob" && git push
git pull && git amaga open          # bob: decrypts the secrets to local plaintext
```

Edit a plaintext, then `git amaga seal` and commit the changed `.amaga` file.

## Useful commands

| Command | What it does |
|---------|--------------|
| `git amaga keygen [PATH]` | Create an age identity and print its public key |
| `git amaga init <name> [KEY…]` | Set up the repository with you as the first member |
| `git amaga add [--force] <path>…` | Encrypt a new secret and make sure its plaintext is ignored |
| `git amaga seal [--force] [<path>…]` | Re-encrypt local edits |
| `git amaga open [--force] [<path>…]` | Decrypt secrets to local plaintext |
| `git amaga close [<path>…]` | Delete local plaintext that is already sealed |
| `git amaga status` | Members, per-secret state, problems and secrets that need rotation |
| `git amaga user add <name> <KEY>…` | Add a member and re-encrypt every secret |
| `git amaga user remove <name>` | Remove a member, re-encrypt, flag exposed secrets |
| `git amaga rotate` | Re-encrypt everything with fresh keys; also finishes an interrupted run |
| `git amaga remove <path>…` | Stop managing a secret: deletes the `.amaga` file only, and the plaintext must be open and in sync so you keep a copy |

A `KEY` is an `age1…` public key, an exported `.asc` OpenPGP key file, or a GPG key ID,
fingerprint or email that the tool exports from your local keyring (for `init` and `user add`).
Without a `KEY`, `init` uses your age identity. `seal` and `open` refuse to overwrite diverged
files unless `--force` is given.

Every command that works on secrets, except `status`, refuses while a `*.amaga` is unmerged.
Resolve a conflict with `git checkout --ours|--theirs -- f.amaga && git add f.amaga`, then
`git amaga open --force f` and re-apply your edit (details in plan.md section 8).

If a sealed but uncommitted `.amaga` is discarded with `git checkout` or `git reset`, the
plaintext shows as outdated and is the only copy of that content: run `seal --force`, not
`open --force`.

## GPG members

- `git amaga init alice alice@example.org` or `git amaga user add bob <FINGERPRINT>` export the
  key from your keyring (`gpg --export-options export-minimal`); an `.asc` file works too. An
  email matching several keys is refused: pass a fingerprint.
- The tool encrypts to GPG members itself and only calls `gpg` to decrypt. Age members can seal
  for GPG members without having gpg installed.
- Decryption may prompt for a PIN or card. If there is no prompt, run `export GPG_TTY=$(tty)`.
  Smartcards and YubiKeys work through gpg-agent.
- A key is identified by its encryption subkey. Replacing the subkey makes secrets stale, and
  `rotate` then flags them as exposed to the old one.

## Removing someone

1. Revoke their repository access at the hosting provider.
2. `git amaga user remove charlie`, review `git status`, commit everything in one commit.
3. `git amaga status` lists every secret marked `NEEDS ROTATION`.
4. Rotate each real credential, edit the plaintext, `seal` and commit until nothing is flagged.

If a `.amaga` file is corrupt or not encrypted to you, `remove` cannot read it; drop it with
`git rm <path>.amaga`.

## How it works

Each `*.amaga` file is a standard age file encrypted to every member's key. Its encrypted header
records who it was encrypted to and who it has been exposed to. Members are the files in
`.amaga/users/` (`<name>.txt` for age keys, `<name>.asc` for GPG). Events are appended to
`.amaga/audit.jsonl`, and plaintext paths are kept in a managed `.gitignore` block.

**Escape hatch for age members:** the tool is not needed to read a secret.

```sh
age -d -i ~/.config/git-amaga/identity.txt secrets/prod.env.amaga | tail -n +2 > secrets/prod.env
```

(`tail` drops the one-line JSON header.) GPG members need the tool, since the `pgp` stanza is
specific to it.

**Threat model, in short**

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

## More documentation

- [`plan.md`](plan.md): the full v1 specification (formats, commands, threat model, workflows).
- [`docs/adrs/`](docs/adrs/README.md): the design decisions and why they were made.

## License

MIT, see [LICENSE](LICENSE).
