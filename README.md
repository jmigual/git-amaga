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

Requires a recent stable Rust toolchain (1.88+) and `git`. GPG members also need `gpg` 2.1+.

```sh
cargo install --git https://github.com/jmigual/git-amaga
```

Prebuilt static binaries for Linux and Windows are planned. With `git-amaga` on your `PATH`,
`git amaga <command>` works too.

## Useful commands

| Command | What it does | State |
|---------|--------------|-------|
| `git amaga keygen [PATH]` | Create an age identity and print its public key | implemented |
| `git amaga init <name> [KEY…]` | Set up the repository with you as the first member | implemented |
| `git amaga add <path>…` | Encrypt a new secret and make sure its plaintext is ignored | implemented |
| `git amaga seal [<path>…]` | Re-encrypt local edits | implemented |
| `git amaga open [<path>…]` | Decrypt secrets to local plaintext | implemented |
| `git amaga close [<path>…]` | Delete local plaintext that is already sealed | implemented |
| `git amaga status` | Members, per-secret state, problems and secrets that need rotation | in development |
| `git amaga user add <name> <KEY>…` | Add a member and re-encrypt every secret | in development |
| `git amaga user remove <name>` | Remove a member, re-encrypt, flag exposed secrets | in development |
| `git amaga rotate` | Re-encrypt everything with fresh keys; also finishes an interrupted run | in development |
| `git amaga remove <path>…` | Stop managing a secret (deletes the `.amaga` file only) | in development |

A `KEY` is an `age1…` public key, an exported `.asc` OpenPGP key file, or a GPG key ID,
fingerprint or email that the tool exports from your local keyring (works for `init` now, and
for `user add` once it lands).

<!-- completed in plan step 11 -->

## How it works

- Each `*.amaga` file is a standard age file encrypted to every member's key. Its encrypted
  header records who it was encrypted to and who it has been exposed to.
- GPG members get an extra `pgp` stanza in the same file; the tool encrypts to it in-process and
  decrypts it by calling your `gpg`.
- Members are the files in `.amaga/users/` (`<name>.txt` for age keys, `<name>.asc` for GPG).
- The tool appends events to `.amaga/audit.jsonl` and keeps plaintext paths in a managed
  `.gitignore` block.

**Threat model, in short**

- People with read access to the repository but no member key cannot decrypt current secrets.
- A new member cannot decrypt history from before they joined.
- A removed member keeps whatever they already saw and can still decrypt old commits. Only
  rotating the real credential fixes that; the tool flags which secrets need it.
- age has no sender authentication: anyone with write access can replace member files or
  ciphertext. Use branch protection, review and signed commits.
- The audit log is informational; its integrity is whatever your Git history gives you.
- Plaintext that is tracked or not ignored is reported as critical.

<!-- completed in plan step 11 -->

## More documentation

- [`plan.md`](plan.md): the full v1 specification (formats, commands, threat model, workflows).
- [`docs/adrs/`](docs/adrs/README.md): the design decisions and why they were made.

## License

MIT, see [LICENSE](LICENSE).
