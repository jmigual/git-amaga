# ADR-0015: Epoch keys that are themselves age keys

**Status:** Accepted (supersedes ADR-0003; plan.md §5.6, §7.1)

## Context
With one age file per secret encrypted to every member (ADR-0003), a GPG member needs one
`gpg --decrypt` per secret: N secrets mean N calls and, with a touch-always card, N touches.
`user add` rewrites every secret. The fix must stay within standard age: no HKDF, no
hand-built AEAD, no custom container (the reasons ADR-0003 dropped the original epoch design).

## Decision
- An **epoch** is a fresh age X25519 key pair generated in-process (`x25519::Identity::generate`).
- `.amaga/epochs/<epoch public key>.age` holds its secret key: a standard age file encrypted to
  every member key (X25519 and `pgp` stanzas, ADR-0004). Payload: one JSON line
  `{"v":2,"members":{<name>:[<key>…]}}` (the member key set it was wrapped to), then the
  `AGE-SECRET-KEY-1…` line. The file name is unique per epoch, so branches never collide.
- `.amaga/current-epoch` is one line: the current epoch's public key. It is the only pointer;
  epochs are not derived from member sets.
- Every `*.amaga` is a standard age file encrypted **only** to the current epoch's public key.
  Its payload header keeps `exposed_to` and drops `recipients`: `{"v":2}` plus the body.
- A command unwraps the current epoch at most once (one gpg call for a GPG member), then
  decrypts secrets in-process. A secret that the current epoch cannot open is tried against
  the other epoch files, each unwrapped at most once.
- `user add` re-wraps the **current** epoch (same key) to the members plus the newcomer; no
  secret is rewritten. `user remove` and `rotate` create a new epoch, re-encrypt every secret
  and move the pointer last (ADR-0007).
- **Stale:** a secret under a non-current epoch, or a current epoch whose key set differs from
  `.amaga/users`. `add`, `seal`, `user add` and `dismiss` refuse while the current epoch is not
  up to date (its members differ from `.amaga/users`).
- Epoch files are never deleted.
- Format version 2. Repositories and secrets from 0.1.0 fail with an error; there is no migration.

## Consequences
- One gpg call (one card touch) per command; more only for secrets under older epochs.
- `user add` changes `.amaga/users/` and one epoch file. The newcomer can read every version of
  every secret committed under that epoch. Run `rotate` before `user add` to prevent that.
- Escape hatch for age members, two `age -d` commands (plan.md §4).
- `.amaga/epochs/` grows by one small file per `rotate`/`user remove` (and per interrupted
  run). Old epochs keep merged branch secrets and interrupted runs readable.
- Whoever holds an epoch secret key reads every secret under it. The key exists in plaintext
  only in memory (and in a private temporary file in the escape hatch).
- Two branches that each create an epoch conflict on `current-epoch`; two that each `user add`
  conflict on the epoch file. Take either side, then `rotate` (plan.md §8).
- The recipient set is recorded once per epoch, not per secret.

## Alternatives considered
- Per-file age (ADR-0003): N gpg calls, and `user add` rewrites everything.
- The original epoch design (HKDF, XChaCha20-Poly1305, custom container): hand-built crypto.
- Current epoch = the epoch whose member set equals `.amaga/users`: needs every epoch
  unwrapped (one gpg call each), and is ambiguous after a `rotate` with unchanged members.
- Pruning old epoch files: a secret merged from a branch, or left by an interrupted run, would
  become unreadable.
- Numbered epochs: two branches pick the same number.
- One wrap file per member (`epochs/<id>/<name>.age`): parallel `user add`s would merge
  cleanly, but at the cost of more files and a union rule, for a rare conflict.
- `user add` creating a new epoch: keeps old history from newcomers but rewrites every secret.
