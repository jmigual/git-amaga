# ADR-0018: Importing a git-crypt repository

**Status:** Accepted (plan.md §7.5, §16)

## Context
Requested: a command that migrates a git-crypt repository. git-crypt encrypts files through a
clean/smudge filter (`filter=git-crypt` or `filter=git-crypt-<key>`), and wraps each symmetric
key to its GPG users in `.git-crypt/keys/<key>/0/<FINGERPRINT>.gpg`. A git-crypt key cannot be
rotated retroactively: everyone who held it can read the history.

## Decision
- The command is `git-amaga import-git-crypt [--name <FPR>=<name>]…`. It runs after `init`, in
  a repository with no secrets yet, and the actor must be a member of `default`.
- The repository must already be unlocked with `git-crypt unlock`. The command takes every
  tracked or untracked-but-not-ignored file whose `filter` attribute is `git-crypt` or
  `git-crypt-<key>` (`git ls-files`, with and without `--others --exclude-standard`, +
  `git check-attr`). An untracked file that matches a git-crypt pattern is imported too, because
  once the filter attribute is gone `git add -A` would stage it in clear. It refuses, listing
  the files, if any of them still
  starts with `\0GITCRYPT\0`. No git-crypt crypto is reimplemented, and git-crypt need not be
  installed.
- **Partitions (ADR-0017):** key `default` maps to partition `default`, and key `<key>` to
  partition `<key>` lowercased. A partition's members are that key's holders plus the importer.
  The importer holds every key, since every file decrypted.
- **Members:**
  - The holders are the fingerprints in the `.git-crypt/keys/<key>/0/*.gpg` file names.
  - A fingerprint that matches an existing member's primary key or subkey reuses that member.
  - Otherwise the key is exported from the local keyring (ADR-0013). A key that cannot be
    exported or used (not in the keyring, revoked, expired, or gpg missing) is skipped with a
    warning and never added.
  - The name comes from `--name`. Without it, the name is the local part of the email in the
    first user ID, normalised to the name rule, with `-2`, `-3`… appended on a collision; with
    no usable email it is `gpg-<last 16 hex digits>`.
- **Order of work:** every check runs before anything is written. Then the command:
  1. runs the ensure-ignored step for each plaintext;
  2. writes the new users and the partitions;
  3. writes the `.amaga` files;
  4. runs `git rm --cached` on the plaintexts;
  5. removes the git-crypt `filter`/`diff` tokens from tracked `.gitattributes` files, deleting
     any line left with no attributes;
  6. checks with `check-attr` that no imported path still has a git-crypt filter;
  7. deletes `.git-crypt/`.
- **Staging:** `git rm --cached` is the one exception to "never stage" (plan §3). Once the filter
  attribute is gone, each unlocked file becomes a tracked plaintext modification, and
  `git commit -a` would publish it. Untracking it in the same command closes that window (an
  untracked file needs no untracking). It only
  removes paths from the index; it never adds content.
- The local git config (`filter.git-crypt*`, `diff.git-crypt*`) and `.git/git-crypt/` are left
  alone, so old commits still check out decrypted.
- The importer reviews `git status` and commits. The command warns that everyone who ever held a
  git-crypt key can still read every imported file in history, including holders of exported
  symmetric keys, who leave no trace in `.git-crypt/keys`. Those credentials should be treated
  as exposed.

## Consequences
- Migrating needs only git, plus gpg when holders must be exported from the keyring.
- An interrupted import has committed nothing. The recovery is in plan §7.5.
- A holder whose key was not exported loses access. Re-add them with `user add` and
  `partition add`.
- Old commits still hold git-crypt ciphertext, readable with the old key. Exposure is printed,
  not recorded in `exposed_to`.
- When teammates pull the import, git deletes their working copies of the files it untracks.
  They then run `git-amaga open`.

## Alternatives considered
- Decrypting git-crypt blobs in-process (AES-CTR plus HMAC from git-crypt's key file): this
  reimplements crypto and needs the key file.
- Running `git-crypt unlock` from the tool: the user already does that, with their own
  credentials.
- Refusing when a holder's key cannot be exported: expired keys of former members would block
  the migration. Skipping is the fail-safe direction, because a missing member can be added
  later.
- Flagging every imported secret with a pseudo-member in `exposed_to`: the flag would persist in
  `status`, but it invents a member name. Deferred (plan §2, decision 22).
- Removing the local git-crypt config: old commits would then check out as ciphertext.
- Leaving the plaintext tracked and printing the `git rm --cached` hint: this leaves the window
  described under Staging open.
- Importing into a repository that already has secrets: holders added to `default` would
  silently gain access to its existing secrets.
