# git-amaga v1 plan

**Goal:** a single self-contained Rust binary that encrypts whole secret files in a Git repository
as explicit, tracked `*.amaga` ciphertext files next to ignored plaintext, with user add/remove,
key rotation, an audit log, and reliable tracking of which secrets still need their real
credentials rotated after someone lost access. Members hold either an age key or a GPG
(OpenPGP) key.

**Runtime dependencies:** the `git` executable. Members who decrypt with a GPG key also need `gpg`
(2.1+, with gpg-agent). Nobody needs the `age` CLI, and age-only members never need `gpg`.

**Decision records:** the decisions below are summarised as ADRs in [`README.md`](README.md).

## 1. Changes from the original plan

| # | Change | Reason |
|---|--------|--------|
| 1 | Each secret is a standard `age` file encrypted to the current **epoch**'s X25519 public key. An epoch's secret key is itself an age file, `.amaga/epochs/<public key>.age`, encrypted to every member key; `.amaga/current-epoch` names the current epoch (ADR-0015, superseding per-file age, ADR-0003). Dropped HKDF, XChaCha20-Poly1305 and the custom binary container of the original epoch design. | Standard age only, with no hand-built crypto composition. One gpg call per command instead of one per secret, and `user add` rewrites one file instead of every secret. Trade-offs are covered in section 4. |
| 2 | Replaced `content_generation` / `last_exposure_*` with one rule: every epoch records the member key set it is wrapped to. Rewriting a secret into an epoch that lacks some keys of its old epoch, without changing the plaintext, adds those keys to `exposed_to`. A plaintext change clears `exposed_to`. | Gives the same results for the original scenarios. It also handles cases the original missed: secrets merged in from a branch that still include a removed user, interrupted removals, and hand-edited membership. |
| 3 | Dropped the transaction journal and the `recover` command. Every secret is decrypted first, then membership is changed, the new epoch is written, secrets are rewritten and `.amaga/current-epoch` moves last. If the run is interrupted, `status` reports "stale recipients" and running `rotate` again finishes the job. | `rotate` is idempotent, and Git already keeps the previous state. No local journal is needed. |
| 4 | Audit log is now plain append-only JSONL with `merge=union`. Dropped `seq`, the hash chain, `audit verify` and `audit show`. | The hash chain breaks on any two branches that both append (both lines get `seq` N+1 with the same `prev_hash`). Git commits already provide tamper evidence relative to a known head. Union merge verified with git 2.x. |
| 5 | Dropped the local `.git/amaga/config.toml` and `actor_user_id`. The identity path comes from `git config amaga.identity`. The actor is the member whose public key matches the loaded identity. | `.git` is a file in worktrees and submodules. Git config is the native mechanism and can be overridden with `git -c`. |
| 6 | Added `keygen`, which generates an X25519 identity in-process. | Without it, users would need `age-keygen` installed, and the binary would not be self-contained. |
| 7 | Added a three-way plaintext check (base hash, ciphertext, local plaintext). The base hash is stored per worktree under `git rev-parse --git-path amaga-base`. | **Bug in the original:** after `git pull` brings in a rotated credential, `seal` of a stale local plaintext would write back the old (exposed) value and *clear* the needs-rotation flag. |
| 8 | `.gitattributes` gets `*.amaga binary`. | Without `-text`, `core.autocrlf` can change line endings in the age header of small ciphertexts that contain no NUL byte, which corrupts them. `-merge` also stops conflict markers being written into ciphertext. |
| 9 | Users are stored in `.amaga/users/<name>.txt`, in the standard age recipients-file format (one `age1…` key per line). Several keys per user (laptop and desktop) are supported. Dropped user UUIDs. | Readable in diffs, works with `age -R`, and multi-device support comes free. Names are restricted to lowercase so they cannot collide on case-insensitive filesystems. |
| 10 | Dropped secret UUIDs and rename tracking. | Exposure state lives inside the file, so it moves with `git mv`. UUIDs only existed for the epoch/HKDF binding. |
| 11 | Dropped `config.toml`, a configurable suffix, `inspect`, `status --json`, the multi-level exit codes, `user list`, fuzzing, zeroization and `--allow-self-removal`. | YAGNI. `status` shows members and per-secret metadata. The only parser we own is one JSON line. Zeroizing is theatre when the plaintext is written to disk anyway. Self-removal is simply allowed. |
| 12 | `open` with no paths opens every secret. Temp files use one ignored suffix, `.amaga-tmp`. The `.gitignore` block is append-only and merged with `merge=union`; `add`, `seal`, `open` and `status` check that every managed plaintext path is ignored. | Matches `seal`/`close`. A crash cannot leave an un-ignored plaintext temp file. Deleting an entry would un-ignore a teammate's plaintext after a pull, and a renamed secret (`git mv`) would otherwise get an un-ignored plaintext. |
| 13 | `add` warns if the plaintext path already appears in Git history, and refuses without `--force` if `<path>.amaga` does. | The first warning prevents a false sense of safety for values that are already public. The refusal stops a delete-then-re-add from silently dropping `exposed_to`. One `git rev-list` call each. |
| 14 | Specified the release build: static musl binary on Linux, `+crt-static` on Windows MSVC. | This is what "self-contained" means in practice. |
| 15 | Removed duplicated rule lists (invariants, definition of done, guidance, error list). Each rule now appears once, next to the behaviour it governs. | Shorter, and nothing can drift out of sync. |
| 16 | GPG members: each epoch file stays one age file, and a GPG member gets an extra `pgp` stanza holding the age file key encrypted to their OpenPGP key (5.2.1). Encryption is in-process with rPGP; decryption runs `gpg --decrypt`. | Requested: the user's own keys are GPG (smartcards via gpg-agent), with age as an option. One file format and one set of rules; `age -d` keeps working for age members; age-only members never need gpg. Considered: a separate `.gpg` file per secret (two formats, two exposure states) and OpenPGP as the outer format (loses the age escape hatch). |
| 17 | A GPG key is identified by its **encryption subkey** fingerprint (`pgp:<FPR>`), not the primary. | Replacing a lost card's subkey is then a key change: secrets go stale and `rotate` flags exposure, exactly as for a removed age key. Extending expiry keeps the fingerprint, so it changes nothing. |
| 18 | GPG key expiry is checked only at `init`/`user add`. Structure, signatures and revocation are checked on every load. | Loading stays deterministic (no clock), and an expired key still decrypts in gpg. See decision 9. |
| 19 | A `KEY` can be a GPG key ID, fingerprint or email: the tool looks it up in the local keyring and exports it export-minimal (7.4). `keygen` prints the `user add` line for the new age key. | Requested: users should not type `gpg`/`age` commands, and the tool then always stores the right export format. ADR-0013. |
| 20 | Added `dismiss [--user <name>]… [<path>…]`: removes members from `exposed_to` without a plaintext change and audits `exposure.dismissed` (ADR-0016). | Requested: a removed member's keys can be known to be destroyed, and a routine key swap (decision 5) should not leave flags that only a content change clears. |
| 21 | Format version 2 (secret and epoch headers `"v":2`). Repositories and secrets written by 0.1.0 fail with an error; there is no migration. | The project has no users yet. |
| 22 | **Partitions** (ADR-0017): named member lists, each with its own epoch chain under `.amaga/partitions/<p>/`. Every secret carries an unencrypted, MAC-authenticated `amaga-partition` label stanza, which is the truth. A partition is chosen at `add` (`--partition`, else the `amaga-partition` attribute, else `default`), and changed only by `partition move`. The 0.2.0 layout changes (`.amaga/current-epoch` → `.amaga/partitions/default/current-epoch`), still format version 2, with no migration. | Requested: per-file-set access such as `production`/`staging`. The label lets non-members see where a secret belongs and lets `rotate` tell "mine" from "not mine" without decrypting. A careless `.gitattributes` edit cannot move a secret into a wider partition. |
| 23 | **`import-git-crypt`** (ADR-0018) migrates an unlocked git-crypt repository: keys become partitions, `.git-crypt/keys` fingerprints become GPG members through the keyring lookup, and the plaintexts are encrypted, untracked with `git rm --cached` and ignored. | Requested. It relies on `git-crypt unlock` and reimplements no git-crypt crypto. |

## 2. Open decisions for the user

Defaults are already chosen in this plan. Each item below can be flipped.

1. **`user add` reuses the current epoch (ADR-0015).** The newcomer can read every version committed under that epoch, back to the last `rotate` or `user remove`. Run `rotate` before `user add` to prevent that. The alternative, a new epoch per `user add`, rewrites every secret.
2. **SSH `ssh-ed25519` recipients are deferred.** age's `ssh` feature adds `aes`, `cbc` and `bcrypt-pbkdf`, and decrypts `ssh-rsa` identities in-process. `rsa 0.9` is already in the tree via `pgp`, but only for public-key encryption and signature verification. RUSTSEC-2023-0071 (Marvin) is a timing attack on RSA *private-key* operations, which this tool never performs (gpg does GPG decryption). `ssh-rsa` identities would change that.
3. **Release targets:** `x86_64-unknown-linux-musl` and `x86_64-pc-windows-msvc`. Possible additions: macOS (aarch64/x86_64) and aarch64 Linux.
4. **`status` exit code:** "needs rotation" alone exits 0. It is a known, tracked condition and could last weeks. Everything else that `status` flags exits 1.
5. **Changing an existing member's key:** edit `.amaga/users/<name>.txt` or replace `<name>.asc`, then run `rotate`. Removing any key marks secrets exposed to that member, which is conservative: correct for a lost device, noisy for a routine swap. When the old key is known to be safe, `dismiss --user <name>` clears the flags (ADR-0016). The same rule means a removed user who is later re-added stays in `exposed_to` until each file's content changes or the flag is dismissed.
6. **Audit log as a separate file vs `git log` only.** Kept because the goal names it. It is informational (unsigned, editable) and is not a security control.
7. **Dropping `audit verify` and the hash chain.** Both were in the original scope. The chain cannot survive two branches that both append (change 4), and a writer who can rewrite history can recompute it anyway. Restoring it means either forbidding parallel security changes or adding a merge-repair command.
8. **`open` vs `unlock`.** The commands stay `open`/`seal`, which pair with `close`; `unlock` and `lock` are visible clap aliases of `open` and `seal`.
9. **Expired GPG keys (change 18).** By default, a key that expires after `user add` is still encrypted to. The alternative is to refuse, as `gpg -e` does. That blocks every `seal` and `rotate` for the whole team until the member re-exports an extended key. It also makes loading depend on the clock.
10. **Confirming a looked-up GPG key (change 19).** By default the tool prints the fingerprint and user ID it used and does not prompt. The alternative is a yes/no prompt before writing, which blocks scripting. The printed line, the audit event and the committed `.asc` diff are the review points.
11. **Fetching GPG keys from the network.** By default the lookup reads only the local keyring. Fetching from a keyserver or WKD (`gpg --locate-keys`) is deferred (section 13): the key would still need out-of-band verification, which the user does by importing it first.
12. **Bare `dismiss` is refused.** At least one path or `--user` is required, so one mistyped command cannot clear all tracking. The alternative is "no arguments means everything", as for `open`.
13. **Old epoch files are kept forever.** A secret merged from an older branch, or left by an interrupted run, stays readable. Pruning is deferred (section 13); each file is a few hundred bytes per member.
14. **Writes while the epoch is stale.** `add`, `seal`, `user add` and `dismiss` refuse whenever the current epoch's key set differs from `.amaga/users`, even when members were only added. Allowing the additions-only case would save one `rotate`, at the cost of a second rule. With partitions this applies per partition (5.7).
15. **`default` has an explicit member list (ADR-0017).** `user add` joins `default` unless `--partition` is given, so a member can see only `staging`. The alternative is an implicit `default` that contains every user: one rule fewer, but every restricted member then forces every other secret out of `default`.
16. **`user remove` re-encrypts only the actor's partitions.** The name leaves every partition's `members` file, and partitions the actor is not in stay stale, with a warning, until one of their members runs `rotate`. The alternative, refusing unless the actor is in all of them, deadlocks when nobody is.
17. **A partition is chosen at `add` only.** After that the label is the truth, and `partition move` changes it. A set `amaga-partition` attribute that differs from the label is a `status` error, never an action. The alternative, the attribute deciding on every `rotate`, lets one `.gitattributes` edit widen access.
18. **Secrets in other partitions are skipped silently** when a command runs without paths, and `status` shows them as `not a member` at level ok (exit 0). An explicit path is `NotInPartition`.
19. **`import-git-crypt` needs a repository with no secrets** (just after `init`). In a repository that has secrets, the holders added to `default` would silently gain access to them.
20. **`import-git-crypt` skips holders whose key cannot be exported** (not in the keyring, revoked, expired, no gpg), and lists them in a warning. The alternative is refusing, which lets the expired keys of former members block the migration. Skipping never grants access; `user add` restores a missing member.
21. **`import-git-crypt` leaves the local `filter.git-crypt*`/`diff.git-crypt*` config and `.git/git-crypt/` alone**, so old commits still check out decrypted. Teammates may remove theirs.
22. **Imported secrets are not flagged in `exposed_to`.** The command prints that git-crypt history stays readable by every former key holder. The alternative is a pseudo-member such as `git-crypt` in `exposed_to`: it persists in `status` until `dismiss`, but it invents a member name.
23. **Member names for imported keys.** `--name <FPR>=<name>` overrides the name. Without it, the name is the local part of the first user ID's email, normalised to the name rule (`-2`, `-3`… on collision), or `gpg-<last 16 hex>` when there is no email.

## 3. Principles and scope

- **Explicit files, no Git filters.** `secrets/prod.env` (plaintext, ignored) sits next to `secrets/prod.env.amaga` (age ciphertext, tracked). `git status` always shows exactly what will be committed.
- **Never stage, commit, or silently overwrite/delete plaintext.** Commands change the working tree and print which repository files changed. The one exception is `import-git-crypt`, which runs `git rm --cached` on the plaintexts it imports (ADR-0018): once the git-crypt filter is gone, each one would otherwise be a tracked plaintext modification.
- **Whole-file semantics.** Exposure and "changed" are per file, not per value inside a file. Status says "content changed since exposure", never "credential rotated".
- **Re-encryption is not credential rotation.**
- **Established crypto only:** the age format via the `age` crate. OpenPGP encryption via `pgp` (rPGP), and OpenPGP decryption via the user's `gpg`. Nothing hand-rolled. The only extension is the `pgp` stanza, written through age's public `Recipient`/`Identity` traits.
- **One crate, no traits of our own, no async, no daemon.** Run the `git` and `gpg` CLIs as subprocesses (no libgit2, no gpgme). Never through a shell.
- **Fail closed.** Decrypt/auth failure, unknown header version, invalid user file → error with a remediation hint. Never write partial plaintext. Panics are bugs.

Out of scope for v1: per-file ACLs (partitions, ADR-0017, cover named sets of files), rotating external credentials, a key server/KMS, merge helpers, history rewriting, signed audit, malicious authorised users or malicious repository writers, symlinked secrets (rejected), passphrase-protected identity files.

## 4. Threat model

**Guarantees**
- People who can read the repository without a member identity cannot decrypt current secrets.
- A member who is not listed in partition P cannot decrypt secrets under P's current epoch, because it is not wrapped to their keys (5.7). The label check (`NotInPartition`) is a convenience; the epoch enforces access.
- After `user remove X`, every secret in a partition the actor is in is re-encrypted to a new epoch whose key is not wrapped to X. Partitions the actor is not in are named in a warning and stay stale until one of their members runs `rotate` (decision 16).
- A newly added member cannot decrypt ciphertext from epochs that ended before they were added (decision 1).
- Modified ciphertext fails authentication (age payload AEAD and header MAC), for secrets and epoch files alike.
- Every secret that a removed key could have read, through an epoch wrapped to that key, is flagged until its content changes or the flag is dismissed.
- Plaintext that is tracked or not ignored is reported as critical.

**Limitations (README and `--help`)**
- A removed user keeps any plaintext they saw, and can still decrypt historical commits from epochs they were in. Only rotating the external credential fixes that. The tool can only flag it.
- A member added by `user add` can decrypt every version committed under the current epoch, including versions from before they joined (decision 1).
- age has no sender authentication. Anyone with write access can replace user files, epoch files or `current-epoch`, or forge ciphertext. Use branch protection, review and signed commits. The original design had the same exposure via `users/` and `key.age`.
- Partition names, their member lists, and the partition of each secret (its label stanza) are readable without a key.
- A compromised member identity exposes everything that member can read. A leaked epoch secret key exposes every secret version under that epoch; `rotate` moves to a new one.
- The audit log is informational. Its integrity is whatever Git history gives you. `dismiss` is a human assertion recorded there, not a check.
- After `import-git-crypt`, every former holder of a git-crypt key (including holders of exported symmetric keys) can still read the imported files in old commits. Only rotating the credentials fixes that (ADR-0018).
- GPG keys come only from the committed `.asc` files. `init`/`user add` may export a key from the local public keyring (7.4), but loading never reads the keyring, and the tool never contacts a keyserver. A revocation or a new subkey takes effect when the member commits a re-exported `.asc` and someone runs `rotate`.
- A GPG key that expires after `user add` is still encrypted to (decision 9).
- GPG decryption trusts the `gpg` on PATH and its agent. It costs one `gpg` call per partition a command touches (its current epoch), plus one per older epoch while a secret is still under it. A card set to touch-always needs one touch per partition.
- Manual escape hatch for age members, two `age -d` commands (the epoch key goes to a private temporary file outside the repository, so it cannot be committed; delete it afterwards):

  ```sh
  k=$(mktemp)
  age -d -i ~/.config/git-amaga/identity.txt ".amaga/epochs/$(cat .amaga/partitions/default/current-epoch).age" | tail -n +2 > "$k"
  age -d -i "$k" secrets/prod.env.amaga | tail -n +2 > secrets/prod.env
  rm "$k"
  ```

  `tail` drops the one-line JSON header of each payload. A secret in another partition needs that partition's `current-epoch` (its label: `grep -a -m1 '^-> amaga-partition' f.amaga`), and a secret under an older epoch needs that epoch's file. GPG members cannot decrypt without the tool, because the age CLI cannot take a file key that gpg has unwrapped.

**Epoch keys vs per-file age (decision 1, ADR-0015)**

Epoch keys gain:
- One gpg call (one card touch) per command instead of one per secret.
- `user add` rewrites one epoch file instead of every secret.
- Secrets are one X25519 stanza each, whatever the team size.

Epoch keys lose:
- History privacy from newcomers under the current epoch (decision 1).
- A two-step escape hatch instead of one `age -d`.
- Two more kinds of file (`.amaga/epochs/`, a `current-epoch` per partition, 5.7); the directory grows by one file per `rotate`/`user remove`.
- Recipient-set visibility without decrypting is still missing (only the partition label is readable, 5.7): X25519 stanzas are anonymous, so the member set is recorded inside the encrypted epoch payload, and a secret's epoch is found by trying keys.

## 5. On-disk formats

```text
repo/
├── .amaga/
│   ├── users/alice.txt          # age recipients file: "age1…" per line, '#' comments, blank lines ok
│   ├── users/bob.asc            # one armored OpenPGP public key (gpg --export --armor --export-options export-minimal)
│   ├── partitions/default/members        # member names, one per line (5.7)
│   ├── partitions/default/current-epoch  # one line: the partition's current epoch public key
│   ├── partitions/production/…  # the same two files for every other partition
│   ├── epochs/age1….age         # one per epoch: its secret key, age-encrypted to its partition's members (5.6); never deleted
│   └── audit.jsonl              # append-only, merge=union
├── .gitattributes               # "*.amaga binary", ".amaga/audit.jsonl merge=union", ".gitignore merge=union", ".amaga/epochs/* binary"
├── .gitignore                   # managed block, see 5.4
└── secrets/prod.env.amaga       # tracked ciphertext with a partition label; secrets/prod.env is ignored plaintext
```

### 5.1 Users

- A member is `<name>.txt` and/or `<name>.asc`. The name (file stem) must match `[a-z0-9][a-z0-9._-]{0,63}` (lowercase, so names cannot collide on case-insensitive filesystems). Any other file in `users/` is an error.
- `.txt` content: one `x25519::Recipient` per line. Strip `\r` on read (autocrlf).
- `.asc` content: exactly one armored transferable public key. On every load (rPGP 0.20 names):
  - `SignedPublicKey::from_string_many` yields exactly one key.
  - `verify_bindings()` succeeds. It also rejects third-party certifications, so the error hint is `gpg --export --armor --export-options export-minimal <fpr>`. Verified: a key certified by another key fails, and its export-minimal export passes.
  - The primary key has no `KeyRevocation` signature in `details.revocation_signatures`.
  - The **encryption subkey** is the newest (`created_at`) subkey that has no `SubkeyRevocation` signature, whose newest `SubkeyBinding` signature has `key_flags().encrypt_comms() || encrypt_storage()`, and whose `algorithm().can_encrypt()` is true. If there is none, error with the hint `gpg --quick-add-key <fpr> default encr`. Encrypting to the primary key is not supported.
  - Expiry is not checked here (change 18).
- Key string (used in headers and comparisons): `age1…`, or `pgp:<FPR>` with `<FPR>` the encryption subkey fingerprint as uppercase hex (`format!("{:X}", subkey.fingerprint())`, the same form gpg prints).
- Validation errors:
  - any `.txt` line that does not parse, or any `.asc` that fails the checks above;
  - a member with zero keys;
  - the same key string, or the same OpenPGP primary fingerprint, appearing twice anywhere across all users;
  - no user files at all.
- The set of user files *is* the current membership. The current epoch records which of these keys it is wrapped to (5.6); when the two differ, the epoch is stale.

### 5.2 Secret file (`*.amaga`)

A standard binary age file encrypted to exactly one key, the X25519 public key of its partition's current epoch (5.6). Its header also holds one **label stanza** naming the partition (5.7):

```text
-> amaga-partition production
<empty body line>
```

- Written by `secret::Label(<p>)`, a type implementing `age::Recipient`. Its `wrap_file_key` ignores the file key and returns one `Stanza { tag: "amaga-partition", args: vec![p], body: vec![] }` with an **empty** label set, like X25519, so age accepts the mix (5.2.1).
- Read without any key by `secret::label_of(ciphertext)`. The first line must be `age-encryption.org/v1`. Header lines are scanned up to the `---` line, and a line starting with `-> ` opens a stanza (base64 body lines never contain `-`, `>` or a space). There must be exactly one `amaga-partition` stanza, with one argument that matches the name rule (5.1). Otherwise the result is `PartitionLabelInvalid(path)`.
- The header MAC covers the label, so decrypting a file whose label was changed fails authentication. age clients, `age -d` included, ignore the stanza.

The decrypted payload is:

```text
{"v":2,"exposed_to":{"charlie":["age1…"]}}\n
<body: the plaintext bytes, arbitrary binary>
```

- The header is one compact JSON line (serde_json never emits a raw newline).
- Parse rules: split at the first `\n`, use `deny_unknown_fields`, `v` must be `2` or it is an error (`UnsupportedVersion`; 0.1.0 secrets have `v` 1) and the file is not modified. `exposed_to` is omitted when empty, so a new secret's header is `{"v":2}`.
- `exposed_to` is a `BTreeMap<String, BTreeSet<String>>` (user name → key strings, 5.1).
- The header does not name the epoch: a secret is under the epoch whose key decrypts it (5.6).
- "Stale": the secret is under an epoch other than its partition's current one, or that current epoch is not up to date (5.7). Compare keys only; names are just labels.

### 5.2.1 `pgp` stanza

Used in epoch files only (5.6); a secret has a single X25519 stanza plus its label (5.2).

```text
-> pgp <FPR>
<age base64 body: a binary OpenPGP message, PKESK v3 to the subkey + SEIPD v1 (AES-256),
 whose literal data is the 16-byte age file key>
```

- **Encrypt:** a recipient type implementing `age::Recipient`, holding the selected subkey (`SignedPublicSubKey`) and `<FPR>`. `wrap_file_key(&self, &FileKey) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError>` returns one `age_core::format::Stanza { tag: "pgp", args: vec![fpr], body }` and an **empty** label set. X25519 also returns an empty set, and age only rejects recipients whose label sets differ, so the two can be mixed. Build the body with `MessageBuilder::from_bytes("", key.expose_secret().to_vec()).seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256)`, then `.encrypt_to_key(&mut rng, &subkey)?`, then `.to_vec(&mut rng)?`, using `rand::thread_rng()`. Map rPGP errors to `EncryptError::Io(io::Error::other(..))`. Use SEIPD v1 because GnuPG does not implement RFC 9580 SEIPD v2.
- **Decrypt:** a `GpgIdentity { fprs }` implementing `age::Identity`. `fprs` holds **all** subkey fingerprints of every held member's `.asc`, so files written before a subkey change still match. `unwrap_stanza(&self, &Stanza) -> Option<Result<FileKey, DecryptError>>` returns `None` unless the tag is `pgp` and there is exactly one argument, which is in `fprs`. Otherwise it runs gpg (7.3) and requires exactly 16 output bytes, returning `FileKey::new(Box::new(bytes))`. Failures are `Some(Err(DecryptError::Io(io::Error::other(GpgError{..}))))`. `GpgIdentity` overrides `unwrap_stanzas` to try every `pgp` stanza in the header instead of stopping at the first match, returning the first success, or else the first failure, or else `None`, so one held key's gpg error cannot mask another held key's success.
- age clients ignore stanzas they do not know: `x25519::Identity::unwrap_stanza` returns `None` for any other tag, and `age -d` follows the spec. age adds its own random "grease" stanza, which `GpgIdentity` ignores.

### 5.3 Audit log

One JSON object per line, written by the tool and never parsed by it:

```json
{"time":"2026-10-02T12:34:56Z","actor":"alice","event":"user.removed","user":"charlie"}
```

- Events:
  - `init`
  - `user.added` / `user.removed` (with `user`)
  - `rotated` (with `partition`), one per re-encrypted partition
  - `partition.created` (with `partition`); `partition.member_added` / `partition.member_removed` (with `partition` and `user`), one per member, also written by `partition create`, `user add` and `import-git-crypt`
  - `secret.moved` (with `path` and `partition`, the new one)
  - `secret.added` / `secret.updated` / `secret.removed` (with `path`)
  - `exposure.dismissed` (with `path` and `user`), one per secret and member (`dismiss`, ADR-0016)
- `init` and `user.added` also carry `gpg_fpr` (primary fingerprint) and `gpg_uid` (first user ID) when the member has an `.asc`, read from the validated key whether it came from a file or from the keyring (7.4).
- `secret.updated` means the plaintext changed. It is never written for a re-encryption.
- Time is UTC RFC 3339, from `SystemTime`, using a ~15-line days-to-civil conversion with a unit test. This avoids a dependency for one formatter.

### 5.4 `.gitignore` and `.gitattributes`

`init` appends the `.gitattributes` lines if they are missing. It also creates a block in the root `.gitignore`:

```gitignore
# BEGIN git-amaga
*.amaga-tmp
/secrets/prod.env
# END git-amaga
```

- **Ensure-ignored step** (used by `add`, `seal`, `open`): if `git check-ignore -q --no-index -- <path>` already succeeds, do nothing. Otherwise insert a root-anchored entry (`/` separators; backslash-escape `\ * ? [ ! #` and trailing spaces) on the line before the last `# END git-amaga`, or append a new block if there is none. Then re-check, and abort if the path is still not ignored (for example because of a negation rule elsewhere). `--no-index` also works for paths that do not exist yet.
- The block is **append-only**. No command deletes entries, so a teammate's plaintext stays ignored after they pull a `remove`. Stale entries are harmless.
- Lines outside the block are kept byte-for-byte. The tool never parses the block; `check-ignore` is the only source of truth.
- `.gitignore merge=union` means two branches that each `add` a secret merge without conflict. Verified: both inserted lines land inside the block and the shared `# END` line stays once. Union also applies to the user's own lines. For an ignore file that can only add ignore rules back, which is acceptable.

### 5.5 Local state (not committed)

- **age identity:** `git config --type=path amaga.identity` (any scope, `~` expanded) holds the path to an age identity file. If it is unset, use the `keygen` default path when that file exists. Only `AGE-SECRET-KEY-1…` lines are accepted, and the file may contain several. Parse each line with `x25519::Identity::from_str`, so the public keys are available for matching the actor.
- **GPG identity:** probed only when no age identity matches a member, so age users never start gpg. For each `.asc` member, run `gpg --list-secret-keys --with-colons <PRIMARY-FPR>`. Exit 0 means held, card stubs included; any other exit means not held (verified: exit 2 for a public-only key and for an unknown key). If spawning fails with `NotFound`, gpg is absent and every GPG member is skipped silently.
- **Actor:** the member matching an age identity, or else the first held GPG member by name. If there is none, the error is `NotAMember`. It lists each member with its key kinds and the remediation: `keygen` and have a member run `user add`, set `amaga.identity`, or import your GPG secret key / insert your card. It adds "gpg not found on PATH" when `.asc` members exist and gpg was absent.
- **Decryption identities:** age identities first, then one `GpgIdentity` for the held members. They unwrap epoch files only (5.6); secrets are decrypted in-process with the epoch's identity. age takes the first identity that claims any stanza (`find_map` over identities in `Decryptor::decrypt`), so gpg runs only when no age identity matches.
- **Base hashes:** stored at `$(git rev-parse --path-format=absolute --git-path amaga-base)`. Verified: in a linked worktree this resolves to `.git/worktrees/<wt>/amaga-base`, i.e. per worktree.
- Base file format: lines of `<sha256-hex> <repo-relative-path>`, rewritten atomically. It records the SHA-256 of the body the local plaintext was last synchronised with.

### 5.6 Epochs (ADR-0015)

- An epoch is a key pair from `x25519::Identity::generate()`. Its id is its public key string (`age1…`, lowercase bech32, so safe on case-insensitive filesystems and unique across branches).
- **Epoch file** `.amaga/epochs/<age1…>.age`: a standard binary age file encrypted to every member key, X25519 stanzas for `.txt` keys and `pgp` stanzas (5.2.1) for `.asc` keys. Payload:

  ```text
  {"v":2,"members":{"alice":["age1…"],"bob":["pgp:97509ABD…"]}}\n
  AGE-SECRET-KEY-1…\n
  ```

  - Header rules as in 5.2. `members` is the `Recipients` map (5.1) of the keys the file is wrapped to. It is the exposure record (6.1); names are labels.
  - Body: exactly one `AGE-SECRET-KEY-1…` line (`\r` stripped). Its public key must equal the file name, otherwise `EpochInvalid`.
  - Every epoch belongs to one partition (5.7); its `members` are that partition's member keys when it was written. Nothing in the file names the partition.
- Written by `init`, `rotate`, `user remove`, `partition create` and `partition remove`; rewritten in place (same key, more members) only by `user add` and `partition add`. Never deleted (decision 13).
- **Pointer** `.amaga/partitions/<p>/current-epoch`, one per partition: one line, the current epoch's public key (`\r` stripped). A missing `default` pointer → `NoEpoch` (a 0.1.0 repository, a pre-partition 0.2.0 layout, or an interrupted `init`). Unparsable, or naming a missing epoch file → `EpochInvalid`.
- Names in `.amaga/epochs/` other than `<age1…>.age` are ignored, for example an `.amaga-tmp` left by an interrupted write.
- **Unwrapping** uses the member identities (5.5). Each epoch is unwrapped at most once per command, the first time the command needs it. A secret is tried first against the current epoch of the partition in its label. A failure there aborts the command with `EpochUndecryptable`, naming the epoch file and, for a gpg failure, the member (`status` reports it per secret instead, 7.2). A secret that this epoch cannot decrypt (`NoMatchingKeys`) is tried against the other epoch files in name order, those an age identity unwraps first and those that need gpg after (a smartcard prompts once per gpg unwrap). Epochs without a stanza for the actor fail without spawning gpg. If none decrypts it, that secret fails.
- **Up to date:** defined per partition in 5.7. Otherwise the partition's epoch is stale.
- `.gitattributes` gets `.amaga/epochs/* binary` for the same reason as `*.amaga binary` (change 8). `current-epoch` stays text, so a conflict on it is visible in diffs.

### 5.7 Partitions (ADR-0017)

- One directory `.amaga/partitions/<p>/` per partition. `<p>` follows the name rule (5.1). Every entry of `.amaga/partitions/` must be such a directory holding both `members` and `current-epoch`; anything else is `PartitionInvalid`. Other names inside a partition directory are ignored, such as an `.amaga-tmp` left by an interrupted write. `init` creates `default`, which always exists; there is no command to delete a partition.
- `members`: one member name per line; `\r` is stripped, blank lines are ignored, and duplicates collapse. The tool writes the names sorted, ending with `\n`. A line that is not a valid name (5.1) is `PartitionInvalid("<p>: <reason>")`, with the hint to edit the file. A valid name that is not a user grants nothing, and `status` warns about it (`Warning::UnknownMember { partition, name }`). This is the state a hand-deleted user file or a merged `user remove` leaves, and it makes the partition stale instead of blocking every command (ADR-0012). At least one listed name must be a user, else `PartitionInvalid`, because an epoch wrapped to nobody can never be opened.
- The **key set** of P is the keys of the users listed in P. P is **up to date** when the `members` key set of P's current epoch equals P's key set. Membership states intent; access is cryptographic: a newly listed name reads P only after P's current epoch is re-wrapped (`partition add`, `user add`) or rotated.
- The actor **is in P** when P's `members` lists the actor's name (5.5).
- A secret's partition is its label (5.2). A label naming no existing partition is `UnknownPartition`.
- **Choosing at `add`:** `--partition <p>`, else the value of `git check-attr amaga-partition -- <plaintext path>`, else `default`. An attribute that is `set` or `unset` without a value, or whose value is not a valid name, is `PartitionAttributeInvalid(path)`. After `add`, nothing reads the attribute except the `status` mismatch check (7.2).
- No new `.gitattributes` line: `members` and `current-epoch` stay text, so conflicts on them are visible.

## 6. Core rules (pure functions, unit-tested)

### 6.1 Exposure rule: `next_header(old: Option<(&Header, &Recipients)>, plaintext_changed: bool, new_members: &Recipients) -> Header`

`old` pairs the file's current header with the `members` of the epoch that decrypted it; `new_members` are the `members` of the epoch the file is written to (5.6).

```text
exposed_to = if old is None or plaintext_changed: {}
             else: old.header.exposed_to ∪ { (user, key) in old.members | key ∉ keys(new_members) }
```

Every secret write goes through this function (`dismiss` then removes the dismissed names, ADR-0016). Consequences:

- `user remove` flags every existing secret.
- `rotate` changes nothing; `user add` rewrites no secret.
- An edited and sealed file is cleared.
- A secret added after a removal is never flagged.
- A file merged in from a branch, still under an epoch wrapped to the removed user, gets flagged on the next `rotate`.
- Rewriting under the same epoch (e.g. `dismiss` of an up-to-date secret) adds nothing.
- `partition remove P bob` flags bob only in P's secrets (ADR-0017).
- `partition move Q f` flags the keys of f's old epoch that Q's current epoch lacks. Moving into a wider partition flags nobody.

### 6.2 Plaintext state: `plaintext_state(P: Option<&[u8]>, C: &[u8], B: Option<Hash>) -> State`

P = local plaintext, C = decrypted ciphertext **body** (after the header line), B = base hash, h = SHA-256.

| Condition | State | Meaning / action |
|-----------|-------|------------------|
| P absent | `Closed` | fine |
| P == C | `InSync` | fine |
| P ≠ C, B == h(C) | `Modified` | local edit; `seal` |
| P ≠ C, B == h(P) | `Outdated` | repository version changed (pull/merge, or a `git checkout`/`reset` of the `.amaga` file); `open` replaces the local copy, `seal --force` keeps it |
| otherwise | `Conflict` | both changed or base unknown; `seal --force` keeps local, `open --force` takes the repository version |

## 7. Commands

The binary is named `git-amaga`, so `git amaga …` works when it is on PATH.

Path handling:
- Path arguments can be either the plaintext path or the `.amaga` path.
- Convert them to repository-relative paths with `git rev-parse --show-prefix` plus lexical normalisation, not `canonicalize`. This avoids `\\?\`, 8.3-name and symlinked-directory mismatches on Windows.
- On Windows, convert `\` to `/`.
- Reject paths that leave the repository, contain control characters, lie under `.git/` or `.amaga/`, or whose plaintext name ends in `.amaga` or `.amaga-tmp`.
- The managed secret list is `git ls-files -z --cached --others --exclude-standard -- '*.amaga'`, deduplicated (an unmerged path appears once per stage) and filtered to files that exist. In no-argument mode, listed paths that fail the validation above are skipped with a warning on stderr.
- For `seal`, `open` and `close`, an explicit path whose `<path>.amaga` does not exist is refused (not a managed secret; use `add`).
- Every command except `status` refuses while `git ls-files -u -- '*.amaga'` is non-empty. `status` lists the unmerged files.
- Every command that loads the repository, `status` included, refuses while `git ls-files -u -- .amaga/partitions .amaga/epochs` is non-empty: `UnmergedEpoch`, listing the paths, with the hint `git checkout --ours -- <paths> && git add <paths>`, then `git-amaga rotate` (section 8). A conflicted `members` file is resolved by editing it, as a text file, before `git add`.
- In no-argument mode the list leaves out, without a warning, secrets whose label names a partition that does not list the actor (5.7). Reading a label needs no key.

Every ciphertext, plaintext and base-file write goes through one helper:
1. Write `<path>.amaga-tmp`. On Unix, plaintext temp files are created with mode `0600`.
2. `sync_all`.
3. `std::fs::rename` (replaces the target on Windows too).

Commands that need an identity load it once (5.5), and the actor comes from it. Encrypting a secret needs only the public key in `current-epoch`, and wrapping an epoch only the member keys; neither needs gpg. Decryption unwraps epochs as in 5.6.

**Partition access:** `Context::decrypt` reads the label first. If the actor is not in that partition, it returns `NotInPartition` (naming the partition and the path) without trying any epoch. Commands that act on a partition by name (`rotate --partition`, `partition add`/`remove`/`move`, `add --partition`, `user add --partition`) need the actor in it too. Being listed in `members` is the check; the epoch still enforces it cryptographically (section 4).

**Stale guard:** a command that writes into partition P (`add`, `seal`, `dismiss`, `user add`, `partition add`, `partition move`) first requires P to be up to date (5.7). It checks every partition it will write into before writing anything, else `EpochStale(p)` ("partition 'p' differs from its current epoch; run `git-amaga rotate --partition p` first"). This unwraps P's current epoch. It keeps new content away from a key that was removed by hand (ADR-0012), and keeps `user add`/`partition add` from re-wrapping an epoch that a removed key can still open.

`KEY` arguments (`init`, `user add`) are classified in this order (ADR-0013):
1. Starts with `age1`: an age recipient.
2. An existing file whose name ends in `.asc`: an armored OpenPGP public key file.
3. Anything else: a GPG key spec (key ID, fingerprint, email or user ID) looked up in the local keyring (7.4).

At most one OpenPGP key (file or lookup) is allowed per member. It must pass 5.1 and the add-time check: neither the primary key nor the selected subkey may be expired, judged from the `key_expiration_time()` of the newest self-signature plus the key's `created_at()`. The `.asc` (file contents or gpg's export) is stored byte-for-byte. For each OpenPGP key, print `<name>: GPG key <PRIMARY-FPR> "<first user ID>"`.

| Command | Behaviour |
|---------|-----------|
| `keygen [PATH]` | Generate `x25519::Identity`. Default path is `home_dir()/.config/git-amaga/identity.txt`. Refuse to overwrite. Write `# public key: age1…` followed by the secret key (0600 on Unix). If `amaga.identity` is unset in global config, set it. Print the public key on stdout (kept alone so scripts can capture it), then on stderr: `to join a repository, send this to a member: git-amaga user add <name> age1…` with the real key. |
| `init <name> [KEY…]` | Requires a Git repo and no `.amaga/`. With no `KEY`, use the configured age identity's public keys (error if there is none). `KEY`s follow the rules above, so `init alice alice@example.org` works with a key in the local keyring. Writes the `.gitattributes` lines and the `.gitignore` block (idempotent), then `users/<name>.txt` and/or `users/<name>.asc`, the first epoch file wrapped to that member, `partitions/default/members` (the name), `partitions/default/current-epoch`, and the audit `init` event. An interruption after `users/` leaves `NoEpoch`; nothing is committed yet, so delete `.amaga/` and rerun. |
| `add [--force] [--partition <p>] <path>…` | Choose the partition (5.7); it must exist and list the actor. Path must be a regular file (not a symlink), inside the repo, and not tracked (`git ls-files --error-unmatch`). If tracked, print the `git rm --cached -- <path>` remediation and stop; never run it. Refuse if `<path>.amaga` already exists. Warn if the plaintext path appears in history (`git rev-list -n1 --all -- <path>`). If `<path>.amaga` appears in history, refuse unless `--force`, and point to `git checkout <rev> -- <path>.amaga` followed by `seal` to keep its exposure state; `--force` says that exposure history is dropped. Stale guard for the partition. Run the ensure-ignored step. Encrypt to the partition's current epoch, with its label, using `next_header(None, …)`. Record the base. Audit `secret.added`. |
| `seal [--force] [<path>…]` | No paths means every secret whose plaintext exists, in the actor's partitions. Stale guard for each selected secret's partition. Each secret keeps its partition. Run the ensure-ignored step. Decide by plaintext state: `InSync` → no-op (ciphertext bytes untouched, even under an older epoch; the base is re-recorded when it differs). `Modified` → encrypt to its partition's current epoch with `plaintext_changed = true`, record base, audit `secret.updated`. `Outdated` / `Conflict` → refuse unless `--force`. When `--force` clears a non-empty `exposed_to`, warn that the needs-rotation flag is being cleared and that the local copy may hold the old value. |
| `open [--force] [<path>…]` | No paths means all. Decrypt and authenticate fully, refuse if the plaintext path is tracked in the index (same remediation as `add`), then run the ensure-ignored step, before writing anything. `Closed` / `Outdated` → write the plaintext. `InSync` → no-op, except the base is re-recorded when it differs. `Modified` / `Conflict` → refuse unless `--force`. Record base. |
| `close [<path>…]` | Delete the plaintext only when `InSync`. Drop the base entry. |
| `remove <path>…` | Needs at least one path; duplicates are removed. Refuse unless every plaintext exists and is `InSync` (so the user keeps a copy; `open` or `seal` first), checked for all paths before anything is deleted. Delete the `.amaga` file and the base entry. Leave the plaintext and its ignore entry alone. Audit `secret.removed`. If the `.amaga` cannot be read or decrypted (corrupt, not encrypted to you, symlink), the error says to drop it with `git rm <path>.amaga`. |
| `user add [--partition <p>]… <name> <KEY>…` | Partitions default to `default`; each must exist, list the actor and pass the stale guard. Refuse if `users/<name>.txt` or `.asc` exists (key changes: decision 5), or if the name is still listed in any `members` file (`UserStillListed`, with the hint `partition remove <p> <name>`): a merge can leave a removed member's name in a partition, and a different person given that name would silently join it. Resolve `KEY`s with the same code as `init` (age key, `.asc` file, or keyring lookup). Validate (5.1 + add-time expiry). Then, in this order: write the member file, audit `user.added`; then per partition, add the name to `members`, audit `partition.member_added`, and re-wrap the partition's current epoch (same key) to its members including the newcomer, atomically. No secret is rewritten (decision 1). Interrupted after the member file: `partition add <p> <name>` finishes it. Interrupted after a `members` file: that partition is stale, and `rotate` finishes the job without flagging anyone. |
| `user remove <name>` | Must exist: a user file, a line in some `members` file, or (after an interrupted run) their name in a current epoch the actor can unwrap. Refuse with `LastMember { user, partition }` if they are the only member of any partition. The files being removed are not validated, so a revoked or broken key can still be removed. Re-encrypt (7.1) every partition that lists the actor and either lists them or has a current epoch wrapped to them (their name, or any of their keys), so a rerun after an interruption or a hand edit of `members` still locks them out. The change step removes the name from the `members` file of each partition it re-encrypts, then deletes the user files. Each partition that lists them but not the actor (and so cannot be unwrapped) gets `Warning::PartitionNotRotated` (decision 16); it is unlisted last, after the pointers, so a rerun of `user remove` still reports it (recover by rerunning `user remove`, not `rotate`). |
| `rotate [--partition <p>]…` | Re-encrypt (7.1) the named partitions, each of which must exist and list the actor. With none, re-encrypt every partition that lists the actor; each other partition gets `PartitionNotRotated`. Audit `rotated` per partition. This is also the recovery command. |
| `partition create <p> <member>…` | Valid name, else `InvalidPartitionName`. `PartitionExists` if the directory exists. At least one member, each a user (`UserNotFound`). The actor need not be listed. Writes a new epoch wrapped to the members' keys, then `members`, then `current-epoch` last. Audit `partition.created`, plus `partition.member_added` per member. Interrupted before the pointer: loading fails with `PartitionInvalid` naming it; nothing is committed yet, so delete the directory and rerun. |
| `partition add <p> <member>…` | P exists and lists the actor. Each name is a user (`UserNotFound`) not yet in P (`AlreadyInPartition`). Stale guard for P. Writes `members`, audits `partition.member_added` per name, then re-wraps P's current epoch (same key). No secret is rewritten (decision 1, per partition). |
| `partition remove <p> <member>…` | P exists and lists the actor. Each name is listed in P (`NotAPartitionMember`), and at least one member stays (`LastMember`). Re-encrypt P (7.1); the change step writes `members` and audits `partition.member_removed` per name. Self-removal is allowed. |
| `partition move <p> <path>…` | P exists and lists the actor. Stale guard for P. Decrypt every selected secret first; the actor must be in each source partition. Secrets already in P are left untouched. For the others: `next_header(Some((old, old epoch members)), false, P's current members)`, encrypt to P's current epoch with label P, write atomically, audit `secret.moved`. Plaintext and base are never touched. Prints `moved <path>`. |
| `import-git-crypt [--name <FPR>=<name>]…` | See 7.5 (ADR-0018). |
| `dismiss [--user <name>]… [<path>…]` | ADR-0016. Refuse with `DismissNoTarget` when neither a path nor `--user` is given. No paths means every secret in the actor's partitions; no `--user` means every member in each secret's `exposed_to`. Stale guard for each selected secret's partition. Decrypt every selected secret first (abort before writing if any fails). A `--user` found in no selected secret's `exposed_to` is `NotExposed`; nothing is written. For each secret with something to dismiss: `next_header(Some((old, old members)), false, current members)`, remove the dismissed names, encrypt to its partition's current epoch, write atomically, audit `exposure.dismissed` per name. Other secrets are untouched. Plaintext and base are never touched. Prints `dismissed <path>`. |
| `status` | See 7.2. |

### 7.1 Re-encrypt (shared by `rotate`, `user remove` and `partition remove`)

Works on a set S of partitions, each listing the actor (ADR-0017).

1. Read and decrypt **every** secret whose label is in S into memory, under whichever epoch the actor holds (5.6), keeping the `members` of the epoch that decrypted each one. If any fails, abort before writing anything and list the files that failed. Secrets of other partitions are read only for their label.
2. The change step: `user remove` removes the name from the `members` file of each partition in S, deletes the user files and appends the audit event (partitions the actor is not in are unlisted after step 5); `partition remove` writes P's `members` and its audit events.
3. For each partition in S, in name order, take the current key set (5.7), generate a new epoch and write its file, wrapped to that key set, with `members` = that key set.
4. For each secret, write `encrypt_to(new epoch of its partition, its label, next_header(Some((old, old members)), false, new members), body)` atomically.
5. Write each partition's `current-epoch`, in name order.

If a run is interrupted:
- After step 2: the membership change is on disk and the partitions in S are stale.
- After step 3: epoch files exist that nothing points to. They are kept (decision 13).
- During step 4 or 5: some secrets are under a new epoch that is not yet current, so they are stale.
- In every case `status` reports stale secrets and rerunning `rotate` completes the work. Exposure marking is still correct, because it comes from each file's own header and the members of the epoch that decrypted it.
- If the actor removed themselves, they are no longer a member and get `NotAMember`. Another member reruns `rotate`.

There is no clean-tree precondition. Unsealed local edits are unaffected, because re-encryption uses the ciphertext payload and plaintext hashes do not change.

Ceiling: all secrets are held in memory at once. Stream per file if anyone stores large files.

### 7.2 `status`

Requires an identity. Prints the members, then `partition <p>: <names>` for every partition, then one line per secret, problems first. A secret outside `default` is shown as `<path> (<p>)`, so a single-partition repository prints its secret lines as before. The current epoch of each partition the actor is in is unwrapped once, when the first of its secrets needs it. A failure becomes that secret's error, not an abort, so other partitions are still reported.

**Errors (exit 1):**
- Invalid user or partition files (a load error, as for every command).
- `.amaga` paths that `git check-attr text` does not report as `unset`.
- A label that is missing or invalid, or that names an unknown partition (5.2, 5.7).
- A set `amaga-partition` attribute of the plaintext path that differs from the label: `in partition <label>, but .gitattributes says <attr>; run git-amaga partition move <attr> <path>, or fix .gitattributes` (decision 17).
- A secret that fails to decrypt (no epoch the actor holds opens it, tampered, unknown `v`, its partition's current epoch cannot be unwrapped).
- Unmerged `.amaga` files.
- **Critical:** plaintext tracked (`git ls-files`), or any managed plaintext path not ignored (`check-ignore --no-index`), checked whether or not the plaintext exists.
- Stale recipients: the secret is under an epoch other than its partition's current one, or that partition is not up to date (5.7). Message `stale recipients; run git-amaga rotate`, plus ` --partition <p>` outside `default`.
- Plaintext state `Modified`, `Outdated` or `Conflict`, each with its action.

**Warning (exit 0):** `NEEDS ROTATION: exposed to charlie`, taken from `exposed_to`.

**Ok:** a secret whose partition does not list the actor shows `not a member`. Only the checks that need no key run for it: `text`, label, attribute, tracked and ignored.

Usage errors exit 2 (clap's default).

### 7.3 Running gpg

- Used only to unwrap an epoch file (5.6), so at most once per epoch per command.
- Decrypt: `gpg --quiet --max-output 16 --decrypt`. The stanza body goes to stdin, which must be closed before waiting. Capture stdout and stderr. `--max-output` bounds the output (verified: gpg exits 2 when it is exceeded).
- Do **not** pass `--batch` or `--pinentry-mode`. gpg-agent must be able to run pinentry for the PIN or for an "insert card" prompt. Piping gpg's stdin and stderr does not affect pinentry.
- On non-zero exit, or output that is not 16 bytes: `GpgError { fpr, stderr }`, reported with the epoch file and the member's name. Pass gpg's stderr through verbatim (for example `decryption failed: No secret key`, or `Operation cancelled` when the card prompt is dismissed), followed by the fixed hint "is the card inserted, and can gpg-agent show a PIN prompt (`export GPG_TTY=$(tty)`)?". Do not parse gpg's messages.
- `gpg` is resolved on PATH; the program name is not configurable (section 13).

### 7.4 Looking up a GPG key (`KEY` rule 3)

1. Spec: the argument as given. If it contains `@`, has no `>` or whitespace and does not start with one of gpg's own prefix characters (`= @ * + # & <`), wrap it as `<spec>`: gpg matches a bare email as a substring (`alice@x` also finds `malice@x`), and `<…>` as an exact address.
2. `gpg --list-keys --with-colons -- <spec>`. Each `pub` record starts a key; the **first** `fpr` record after it holds the primary fingerprint (field 10), and later `fpr` records belong to subkeys. `uid` records give user IDs (field 10, shown as gpg escapes them). Parse this in a pure function, unit-tested on canned output.
   - `pub` records that can never be added are ignored before counting: validity (field 2) `r` (revoked) or `e` (expired), or `D` (disabled) in the capabilities (field 12). So an old revoked key and a new key under one email resolve to the new key.
   - Non-zero exit or no usable `pub` record: `GpgKeyNotFound`: "'<spec>' is not in your local gpg keyring (import it with `gpg --import`, or pass an exported `.asc` file)", plus gpg's stderr. If every match was ignored, the message says "only revoked, expired or disabled keys match". If the spec ends in `.asc` or contains a path separator, the error is `KeyFileNotFound` instead: it is not an existing file and not in the keyring.
   - More than one usable `pub`: `GpgKeyAmbiguous`, listing `<FPR> <first user ID>` for each key, with the hint to pass a fingerprint.
3. `gpg --export --armor --export-options export-minimal -- <FPR>`. Empty output is `GpgKeyNotFound`. The output then goes through 5.1 and the add-time check like a file would.
4. Spawning gpg fails with `NotFound`: `GpgNotFound`: "gpg not found on PATH; pass an exported `.asc` file instead".

No `--batch`/pinentry concerns: neither call touches secret keys. Nothing is fetched from the network (decision 11).

### 7.5 `import-git-crypt` (ADR-0018)

**Checks.** All of these run before anything is written, and each failure is one `Error` variant:
1. Load as usual (identity, actor). The actor must be in `default`, and `default` must pass the stale guard.
2. No managed secret exists yet (decision 19): `ImportNotFresh`.
3. Files: `git ls-files -z` plus `git ls-files -z --others --exclude-standard` (an untracked file that matches a git-crypt pattern would otherwise be added in clear once the filter is gone), then `git check-attr -z --stdin filter` over them. A file is imported when the value is `git-crypt` (key `default`) or `git-crypt-<key>`. If none is: `NothingToImport`.
4. Each file must pass path validation as a plaintext path (7), be a regular file in the working tree (`NotARegularFile`), and have no `<path>.amaga` (`CiphertextExists`). Files whose content starts with the 10 bytes `\0GITCRYPT\0` are collected over all files into `GitCryptLocked(paths)`, with the hint `git-crypt unlock`.
5. No imported path may have staged changes (`git diff --cached --name-only -z`): `ImportStagedChanges(paths)`. `git rm --cached` would refuse them later. Nor unstaged ones (`git diff --name-only -z`): `ImportUnstagedChanges(paths)`. The recovery below (`git reset --hard`) would discard them.
6. Partitions: each key maps to `default`, or to `<key>` lowercased. The name must match the name rule (`InvalidPartitionName`), no two keys may map to one name (`InvalidPartitionName`, naming both), and a partition other than `default` must not exist yet (`PartitionExists`).
7. Holders: for each key that imported files use, the file names `.git-crypt/keys/<key>/0/<FPR>.gpg`. `<FPR>` is 40 hex digits, uppercased; any other name is skipped with a warning. Each `--name <FPR>=<name>` must name a holder fingerprint (`ImportUnknownFingerprint`), with a valid, unused name (`InvalidMemberName`, `UserExists`) that no `members` file lists (`UserStillListed`, as for `user add`). For each distinct fingerprint:
   - A member whose `.asc` has it as its primary or a subkey fingerprint is reused.
   - Otherwise it goes through `keyring::resolve(dir, &[fpr])` (7.4, add-time expiry included). An error becomes `Warning::KeySkipped { fpr, error }`, and the fingerprint is dropped (decision 20).
   - The name is the `--name` value, else `derive_name(first user ID, fpr, taken)` (decision 23). This is a pure function: it takes the address inside the last `<…>`, or the user ID itself if it contains `@`, and keeps the part before `@`. It lowercases that, maps every character outside `[a-z0-9._-]` to `-`, drops leading characters until one is `[a-z0-9]`, and truncates to 64. If the result is empty it uses `gpg-<last 16 hex, lowercase>`. While the name is taken (existing users, names already derived, and names any `members` file lists), it appends `-2`, `-3`…, shortening the base to stay within 64.
   - The resulting users must pass `users::check` (5.1).
8. Each partition's members are its key's remaining holders, plus the actor.

**Writes**, in this order:
1. The ensure-ignored step for every plaintext. The files are still tracked, which ignore rules do not affect.
2. New users: for each, the member file, then audit `user.added` (with `gpg_fpr`/`gpg_uid`).
3. `default`: the `partition add` sequence for its new names. Every other partition: the `partition create` sequence.
4. Every file: encrypt its working-tree bytes to its partition with `next_header(None, …)`, write `<path>.amaga`, record the base, audit `secret.added`. The history checks of `add` are skipped, because every path is in the git-crypt history by definition.
5. One `git --literal-pathspecs rm --cached -q --pathspec-from-file=- --pathspec-file-nul` over every imported path that is tracked (ADR-0018 explains why).
6. Every tracked `.gitattributes` (`git ls-files -z -- .gitattributes '*/.gitattributes'`) outside `.git-crypt/`: drop the tokens `filter=git-crypt`, `filter=git-crypt-*`, `diff=git-crypt` and `diff=git-crypt-*`. Delete a line left with only its pattern, and keep every other byte (comments, other attributes, CRLF). This is a pure function. A quoted pattern (`"a b" filter=…`) is one token.
7. `git check-attr -z --stdin filter diff` over every imported path and its `.amaga` path. A value starting with `git-crypt` is `GitCryptAttributeRemains(paths)`, with the hint to remove it by hand (for example from `.git/info/attributes`). Everything else is already done at this point.
8. Delete `.git-crypt/` from the working tree. Its index entries show as deleted, for the user to stage.

The local git config and `.git/git-crypt/` are not touched (decision 21).

**Result:** `Imported { members, created, changed, warnings }`:
- `members` holds `(name, GpgKey)` for each new member.
- `created` holds the new partitions.
- `changed` holds the `.amaga` paths.
- `warnings` always ends with `Warning::GitCryptHistory`.

**Interrupted:** nothing is committed. Commit `init` before importing. Then `git reset --hard && git clean -fd -- .amaga '*.amaga'` restores the starting state (`clean` without `-x` keeps ignored files), and the import can be rerun.

## 8. Branches and merges

- `*.amaga` files are `binary`, so concurrent edits produce a normal conflict with "ours" left in the working tree and no markers. To resolve: `git checkout --ours|--theirs -- f.amaga && git add f.amaga` (verified: `checkout --theirs` alone leaves the path unmerged), then `git-amaga open --force f` and edit / `seal`. The three-way check makes the stale-plaintext case visible.
- Epoch files are named by their public key, so epochs created on two branches never collide, and none is ever deleted. A secret that arrives under any of them stays readable by that epoch's members.
- **Secrets added on a branch under an older epoch:** after the merge they are under a non-current epoch. `status` reports them stale, and `rotate` re-encrypts them and flags every key of their epoch that the new epoch lacks. This is correct whenever that branch was pushed while those keys had access.
- **Two branches that each `rotate` or `user remove`:** both moved `current-epoch` (a text conflict), and both rewrote every secret (binary conflicts). Every command refuses until the epoch paths are resolved (7). Take either side of `current-epoch`, and either side of each secret, `git add` them, then `rotate`. Exposure stays correct: each file keeps its own `exposed_to`, and both epochs' member sets are on disk.
- **A member added on a branch** (`user add`) rewrites the current epoch file. If the other side did not touch that file, the merge is clean. If the other side moved `current-epoch` (a `rotate` or `user remove`), the result is stale (the newcomer is in `.amaga/users` but not in the current epoch) and `rotate` fixes it. If both sides ran `user add`, the epoch file conflicts: take either side, `git add`, then `rotate`. The side not taken loses its newcomer from that epoch's recorded `members`; that newcomer is not flagged for secrets still under that epoch if later removed. `rotate` right after the merge leaves no secret under it.
- **A member who is not in an old epoch** (added after it ended) cannot decrypt secrets still under it. `open`/`status` report the failure for those files, and their `rotate` aborts before writing (7.1). Any member of that epoch runs `rotate`; after that the newcomer reads everything.
- Concurrent edits to `.amaga/users/` touch different files and normally merge cleanly. After the merge the epoch is stale until someone runs `rotate`.
- **Partitions (ADR-0017).** Everything above holds per partition.
  - A label travels inside its file, so `git mv` keeps a secret's partition.
  - `partition add` on one branch and `rotate --partition p` on another touch `members` and `current-epoch` respectively, so they merge cleanly. The partition is then stale until `rotate --partition p`.
  - Two branches that edit the same `members` file can conflict as text. Every command refuses (7) until the file is edited, `git add`ed, and the partition rotated.
  - Two branches that `partition create` the same name conflict on both files (add/add): take one side of both, then `rotate --partition p`.
  - A secret moved on one branch and edited on another is a normal `.amaga` conflict.
- `.gitignore` and `audit.jsonl` merge by union (verified). Lines from both sides are kept, ordered by side rather than by time. If a hosting platform's merge ignores `merge=union`, resolve the conflict by keeping both sides' lines.
- A sealed but uncommitted `.amaga` file discarded with `git checkout`/`reset` makes the plaintext `Outdated`. The plaintext is then the only copy of that content: `seal --force` it rather than `open` (README).

## 9. Removal workflow (README)

1. Revoke the person's repository access at the hosting provider.
2. `git-amaga user remove charlie`, review `git status` (the user file, the `members` files, a new `.amaga/epochs/` file and `current-epoch` per partition, and every secret in those partitions), and commit everything in one commit. If a warning names a partition you are not in, one of its members runs `git-amaga rotate --partition <p>` and commits; until then that partition is stale and charlie's key still opens it.
3. `git-amaga status` lists every secret marked `NEEDS ROTATION`.
4. Rotate each real credential, edit the plaintext, `seal`, and commit, until nothing is flagged.
5. If charlie's keys are known to be destroyed, or a secret needs no rotation, `git-amaga dismiss --user charlie [<path>…]` clears the flag instead of step 4, and commit. The audit log records who dismissed it.

Adding a member without giving them the history of the current epoch: `git-amaga rotate`, then `user add` (decision 1). For another partition: `rotate --partition <p>`, then `user add --partition <p>` or `partition add`.

## 10. Rust implementation

### 10.1 Dependencies (checked on crates.io, 2026-10-02)

| Crate | Version | Use |
|-------|---------|-----|
| `age` | `0.12.1`, default features only | `x25519::Identity::generate` / `to_public` / `FromStr`, `Encryptor::with_recipients(iter of &dyn Recipient) -> Result<_, EncryptError>` with `wrap_output` followed by a **mandatory** `finish()`, and `Decryptor::new_buffered(&[u8])?.decrypt(iter of &dyn Identity)` → `read_to_end`. `Identity::to_string()` returns a `SecretString`; use `age::secrecy::ExposeSecret`. |
| `age-core` | `0.12.0` | `format::{Stanza, FileKey}`, which `age` does not re-export. Must stay on the same minor version as `age` uses (0.12), so only one copy is compiled. Bump the two together. |
| `pgp` (rPGP) | `0.20.0`, `default-features = false` | `SignedPublicKey`, `MessageBuilder`, `SymmetricKeyAlgorithm`, `SignatureType`, `KeyDetails` (5.1, 5.2.1). Dropping the default `bzip2` feature is fine: we only encrypt, without compression. MSRV 1.88. |
| `rand` | `0.8` | `thread_rng()` for rPGP, which needs `rand 0.8` `CryptoRng + Rng`. Already in the tree via `age` and `pgp`. |
| `clap` | `4.6.7` (`derive`) | CLI |
| `serde` | `1.0.229` (`derive`) / `serde_json` `1.0.151` | header and audit line |
| `sha2` | `0.10` | base hashes. 0.11.0 is the latest, but pin 0.10 because `age 0.12.1` already depends on it, so no second copy is compiled. |
| `thiserror` | `2.0.21` | typed errors |
| `tempfile` | `3.27.0` (dev-dependency only) | test repositories |

Not used: `toml`, `uuid`, `zeroize`, `hkdf`, `chacha20poly1305`, `chrono`, `dirs`, `gpgme`, `sequoia-openpgp` (LGPL). `std::env::home_dir` builds without a deprecation warning on rustc 1.99. Edition 2024.

Licenses: `age`, `age-core`, `pgp` and `rand` are `MIT OR Apache-2.0`. Checked over their resolved tree with `cargo metadata`: everything is MIT, Apache-2.0, BSD-2/3, Zlib, Unicode-3.0 or Unlicense, except `self_cell` (via age's i18n), which is `Apache-2.0 OR GPL-2.0-only`; we take Apache-2.0. The tree has no `-sys` crates, so the musl static build is unaffected. `pgp` adds about 80 crates to compile. `cargo audit` will report RUSTSEC-2023-0071 for `rsa`; that ID is not exploitable here (decision 2).

### 10.2 Layout

Library plus a thin binary. Unit tests live in each file; integration tests live in `tests/`.

File locations are superseded by the workspace split (section 14): the library is `crates/core/src/`, the binary `crates/cli/src/main.rs`.

```text
src/main.rs      parse args (clap), call lib, map Error -> exit code
src/lib.rs       command functions (one per subcommand)
src/git.rs       run git with args (never through a shell; `--` before paths; -z output), toplevel/prefix/git-path helpers
src/paths.rs     arg → repo-relative path, .amaga mapping, .gitignore block edit + escaping, atomic write
src/users.rs     load/validate users dir (.txt + .asc), Recipients map, member keys as age recipients
src/gpg.rs       .asc parse/validate/subkey selection, pgp Recipient, GpgIdentity (gpg --decrypt), held check, keyring lookup (7.4)
src/identity.rs  keygen, load age identity, GPG probe, actor lookup
src/secret.rs    Header, encode/decode payload, age encrypt/decrypt, next_header, plaintext_state, base file
src/audit.rs     append event, RFC 3339 formatting
src/error.rs     Error enum (thiserror), one variant per user-actionable failure
```

### 10.3 Release build

`Cargo.toml`:

```toml
[profile.release]
lto = true
strip = true
```

- **Linux:** `cargo build --release --target x86_64-unknown-linux-musl`. Accept when `file` reports "statically linked".
- **Windows:** in `.cargo/config.toml`, set `[target.x86_64-pc-windows-msvc] rustflags = ["-C", "target-feature=+crt-static"]`. Accept when `dumpbin /dependents` shows no `vcruntime*.dll`.
- **CI:** `cargo fmt --check`, `cargo clippy -- -D warnings` and `cargo test` on Linux and Windows.

## 11. Tests

**Unit tests** (beside the code):
- `next_header`: every row of 6.1, including a re-added user, a rename where the same key now sits under a new name, and a rewrite under the same epoch (adds nothing).
- `plaintext_state`: every row of 6.2.
- Header parsing rejects missing `\n`, unknown fields (including 0.1.0's `recipients`), and `v != 2` (a 0.1.0 header gives `UnsupportedVersion(1)`).
- Epochs (5.6): generate, wrap to two X25519 members and unwrap with each, `members` preserved; a third identity gets `NoMatchingKeys`; a body whose public key differs from the file name, or with zero or two key lines, is `EpochInvalid`; the pointer parses with CRLF, garbage is `EpochInvalid`, a missing pointer is `NoEpoch`; listing ignores names that are not `<age1…>.age`; an epoch wrapped to X25519 + `pgp` unwraps with the x25519 identity alone.
- `dismiss` selection: no `--user` dismisses every name; named users are removed only where present; a secret under an older epoch keeps the exposure its epoch change adds for names not dismissed.
- Label (5.2): a secret encrypted with `Label("production")` gives `label_of` = `production` and decrypts with the epoch identity alone. Zero labels, two labels, a non-age input, and a label argument outside the name rule are each `PartitionLabelInvalid`. A file whose label bytes were changed fails to decrypt.
- Partitions (5.7): `members` loads with CRLF, blank lines and duplicates. A valid name that is not a user loads, but is left out of the key set and reported. An invalid name line, an empty `members`, a list with no user, an invalid directory name, a plain file in `partitions/`, and a missing `current-epoch` are each `PartitionInvalid`. A missing `default` is `NoEpoch`. `write_members` writes sorted names.
- Import pure functions (7.5):
  - Attribute stripping: a git-crypt-only line is deleted; `*.key filter=git-crypt diff=git-crypt -text` becomes `*.key -text`; named-key tokens go; CRLF, comments and unrelated lines are kept byte for byte; a quoted pattern stays one token.
  - `derive_name`: an email; no email; uppercase and non-ASCII characters; a leading `.`; collisions giving `-2` and `-3`; truncation to 64.
  - Filter value to key: `git-crypt`, `git-crypt-Prod`, `other`, `unspecified`.
  - Holder listing from a temp `.git-crypt/keys` tree: non-hex names are skipped, and directories other than `0` are ignored.
- Users parsing: comments, CRLF, duplicate key across users, invalid names.
- `.gitignore` entry insertion (existing block, no block) and escaping.
- Path normalisation and rejection (`\`, `.git/`, `.amaga/`, `.amaga`/`.amaga-tmp` names).
- RFC 3339 formatting against known timestamps.
- `KEY` classification (7, rules 1–3), email wrapping, and `--with-colons` parsing (7.4): one key, two keys, a key whose subkey `fpr` lines must not be taken as primaries.
- `gpg.rs`, from committed fixtures in `tests/fixtures/` (test-only keys, loaded with `include_str!`):
  - `.asc` validation: a valid cv25519 key, the same key with CRLF line endings (autocrlf), and a valid RSA key load; a sign-only key, a revoked key, a key with a third-party certification, two keys in one file, and garbage are each rejected with their own error variant. An expired key loads but fails the add-time check.
  - Subkey selection: with two encryption subkeys, the newest non-revoked one is chosen.
  - Stanza round trip without gpg: wrap a file key, then decrypt the body with rPGP (`Message::from_bytes(..)?.decrypt(&"".into(), &secret_key_fixture)`) and get the same 16 bytes.
  - A file encrypted to X25519 + `pgp` decrypts with the x25519 identity alone. `GpgIdentity` returns `None` for other tags and for unknown fingerprints.
  - With gpg: a `GpgIdentity` in a temp GNUPGHOME (below) unwraps an rPGP-written stanza.
  - Fixture generation commands are listed in `tests/fixtures/README.md` (`--faked-system-time 20240101T000000` with a `1d` expiry for the expired key; `gpg --gen-revoke` + import for the revoked key; `--quick-sign-key` from a second key for the third-party one).

**Integration tests** (`tests/`):
- Run the built binary via `env!("CARGO_BIN_EXE_git-amaga")` against `tempfile` repositories.
- Isolate Git with `GIT_CONFIG_GLOBAL=<tmp>` and `GIT_CONFIG_NOSYSTEM=1`.
- Set the identity with local `git config amaga.identity`.
- **gpg tests** (unit and integration) share one rule set. If `gpg --version` fails to spawn, print `skipping <test>: gpg not on PATH` and return. Otherwise:
  - Use a temp `GNUPGHOME` passed only to child processes (never `set_var`).
  - Create it with a short path (`tempfile::Builder::new().tempdir_in("/tmp")` on Unix). The agent socket path is limited to about 107 bytes; verified that a 118-byte home made gpg-agent fail to start.
  - Generate a passphrase-less key with `gpg --batch --passphrase '' --quick-gen-key 'Test <test@example.invalid>' default default never` (gives an ed25519 primary key and a cv25519 encryption subkey), and export it with `--armor --export --export-options export-minimal`.
  - A `Drop` guard runs `gpgconf --kill gpg-agent` with that GNUPGHOME.
  - Never touch `~/.gnupg`.

Each test below must fail against an implementation lacking the behaviour:

1. `keygen_then_init_creates_state`
2. `roundtrip_text_and_binary_exact_bytes` (NUL, CRLF, no trailing newline)
3. `add_refuses_tracked_plaintext`
4. `add_makes_plaintext_ignored`
5. `seal_unchanged_is_noop` (ciphertext bytes identical)
6. `seal_refuses_outdated_plaintext_after_pull`: the regression for change 7
7. `open_updates_outdated_unmodified_plaintext`
8. `open_refuses_local_edits`
9. `close_refuses_unsealed`
10. `status_flags_force_added_plaintext`
11. `tampered_ciphertext_fails_and_writes_nothing`
12. `user_add_rewraps_epoch_only`: after `user add bob`, every `.amaga` is byte-identical and only `users/bob.txt`, `partitions/default/members`, the current epoch file and `audit.jsonl` changed; bob opens the secret and can decrypt its committed version from the same epoch (decision 1).
13. `user_remove_locks_out_and_flags_all`
14. `seal_change_clears_only_that_file`
15. `secret_added_after_removal_not_flagged`
16. `rotate_preserves_exposure`
17. `interrupted_remove_reported_stale_and_rotate_completes`: delete a user file by hand, then check that `status` exits 1, that `seal` of an edited plaintext refuses with the rotate hint and writes nothing, and that `rotate` flags exposure.
18. `works_in_linked_worktree`: `.git` is a file, and the base file is per worktree.
19. `merged_branch_secret_flagged_after_removal`: a branch adds a secret before a removal on main; after the merge, `status` reports it stale and `rotate` flags it.
20. `user_remove_with_undecryptable_secret_changes_nothing`: `users/`, `.amaga/epochs/`, `current-epoch` and `audit.jsonl` are untouched.
21. `renamed_secret_plaintext_stays_ignored`: `git mv a.env.amaga b.env.amaga`, then `open b.env` leaves `b.env` ignored.
22. `remove_keeps_teammates_plaintext_ignored`: a second clone pulls the `remove` and its plaintext is still ignored.
23. `readd_deleted_secret_requires_force`: without `--force` it refuses; restoring the old ciphertext and running `seal` keeps `exposed_to`.
24. `autocrlf_clone_opens`: commit with `core.autocrlf=true`, make a fresh clone, and `open` succeeds.
25. `parallel_adds_merge_cleanly`: two branches each `add`; the merge has no `.gitignore` conflict and both plaintexts are ignored.
26. `commands_refuse_during_amaga_merge_conflict`
27. `no_identity_error_lists_members` (`NotAMember` exit code, and both member names appear)
28. `init_with_gpg_key_file` (gpg): `init alice key.asc` with no age identity; then `add` and `open` work through gpg.
29. `age_member_seals_for_gpg_member_without_gpg` (gpg, Unix only): the age member runs with a PATH holding only a `git` symlink and `seal`s; the GPG member then `open`s with gpg.
30. `user_add_rejects_unusable_gpg_keys`: the expired, revoked, sign-only and third-party fixtures each exit 1, and `users/` is unchanged. Needs no gpg.
31. `gpg_subkey_replacement_flags_exposure` (gpg): add a new encryption subkey, revoke the old one, and commit the re-exported `.asc`. `status` then reports stale, and `rotate` puts `pgp:<old FPR>` in `exposed_to`.
32. `gpg_decrypt_failure_writes_nothing` (gpg): after `add`, delete only the encryption subkey's secret (`gpg --batch --yes --delete-secret-keys '<SUBFPR>!'`). The member is still detected as held, `open` exits 1, and no plaintext is written.

Keyring lookup (7.4). The gpg ones generate keys in the short temp `GNUPGHOME` above and pass it only to the child process:

33. `init_gpg_key_by_unique_email` (gpg): keys for `alice@example.invalid` and `malice@example.invalid` exist; `init alice alice@example.invalid` stores alice's key (subkey fingerprint matches), and stdout and the `init` audit line carry her primary fingerprint and user ID. Fails without the `<…>` wrapping.
34. `gpg_lookup_refuses_ambiguous_email` (gpg): two keys share one email; exit 1, stderr lists both primary fingerprints, and `.amaga/` is not created.
35. `gpg_lookup_unknown_key_errors` (gpg): exit 1 with the not-in-keyring error; nothing written.
36. `gpg_lookup_exports_minimal` (gpg): certify alice's key with a second key (`--quick-sign-key`); `init alice <FPR>` succeeds, and the stored `.asc` loads (it would fail `verify_bindings()` with the certification included).
37. `keygen_prints_user_add_line`: stdout is the public key alone; stderr contains `git-amaga user add <name> <that key>`.
38. `gpg_lookup_without_gpg_errors` (Unix only): PATH holding only a `git` symlink (as in 29); `init alice alice@example.invalid` exits 1 with the gpg-not-found error.

Epoch keys (ADR-0015). Helpers that read a header unwrap the current epoch through `git_amaga_core::epoch`; "X cannot decrypt" now means X cannot unwrap the epoch.

39. `rotate_before_user_add_hides_history`: commit a secret, `rotate`, `user add carol`; carol decrypts the current version but not the one committed before the `rotate`.
40. `branch_secret_under_old_epoch_after_user_remove`: a branch adds a secret; main runs `user remove bob`; after the merge alice can `open` it, `status` reports it stale, and `rotate` flags bob.
41. `parallel_rotations_conflict_on_current_epoch`: with no secrets, main and a branch each `rotate`; the branch then `add`s a secret. After the merge every command, `status` included, exits 1 naming `.amaga/partitions/default/current-epoch` (path since 16.3). After `git checkout --ours` + `git add` of it, `status` reports the secret stale, `rotate` succeeds and `status` exits 0.
42. `member_added_on_branch_and_removal_on_main`: a further member `bobby` sits between the two edits of `default/members`, which would otherwise touch adjacent lines and conflict (ADR-0017). The branch runs `user add carol`, main `user remove bob`; the merge is clean; `status` exits 1 and `add` refuses with the rotate hint; after `rotate` carol opens every secret, bob is flagged and carol is not.
43. `member_not_in_old_epoch_cannot_read_its_secrets`: a branch adds a secret; main runs `rotate`, then `user add carol`; after the merge carol's `open` of that secret and her `rotate` exit 1 and write nothing; after alice's `rotate` carol opens it.
44. `interrupted_user_add_finished_by_rotate`: write `users/carol.txt` by hand; `status` exits 1; `add`, `seal`, `user add dave` and `dismiss --user x` refuse with the rotate hint; after `rotate` carol opens every secret and nothing is flagged.
45. `one_gpg_decrypt_per_command` (gpg, Unix only): a GPG member and three secrets; PATH holds a `gpg` wrapper that logs its arguments and runs the real gpg; `open` and `status` each log exactly one `--decrypt`.
46. `epoch_and_secret_are_plain_age`: with the `age` crate only, decrypt the current epoch file with alice's identity, drop the first line, parse the rest as an identity, decrypt a secret with it and drop its first line: the plaintext comes out (the escape hatch in section 4).
47. `tampered_epoch_file_fails_and_writes_nothing`: flip the last byte of the current epoch file; `open` and `rotate` exit 1 naming that file; nothing is written.
48. `repository_without_current_epoch_errors`: delete `.amaga/partitions/default/current-epoch` (path since 16.3); `status` exits 1 and stderr names `current-epoch`.

Dismiss (ADR-0016):

49. `dismiss_clears_selected_user_and_paths`: members alice, bob, carol, two secrets; remove bob and carol; `dismiss --user bob a.env` leaves a flagged for carol only and b for both; stdout is `dismissed a.env.amaga`; `status` still shows the plaintext `in sync`; the audit log gains one `exposure.dismissed` line (path `a.env`, user `bob`) and no `secret.updated`.
50. `dismiss_refuses_without_target_or_unknown_user`: bare `dismiss` and `dismiss --user nobody` exit 1; every `.amaga` and `audit.jsonl` are unchanged.
51. `dismiss_user_across_all_secrets`: `dismiss --user bob` clears bob everywhere; rerunning it exits 1 (`NotExposed`) and writes nothing.

Partitions (ADR-0017), in `crates/cli/tests/partitions.rs`. Members are age members unless noted; "cannot unwrap" is checked with the `age` crate, so the test proves the cryptography and not just the refusal:

52. `secret_label_is_readable_and_authenticated`: after `add`, the `.amaga` header has the line `-> amaga-partition default`. Changing it in place to `defaulx` (same length) makes `open` exit 1, and nothing is written.
53. `default_members_file_controls_access`: alice and bob. Delete the line `bob` from `.amaga/partitions/default/members` by hand. `status` exits 1 with `run git-amaga rotate`, and `add` refuses with the rotate hint. After alice's `rotate`, bob cannot unwrap the new default epoch, and every secret is flagged bob.
54. `partition_create_restricts_access`: alice and bob in `default`; `partition create production alice`; `add --partition production p.env` and `add d.env`. Bob's `open` without paths opens only `d.env` and exits 0. Bob's `open p.env` exits 1, and stderr names `production`. Bob's `status` exits 0 with `ok p.env.amaga (production): not a member`. Bob cannot unwrap the epoch named in `.amaga/partitions/production/current-epoch`. Alice's `status` prints `partition default: alice, bob` and `partition production: alice`.
55. `stale_guard_is_per_partition`: write `bob` into `production/members` by hand. `add --partition production x.env` exits 1 with `rotate --partition production`; `add y.env` (default) succeeds.
56. `rotate_partition_touches_only_that_partition`: `rotate --partition production` rewrites only production secrets and moves only production's pointer; every default `.amaga` stays byte-identical. Bob, who is not in production, runs `rotate`: default is re-encrypted, stderr names `production`, and the production files stay byte-identical.
57. `user_remove_rotates_only_the_actors_partitions`: alice in `default`; bob and carol in `default` and `production`. Alice's `user remove bob` re-encrypts the default secrets and flags bob; stderr names `production`; `users/bob.*` is gone; `production/members` lacks bob; the production secrets stay byte-identical. Carol's `status` reports them stale; after carol's `rotate`, they are flagged bob.
58. `last_partition_member_cannot_be_removed_by_user_remove`: production = {alice}, bob in default. `user remove alice` exits 1 naming `production`, and nothing changes.
59. `partition_remove_flags_only_that_partition`: alice and bob in `default` and `production`; secrets `d` (default) and `p` (production). `partition remove production bob` prints `re-encrypted p.env.amaga (NEEDS ROTATION: exposed to bob)`. `d.env.amaga` and default's pointer are unchanged. Then `partition remove production alice` (the last member) exits 1, and nothing changes.
60. `partition_add_rewraps_only`: `partition add production bob` leaves every `.amaga` byte-identical. Only `production/members`, the production epoch file and `audit.jsonl` change, and bob opens `p.env`.
61. `partition_add_on_branch_rotate_on_main`: a branch runs `partition add production bob`, and main runs `rotate --partition production`. The merge is clean. Alice's `status` exits 1 for the production secrets (stale), and `add --partition production` refuses. After `rotate --partition production`, bob opens them and nobody is flagged.
62. `user_add_into_partition_only`: `user add carol <key> --partition production`. Carol opens the production secrets, and her `open d.env` exits 1. Default's epoch file, its pointer and `default/members` are unchanged.
63. `partition_move_flags_members_missing_from_target`: default = {alice, bob}, production = {alice}. `partition move production d.env` prints `moved d.env.amaga`, and the label is now `production`. Alice's `status` shows `WARN d.env.amaga (production): NEEDS ROTATION: exposed to bob`. The plaintext and base are untouched, the audit log gains `secret.moved`, and bob cannot open it. Moving it back into `default` flags nobody new.
64. `partition_is_chosen_at_add_and_attribute_never_moves_it`: `.gitattributes` has `prod/** amaga-partition=production`, and `add prod/db.env` gives the label `production`. Change the attribute to `default` and commit. `status` exits 1 with `.gitattributes says default`. `rotate` keeps the label `production`, and bob (default only) still cannot open the file. Restoring the attribute makes `status` exit 0. This is the regression test for decision 17.

git-crypt import (ADR-0018), in `crates/cli/tests/import_git_crypt.rs`. None of these needs git-crypt; a simulated unlocked repository is tracked plaintext plus the attribute lines plus `.git-crypt/keys/...` files:

65. `import_simulated_git_crypt_repo`, which needs no gpg. alice runs `init alice <age key> valid_cv25519.asc`, so she has both kinds of key and is the actor through her age identity. The local config has `filter.git-crypt.clean`/`smudge` = `cat`, as an unlocked git-crypt repository would. The commit has:
    - a `.gitattributes` with `secret.env filter=git-crypt diff=git-crypt`, `prod/** filter=git-crypt-Prod diff=git-crypt-Prod` and `*.key filter=git-crypt diff=git-crypt -text`;
    - `secret.env`, `prod/db.env`, `a.key` and `plain.txt`;
    - `.git-crypt/.gitattributes`, `.git-crypt/keys/default/0/<alice primary FPR>.gpg` and `.git-crypt/keys/Prod/0/<unknown 40-hex>.gpg`.

    The import runs with `GNUPGHOME` set to an empty home from the common gpg helper (a short temp dir, agent killed on drop). Whether or not gpg is on PATH, the unknown fingerprint is skipped. Asserts:
    - Exit 0. stderr names the unknown fingerprint as not imported and carries the git-crypt history warning.
    - Partitions `default` = {alice} and `prod` = {alice}. The labels of `secret.env.amaga` and `a.key.amaga` are `default`, and of `prod/db.env.amaga`, `prod`. Each decrypts to its original bytes.
    - `git ls-files` lists none of the three plaintexts but still lists `plain.txt`, and the plaintexts are ignored.
    - `.gitattributes` keeps only `*.key -text` of the three lines, and `git check-attr filter -- prod/db.env.amaga` is `unspecified`.
    - `.git-crypt/` is gone, and `git config filter.git-crypt.smudge` is still `cat`.
66. `import_refuses_locked_or_staged_files_and_writes_nothing`: (a) a file whose content starts with `\0GITCRYPT\0` makes it exit 1 with `git-crypt unlock` on stderr; (b) a staged change to an imported file makes it exit 1. In both cases `git status --porcelain`, the `.amaga/` tree and `.gitattributes` are unchanged.
67. `import_refuses_repo_with_secrets`: after one `add`, the import exits 1, and nothing is written.
68. `import_exports_holder_from_keyring_and_names_it` (gpg): a key `Dave Smith <dave.smith@example.invalid>` in the temp GNUPGHOME is a default holder. Without `--name` it becomes `users/dave.smith.asc`, and stdout has `dave.smith: GPG key <primary FPR>`. In a fresh repository, `--name <FPR>=dave` gives `users/dave.asc`. `--name <another FPR>=x` exits 1.
69. `import_real_git_crypt_repo` (gpg and git-crypt; prints a skip notice when either is missing): `git-crypt init`, `git-crypt add-gpg-user --trusted <FPR>` with the temp GNUPGHOME (passed only to child processes), `secret.env filter=git-crypt diff=git-crypt`, commit. After `git-crypt lock` the import exits 1 (locked); after `git-crypt unlock` it succeeds. The derived member holds the GPG key, and alice decrypts `secret.env.amaga` to the original bytes. CI installs git-crypt on Linux (`sudo apt-get install -y git-crypt`, 16.10); Windows skips.

## 12. Implementation steps

These are the v0.1.0 steps, kept as history (per-file age). Epoch keys and `dismiss` are built by section 15.

Each step is one coder worktree. It contains one to three commits, and each commit builds, passes
`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test`. Steps merge in
order. Almost every step touches `src/lib.rs`, `src/error.rs` and often `Cargo.toml`, so steps are
**sequential** unless marked parallel. A step adds only the `Error` variants it uses.

| Step | Commits | Files | Depends on | Acceptance |
|------|---------|-------|------------|------------|
| 1 Crypto core (age) | 1: header, encode/decode payload, age encrypt/decrypt over `&dyn Recipient`/`&dyn Identity`, `next_header`, `plaintext_state` | `Cargo.toml`, `src/lib.rs`, `src/error.rs`, `src/secret.rs` | none | Unit tests in section 11 for `next_header`, `plaintext_state` and header parsing. A two-recipient round trip. A third identity gets `NoMatchingKeys`. |
| 2 GPG crypto | 2a: fixtures + `.asc` parse/validate/subkey selection + add-time expiry check. 2b: `pgp` Recipient, `GpgIdentity`, gpg decrypt (7.3), held check. | `Cargo.toml` (`pgp`, `age-core`, `rand`), `src/lib.rs`, `src/error.rs`, `src/gpg.rs`, `tests/fixtures/*.asc` | 1 | `gpg.rs` unit tests in section 11. The gpg ones print the skip notice when gpg is absent. |
| 3 CI (**parallel** with 2–9) | 1: workflow running fmt, clippy and test on `ubuntu-latest` + `windows-latest`; `.cargo/config.toml` with `+crt-static` | `.github/workflows/ci.yml`, `.cargo/config.toml` | 1 | CI green on the step-1 tree. |
| 4 Git, identity, CLI | 4a: `git.rs`. 4b: age identity load (config, then default path), GPG probe (5.5), `keygen`, `main.rs` | `Cargo.toml` (`clap`), `src/lib.rs`, `src/error.rs`, `src/git.rs`, `src/identity.rs`, `src/main.rs`, `tests/common/mod.rs` (repo + gpg helpers), `tests/cli.rs` | 2 | `keygen` writes a 0600 file, refuses to overwrite, and sets `amaga.identity`. Unit tests for the default-path fallback. |
| 5 Users, audit, paths, init | 5a: `users.rs` (`.txt` + `.asc`, 5.1). 5b: `audit.rs`, `paths.rs`, actor lookup, `init [KEY…]` | `src/users.rs`, `src/audit.rs`, `src/paths.rs`, `src/identity.rs`, `src/lib.rs`, `src/main.rs`, `src/error.rs`, `tests/cli.rs` | 4 | Test 1. Users, `.gitignore`, path and RFC 3339 unit tests. |
| 6 add + seal | 1–2 | `src/lib.rs`, `src/main.rs`, `src/secret.rs` (base file), `src/error.rs`, `tests/cli.rs` | 5 | Tests 3, 4, 5, 27. |
| 7 open + close | 1–2 | same as 6 | 6 | Tests 2, 6–9, 11, 21, 23, 24, 28, 29, 32. |
| 7b GPG key lookup (ADR-0013) | 1: `KEY` classification + keyring lookup and export (7.4), audit `gpg_fpr`/`gpg_uid`, keygen `user add` hint. `user add` (step 9) reuses the same `KEY` resolution. | `src/gpg.rs` (or a new `src/keyring.rs` if `gpg.rs` passes ~400 non-test lines, per `CLAUDE.md`), `src/lib.rs`, `src/audit.rs`, `src/error.rs`, `tests/common/mod.rs` (key generation in `GpgHome`), `tests/cli.rs` | 7 | Tests 33–38; classification and colon-parsing unit tests. Existing test 28 (`.asc` path) still passes. |
| 8 status | 1 | `src/lib.rs`, `src/main.rs`, `tests/cli.rs` | 7b | Tests 10, 25, 26, plus the status assertions in 6–9. |
| 9 Membership | 9a: re-encrypt all + `rotate`. 9b: `user add` / `user remove` | `src/lib.rs`, `src/main.rs`, `src/users.rs`, `src/error.rs`, `tests/cli.rs` | 8 | Tests 12–20, 30, 31. |
| 10 remove | 1 | `src/lib.rs`, `src/main.rs`, `tests/cli.rs` | 9 | Test 22. |
| 11 Release | 1: complete `README.md` (its parts marked `<!-- completed in plan step 11 -->`: section 4 threat model incl. GPG limitations, sections 8–9 workflows, `age -d` escape hatch, GPG setup: key lookup or export-minimal, `GPG_TTY`; command table marked implemented) + `[profile.release]` | `README.md`, `Cargo.toml` | 10, 3 | `file` reports the musl binary as statically linked; `dumpbin /dependents` shows no `vcruntime*.dll`; CI green. |

`tests/cli.rs` may be split into one file per command group if it grows. Doing so does not change
the ordering above.

## 13. Deferred

SSH recipients · pruning old epoch files (decision 13) · deleting or renaming a partition · member groups · importing git-crypt holders of exported symmetric keys (they leave no trace) · flagging imported secrets in `exposed_to` (decision 22) · backup copy of a plaintext before `open` overwrites it · pre-commit hook that blocks tracked plaintext · `git diff` textconv for decrypted diffs · `--stage` · signed audit/commits integration · per-secret ACLs (partitions cover named sets, ADR-0017) · a secret in several partitions (encrypt to each partition's current epoch with one label stanza per partition; readers are the union; additive, because single-label files stay valid; until then, use a partition whose members are the union) · passphrase-protected age identities / age plugins (`age-plugin-yubikey`; YubiKeys already work as GPG cards) · honouring `gpg.program` · warning before a GPG key expires · encrypting to an OpenPGP primary key that has no encryption subkey · fetching GPG keys from a keyserver/WKD (`gpg --locate-keys`) at `init`/`user add` · macOS/aarch64 release targets.

## 14. Workspace split (ADR-0014)

Goal: a core library that others can call without terminal output, and a CLI whose output does
not change. One coder worktree, four commits (14.5).

### 14.1 Layout

```text
Cargo.toml                   virtual workspace (below); Cargo.lock stays at the root
.cargo/config.toml           unchanged (read for builds run from the root)
crates/core/Cargo.toml       package git-amaga-core, lib git_amaga_core
crates/core/src/             today's src/ minus main.rs, plus outcome.rs (14.2)
crates/core/tests/fixtures/  today's tests/fixtures/ incl. README.md; unit tests' include_str!("../tests/fixtures/…") stay valid
crates/cli/Cargo.toml        package git-amaga, bin git-amaga (src/main.rs)
crates/cli/src/main.rs       clap, dispatch, rendering (one file, ~200 lines)
crates/cli/tests/            cli.rs, membership.rs, common/mod.rs
```

Root `Cargo.toml`:

```toml
[workspace]
members = ["crates/core", "crates/cli"]
resolver = "3"

[workspace.package]
version = "0.3.0"
edition = "2024"
rust-version = "1.88"
license = "MIT"
repository = "https://github.com/jmigual/git-amaga"

[workspace.dependencies]
git-amaga-core = { path = "crates/core" }
# age, age-core, clap, pgp, rand, serde, serde_json, sha2, thiserror, tempfile:
# moved verbatim from today's [dependencies]/[dev-dependencies] (versions and features as in 10.1)

[profile.release]
lto = true
strip = true
```

Members set `version`, `edition`, `rust-version`, `license` and `repository` with
`.workspace = true`, and list dependencies as `name.workspace = true`:
- core: `age`, `age-core`, `pgp`, `rand`, `serde`, `serde_json`, `sha2`, `thiserror`; dev `tempfile`.
- cli: `git-amaga-core`, `clap`; dev `age`, `tempfile` (the integration tests use both).

Integration tests: the only edits are `git_amaga::` → `git_amaga_core::` and
`include_str!("fixtures/` → `include_str!("../../core/tests/fixtures/`. `CARGO_BIN_EXE_git-amaga`
still resolves, because the tests live in the binary's package.

Install and CI:
- With two packages in the repository, the cargo docs require the crate argument for `--git`.
  README: `cargo install --locked --git https://github.com/jmigual/git-amaga git-amaga`.
- `ci.yml`: `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace`.
  A virtual manifest already builds every member; the flag matches `CLAUDE.md`.
- `release.yml`: unchanged. The binary is still `target/<target>/release/git-amaga[.exe]`.

### 14.2 Core API

`lib.rs` gets a one-line crate doc: each command takes the directory it runs in, acts on the
repository containing it and never prints. Public modules: `epoch` (section 15), `error`, `gpg`, `identity`, `partition` (section 16), `secret`, `users`. Private
modules: `audit`, `commands`, `context`, `dismiss` and `status` (section 15), `files` and `import` (section 16), `git`, `gitcrypt` (pure `import-git-crypt` helpers), `keyring`, `membership`, `outcome`, `partition_commands`
(the `partition` commands), `paths`, `remove`, `selection`. Root re-exports: `Error`, `keyring::GpgKey`, the `outcome` types, and every `cmd_*`.

```text
cmd_keygen(dir, path: Option<&Path>)           -> Result<age::x25519::Recipient, Error>
cmd_init(dir, name: &str, keys: &[String])     -> Result<Option<GpgKey>, Error>
cmd_add(dir, force: bool, partition: Option<&str>, paths: &[String]) -> Result<Outcome, Error>   changed: `.amaga` paths (section 16)
cmd_seal(dir, force: bool, paths: &[String])   -> Result<Outcome, Error>   changed: `.amaga` paths
cmd_open(dir, force: bool, paths: &[String])   -> Result<Outcome, Error>   changed: plaintext paths
cmd_close(dir, paths: &[String])               -> Result<Outcome, Error>   changed: plaintext paths
cmd_remove(dir, paths: &[String])              -> Result<Outcome, Error>   changed: `.amaga` paths
cmd_rotate(dir, partitions: &[String])         -> Result<Rotation, Error>   (section 16)
cmd_user_add(dir, name: &str, keys: &[String], partitions: &[String]) -> Result<Option<GpgKey>, Error>   no secret is rewritten (sections 15, 16)
cmd_user_remove(dir, name: &str)               -> Result<Rotation, Error>   (section 16)
cmd_partition_create(dir, name: &str, members: &[String]) -> Result<(), Error>        (section 16)
cmd_partition_add(dir, name: &str, members: &[String])    -> Result<(), Error>        (section 16)
cmd_partition_remove(dir, name: &str, members: &[String]) -> Result<Rotation, Error>  (section 16)
cmd_partition_move(dir, name: &str, paths: &[String])     -> Result<Outcome, Error>   changed: `.amaga` paths (section 16)
cmd_import_git_crypt(dir, names: &[String])    -> Result<Imported, Error>  `names`: `<FPR>=<name>` (section 16)
cmd_dismiss(dir, users: &[String], paths: &[String]) -> Result<Outcome, Error>  changed: `.amaga` paths (section 15)
cmd_status(dir)                                -> Result<StatusReport, Error>
```

`dir: &Path` is the directory the command runs in, exactly replacing the process cwd.

`outcome.rs` (illustrative; every pub item gets a one-line doc):

```rust
pub struct Outcome { pub changed: Vec<String>, pub warnings: Vec<Warning> }   // Default, Debug
pub enum Warning {                                   // Debug + Display (the text after `warning: `)
    PlaintextInHistory(String),                      // '{0}' already appears in git history
    ExposureHistoryDropped(String),                  // '{0}' appears in git history; its exposure history is dropped
    ExposureCleared { plaintext: String, members: usize },
        // sealing '{plaintext}' with --force clears NEEDS ROTATION for {members} member(s); the local copy may still hold an old value
    Skipped { path: String, error: Error },          // skipping '{path}': {error}
}
pub struct Reencrypted { pub path: String, pub exposed_to: Vec<String> }      // in write order
// section 16:
pub struct Rotation { pub written: Vec<Reencrypted>, pub warnings: Vec<Warning> }
pub struct Imported { pub members: Vec<(String, GpgKey)>, pub created: Vec<String>, pub changed: Vec<String>, pub warnings: Vec<Warning> }
// Warning gains:
//   PartitionNotRotated(String)   partition '{0}' was not re-encrypted: you are not a member; if it needs rotation, a member must run `git-amaga rotate --partition {0}`
//   KeySkipped { fpr: String, error: Error }   git-crypt key holder {fpr} not imported: {error}
//   UnknownMember { partition: String, name: String }   partition '{partition}' lists '{name}', who is not in .amaga/users; it grants nothing
//   GitCryptHistory               every former git-crypt key holder, including anyone given an exported key, can still read the imported files in git history; treat those credentials as exposed
pub enum Level { Error, Warn, Ok }                                           // Ord: Error first
pub struct SecretStatus { pub level: Level, pub path: String, pub partition: String, pub messages: Vec<String> }   // partition: section 16
pub struct StatusReport { pub members: String, pub partitions: Vec<(String, Vec<String>)>, pub secrets: Vec<SecretStatus>, pub warnings: Vec<Warning> }
impl StatusReport { pub fn error_count(&self) -> usize }   // > 0: `status` exits 1
```

Internal changes (no new behaviour):
- `secret_paths_for(.., warnings: &mut Vec<Warning>)` pushes `Skipped` instead of printing.
- `reencrypt_all` returns `Vec<Reencrypted>`, with `exposed_to` taken from the new header's
  `exposed_to` keys.
- `cmd_init` and `cmd_user_add` return `resolved.gpg` instead of printing it.
- `secret_status` returns a `SecretStatus` holding today's message list, not yet joined. Unmerged
  files without a worktree copy get `messages: [UNMERGED]`. `secrets` keeps today's stable sort
  by level.
- Delete `GpgKey::summary` (its format moves to the CLI) and `Error::StatusProblems` (no caller
  left in the core). `identity::member_summary` stays, because `Error::NotAMember` uses it.

`dir` drives git (`current_dir`), `show_prefix`, relative `KEY` files, the `keygen` path and a
relative `amaga.identity` config value. For an absolute `dir` the core never reads the process
cwd (ADR-0014). Git's own environment (`GIT_DIR`, `GIT_WORK_TREE`) takes precedence over `dir`,
as with `git -C`. An unusable `dir` (missing, or not a directory) is `Error::IoPath` naming it,
raised before anything is written. The CLI passes its cwd, or the global `-C <path>` (`--repo`).

### 14.3 Rendering contract

On success, each stream's bytes are the same as today. The CLI prints a command's warnings
first, then its lines.

| Command | stdout | stderr |
|---------|--------|--------|
| keygen | `{public}` | `to join a repository, send this to a member: git-amaga user add <name> {public}` |
| init, user add | `{name}: GPG key {fpr} "{uid}"`, if the member has a GPG key (`user add` prints nothing else) | |
| add / seal / remove | `added` / `sealed` / `removed {path}` per changed path | `warning: {w}` per warning |
| open / close | `opened` / `closed {path}` | `warning: {w}` |
| rotate, user remove, partition remove | `re-encrypted {path}`, or `re-encrypted {path} (NEEDS ROTATION: exposed to {a, b})` | `warning: {w}` (section 16) |
| dismiss | `dismissed {path}` per changed `.amaga` path | |
| partition create, partition add | nothing | |
| partition move | `moved {path}` per changed `.amaga` path | |
| import-git-crypt | `{name}: GPG key {fpr} "{uid}"` per new member, then `imported {path}` per `.amaga` | `warning: {w}`, the history warning last |
| status | `members: {members}`, then `partition {p}: {names joined by ", "}` per partition, then `{ERROR\|WARN\|ok} {path}: {messages joined by "; "}`, with ` ({partition})` after the path outside `default` | `warning: {w}`; if n > 0, `error: status found problems with {n} secret(s)` and exit 1 |
| any error | | `error: {e}`, exit 1 (clap usage errors unchanged, exit 2) |

Tokens the integration tests assert, none of which change:
- stdout: keygen's bare key; `init`/`user add` primary fingerprint and `Alice <alice@example.invalid>`;
  status `members: alice (age)`, `ok … in sync`, `ok … closed`, `ERROR …: unmerged` (incl. `sé.env.amaga`),
  `ERROR a.env.amaga: 'a.env' is not a regular file`, `; not a regular file`,
  `CRITICAL plaintext 'b.env' is tracked`, `` `text` attribute ``, `run git-amaga rotate`,
  `WARN secret.env.amaga: NEEDS ROTATION: exposed to charlie`, two `NEEDS ROTATION: exposed to bob`,
  `decryption error`, `ERROR` lines before `ok` lines.
- stderr: `git-amaga user add <name> {key}`, `appears in git history`, `exposure history is dropped`,
  `NEEDS ROTATION` (seal --force), and every `Error` text (unchanged, because `Error` keeps its `Display`).
- exit code 1 from status problems and from errors.

Known difference: a command that fails part-way prints only `error: {e}`, not the lines for the
files it already wrote (ADR-0014).

### 14.4 Checks (every commit)

`cargo fmt --check` · `cargo clippy --workspace --all-targets -- -D warnings` ·
`cargo test --workspace` · `GIT_DIR=/nonexistent cargo test --workspace`.

### 14.5 Commits

| Commit | Content | Acceptance |
|--------|---------|------------|
| 1 `workspace: move the library to crates/core and the binary to crates/cli` | `git mv` only, manifests, `Cargo.lock`, the two mechanical test edits, `git_amaga::` → `git_amaga_core::` in `main.rs`, the `ci.yml` flags. The core still prints. | Checks green. The number of passed tests matches the count before the move (sum the `test result` lines). `cargo install --locked --git file://<worktree> --branch <branch> git-amaga --root <scratch>` installs `bin/git-amaga`. `cargo build --release` yields `target/release/git-amaga`. |
| 2 `core: return command results instead of printing; the CLI renders them` | `outcome.rs`, `commands.rs`, `membership.rs`, `remove.rs`, `context.rs`, `keyring.rs`, `error.rs`, `main.rs` (14.2, 14.3). Must be one commit, so the output moves atomically. | Checks green with the integration tests unedited. `grep -rn -e 'print!' -e 'println!' -e 'eprint' crates/core/src` finds only the two `#[cfg(test)]` skip notices (`gpg.rs`, `paths.rs`). A scratch transcript is identical for the commit-1 and commit-2 binaries. It covers keygen, init, add, add --force, seal --force on an exposed secret, open, close, status with a problem, user add, user remove, rotate and remove, recording stdout, stderr and the exit code per step, with `age1…` masked. |
| 3 `core: keep git, paths, audit and the command modules private` | `lib.rs` visibility, crate doc, re-exports (14.2). | Checks green, with no new `dead_code` warnings. `cargo doc -p git-amaga-core --no-deps` shows only the public items in 14.2. |
| 4 `docs: CLAUDE.md and README for the workspace` | `CLAUDE.md`: module map under `crates/core/src/` and `crates/cli/src/main.rs`, test and fixture paths, the checks from 14.4, and the rule "the core never prints; the CLI owns output and exit codes". `README.md`: the install line with `git-amaga`, and one sentence pointing library users to `git-amaga-core`. | Every path in both files exists (`ls` each). |

Out of scope: publishing to crates.io (needs a `version` on the path dependency and a free crate
name), a `repo: &Path` API, and a progress callback.

## 15. Epoch keys and dismiss: implementation steps

ADR-0015 and ADR-0016. One coder worktree on `epoch-keys`; the commits below land in order.
Every commit passes the checks of 14.4 (`cargo fmt --check` · `cargo clippy --workspace
--all-targets -- -D warnings` · `cargo test --workspace` · `GIT_DIR=/nonexistent cargo test
--workspace`). "Fails before" means the named test fails, or does not compile, on the previous
commit. A commit adds only the `Error` variants it uses. Public API changes are marked **API**.

Commit 3 is the format switch. Every reader and writer of secrets changes together, so it cannot
be split further without a commit in which `add` and `open` disagree on the format.

### 15.1 `core: move status into its own module`

- Files: `crates/core/src/commands.rs`, new `crates/core/src/status.rs`, `crates/core/src/lib.rs`.
- Change: move `cmd_status`, `secret_status`, `without_path`, `state_problem`, `key_set` and
  `UNMERGED` verbatim; `lib.rs` re-exports `cmd_status` from `status`. No behaviour change.
  Needed because `commands.rs` (376 lines) would pass ~400 with the epoch work (`CLAUDE.md`).
- Tests: none new. Acceptance: checks green with an unchanged test count;
  `git diff --color-moved=zebra` shows only moved lines plus `use`/`mod` lines.

### 15.2 `secret: payload helpers generic over the header type`

- Files: `crates/core/src/secret.rs`.
- Change: `encode_payload`, `decode_payload`, `encrypt` and `decrypt` take any
  `H: Serialize` / `DeserializeOwned` header; the version check compares against a new
  `pub const VERSION: u8 = 1` used by `Header`. **API** (source compatible for `Header` callers).
- Tests: none new. Acceptance: checks green, no test edited.

### 15.3 `core: epoch file format (ADR-0015)`

- Files: new `crates/core/src/epoch.rs` (public module), `crates/core/src/lib.rs`,
  `crates/core/src/error.rs` (`NoEpoch`, `EpochInvalid(String)`). **API**: new `epoch` module.
- Change (illustrative names): `Epoch { members: Recipients, … }` holding the
  `x25519::Identity`; `generate(members) -> Epoch`; `id()` (public key string);
  `wrap(&Epoch, &[&dyn age::Recipient]) -> Vec<u8>` writing the 5.6 payload with
  `"v": secret::VERSION`; `unwrap(id, ciphertext, &[&dyn age::Identity]) -> Epoch`, checking the
  key line and that its public key equals `id`; `file_path(id)`; `read_pointer(root)`,
  `write_pointer(root, id)`; `list(root)` (sorted ids, other names ignored). Nothing calls it yet.
  Keep it under ~200 lines without tests.
- Tests (fail before: the module does not exist): the epoch unit tests of section 11.

### 15.4 `core: secrets are encrypted to the current epoch (format 2)`

- Files: `crates/core/src/{secret,context,commands,status,membership,remove,error}.rs`,
  `crates/cli/tests/{cli,membership}.rs`, `crates/cli/tests/common/mod.rs`,
  `crates/core/tests/directory.rs` if it needs a helper.
- Change:
  - `secret.rs`: `VERSION = 2`; `Header` loses `recipients` (**API**); `next_header` takes
    `old: Option<(&Header, &Recipients)>` and `new_members` (6.1, **API**).
  - `context.rs`: `load` reads `current-epoch` (5.6). A per-command cache unwraps each epoch at
    most once (success or failure). `decrypt` tries the current epoch, then the others (5.6),
    and returns the header, the body and the decrypting epoch. `encrypt` encrypts to the
    current epoch's public key. The old member-recipient list becomes the helper used to wrap
    epochs. `failing_member` also names the member for `EpochUndecryptable` (new variant in
    `error.rs`).
  - `commands.rs`: `init` writes the first epoch and `current-epoch` after the user file and
    adds `.amaga/epochs/* binary` to `GITATTRIBUTES_LINES`. `add`/`seal` use the new
    `next_header`.
  - `status.rs`: unwraps the current epoch up front; stale = under a non-current epoch or
    current epoch not up to date (7.2).
  - `membership.rs`: `reencrypt_all` follows 7.1 (new epoch, secrets, pointer last). `user add`
    still goes through it in this commit (new epoch per add) until 15.6.
  - `remove.rs`: the new `decrypt` return type.
- Test helpers: `common` gains readers for the current epoch (via `git_amaga_core::epoch`) and an
  "encrypt a secret to the current epoch" helper, replacing direct `secret::encrypt` to alice in
  `rotate_ciphertext`, `readd_deleted_secret_requires_force`,
  `seal_force_warns_when_clearing_exposed_to` and `status_warns_about_exposure_with_exit_zero`.
  `header_of`/`decrypt_with` in `membership.rs` unwrap the epoch. A member written by hand gets
  access only after `rotate`: `write_member` runs `rotate`, as do
  `age_member_seals_for_gpg_member_without_gpg` and `status_stale_compares_key_sets_not_names`
  after their hand-written file. `status_reports_stale_recipients` makes a secret stale by
  restoring its pre-`rotate` ciphertext with `git checkout`. `keygen_then_init_creates_state`
  also asserts the new `.gitattributes` line, an epoch file and `current-epoch`. Test 16 also
  asserts a new epoch file and a changed `current-epoch`. Test 20 also asserts `.amaga/epochs/`
  and `current-epoch` are untouched.
- Tests that fail before and pass after: 45, 46, 47, 48; `secret.rs` unit tests for `v` 2, a
  rejected 0.1.0 header and the 6.1 rows with epoch member sets. Tests 40 and 43 are regression
  guards: 0.1.0 behaved the same, and the epoch design must keep it. Every other existing test
  passes after the helper changes above.

### 15.5 `core: add and seal refuse while the epoch is stale`

- Files: `crates/core/src/{context,commands,error}.rs` (`EpochStale`),
  `crates/cli/tests/{cli,membership}.rs`.
- Change: `Context::require_up_to_date()` (unwraps the current epoch, compares key sets) called
  first by `add` and `seal` (7, stale guard).
- Tests that fail before and pass after: 17 (the `seal` refusal), 44 (the `add`/`seal` part).

### 15.6 `core: user add re-wraps the current epoch`

- Files: `crates/core/src/membership.rs`, `crates/cli/src/main.rs`,
  `crates/cli/tests/membership.rs`.
- Change: `cmd_user_add` no longer calls `reencrypt_all`: checks as today, stale guard, then
  member file, audit `user.added`, re-wrap the current epoch to all members (7). Returns
  `Option<GpgKey>` (**API**); the CLI prints only the GPG key line.
- Tests that fail before and pass after: 12 (rewritten), 42, 44 (the `user add dave` part).
  Test 39 is a regression guard for decision 1 and also passes before.

### 15.7 `core: refuse while an epoch path is unmerged`

- Files: `crates/core/src/{git,context,error}.rs` (`UnmergedEpoch`), `crates/cli/tests/cli.rs`.
- Change: generalise `git::unmerged_secrets` into `unmerged_paths`, which takes pathspecs (callers pass `*.amaga`), and
  make `Context` loading refuse when `.amaga/current-epoch` or `.amaga/epochs` is unmerged, for
  every command including `status` (7).
- Tests that fail before and pass after: 41 (asserts the `git checkout --ours` hint, which the
  `EpochInvalid` error from parsing conflict markers does not contain).

### 15.8 `core: dismiss exposure (ADR-0016)`

- Files: new `crates/core/src/dismiss.rs`, `crates/core/src/lib.rs` (re-export `cmd_dismiss`,
  **API**), `crates/core/src/error.rs` (`DismissNoTarget`, `NotExposed(String)`).
- Change: `cmd_dismiss(dir, users, paths) -> Result<Outcome, Error>` as in the command table
  (7): target check before loading, stale guard, decrypt all, `NotExposed` check, then per secret
  `next_header` minus the dismissed names, write, audit `exposure.dismissed` per name. The
  selection is a small pure function, unit-tested.
- Tests that fail before and pass after: `dismiss.rs` unit tests (section 11), and
  `no_target_is_refused_before_anything_is_loaded` (as in `remove.rs`).

### 15.9 `cli: dismiss subcommand`

- Files: `crates/cli/src/main.rs`, `crates/cli/tests/membership.rs` (or a new
  `crates/cli/tests/dismiss.rs`).
- Change: `Dismiss { #[arg(long = "user", value_name = "NAME")] users: Vec<String>, paths:
  Vec<String> }`, doc "Clear NEEDS ROTATION without changing the plaintext"; output per 14.3.
- Tests that fail before and pass after: 49, 50, 51, and the `dismiss` part of 44.

### 15.10 `docs: README for epoch keys and dismiss`

- Files: `README.md`.
- Change: "How it works" (epochs, `current-epoch`, format 2; 0.1.0 repositories are not
  readable: open secrets with 0.1.0, then `init` anew), the two-command escape hatch (section 4),
  team workflow (`user add` re-wraps; `rotate` first to keep history private), command
  reference (`user add`, `rotate`, new `dismiss` row), GPG notes (one gpg call per command),
  removal workflow step 5 (section 9), branches (`current-epoch` conflicts, section 8), and the
  security model bullets that changed (new members and history, one gpg call per command,
  merged branch secrets).
- Acceptance: the README no longer says that `user add` re-encrypts every secret, that gpg runs
  once per secret, or that a new member cannot decrypt any history; every command in its
  reference appears in `git-amaga --help`.

### 15.11 `docs: CLAUDE.md module map`

- Files: `CLAUDE.md`.
- Change: add `epoch.rs` (epoch files, `current-epoch`, wrap/unwrap), `status.rs` (`status`)
  and `dismiss.rs` (`dismiss`) to the core module list; `membership.rs` becomes "`rotate`,
  `user add` (re-wrap) and `user remove`".
- Acceptance: every path named in `CLAUDE.md` exists (`ls` each).

## 16. Partitions and git-crypt import: implementation steps

ADR-0017 and ADR-0018, on the integration branch `partitions-import`. Each step is one commit and
passes the checks of 14.4. "Fails before" means the named test fails, or does not compile, on the
previous commit. A step adds only the `Error` variants it uses. Public API changes are marked
**API** (14.2 lists the final signatures). Paths are under `crates/core/src/` unless written in
full. Struct and function names are illustrative unless 14.2 fixes them.

```text
16.1 → 16.2 → 16.3 → 16.4 → 16.5 → 16.6 ─┬─ 16.7  ─┐
                                         ├─ 16.8  ─┤
                                         ├─ 16.9  ─┼─→ 16.11 ∥ 16.12
                                         └─ 16.10 ─┘
```

- 16.1 to 16.6 form a chain. Each one changes `context.rs` or `membership.rs` in a way the next
  step builds on.
- 16.7, 16.8, 16.9 and 16.10 each need only 16.6, and their order is free. They still share
  `crates/cli/src/main.rs`, `lib.rs` and `error.rs` (16.9 and 16.10 also share `git.rs`), so under
  the same-files rule they are **dependent**. Run them one after another, each on top of the
  previous. If two are built in parallel worktrees anyway, expect conflicts only in list-like
  hunks: clap variants, re-exports and `Error` variants. Whichever of 16.9 and 16.10 lands first
  adds `git::check_attr`, and the other reuses it.
- 16.11 (`README.md`) and 16.12 (`CLAUDE.md`) touch disjoint files, so they can run in parallel
  with each other, after 16.10 and 16.7 to 16.9, which their checks need.
- No step touches `Cargo.toml`, `.github/workflows/release.yml` or the README install section.
  The crates.io packaging work owns those. 16.10 is the only step that edits
  `.github/workflows/ci.yml`.

### 16.1 `core: move repo file helpers into files.rs`

- Files: `context.rs`, new `files.rs`, `lib.rs` (`mod files;`), and the `use` lines of
  `commands.rs`, `status.rs`, `membership.rs`, `remove.rs` and `dismiss.rs`.
- Change: move `read_repo_file`, `read_plaintext`, `write_repo_file` and `ensure_ignored`
  verbatim. `context.rs` is 375 lines without tests, and 16.3 adds about 50 (`CLAUDE.md`, ~400).
- Tests: none new. Acceptance: checks green with an unchanged test count, and
  `git diff --color-moved=zebra` shows only moved lines plus `use`/`mod` lines.

### 16.2 `secret: every secret carries a partition label`

- Files: `secret.rs`, `context.rs`, `error.rs` (`PartitionLabelInvalid(String)`),
  `crates/cli/tests/common/mod.rs`, and new `crates/cli/tests/partitions.rs`.
- Change (5.2):
  - `secret.rs` gains `Label` (an `age::Recipient`) and `label_of`. **API**.
  - `Context::encrypt` adds `Label("default")`.
  - `Context::decrypt` calls `label_of` first, so a file without exactly one valid label fails.
    The value is not used for routing yet.
  - `common::encrypt_to_current_epoch` adds the label.
- Fails before, passes after: the label unit tests (section 11) and test 52. Test 46 (the escape
  hatch) passes unchanged, which shows that age ignores the label.

### 16.3 `core: partitions directory replaces current-epoch`

- Files:
  - `crates/core/src/`: new `partition.rs`, plus `epoch.rs`, `context.rs`, `commands.rs`,
    `status.rs`, `membership.rs`, `dismiss.rs`, `remove.rs`, `users.rs`, `error.rs` and `lib.rs`.
  - Tests: `crates/cli/tests/common/mod.rs`, `crates/cli/tests/cli.rs`,
    `crates/cli/tests/membership.rs` and `crates/cli/tests/partitions.rs`, plus
    `crates/core/tests/directory.rs` if it reads the pointer.
- Change (5.6, 5.7, 7, 7.1):
  - `partition.rs` (public module, **API**): `DEFAULT`, `Partition { members, current }`,
    `load(root, users)`, `write_members`, and the per-partition `read_pointer` and `write_pointer`,
    moved out of `epoch.rs` (**API**: `epoch::read_pointer` and `epoch::write_pointer` move).
  - `users.rs`: the key set of a list of names. Names that are not users are skipped and
    returned for `Warning::UnknownMember`.
  - `init` writes `partitions/default/{members,current-epoch}`.
  - `Context`:
    - It holds `partitions` instead of `current`.
    - `current_epoch(p)`, `epoch_up_to_date(p)`, `require_up_to_date(p)` and `write_epoch(p, …)`
      work per partition, and `encrypt(p, …)` writes label p.
    - `decrypt` tries the label's current epoch first and also returns the partition (a
      `Decrypted` struct instead of a growing tuple).
    - Loading refuses on unmerged `.amaga/partitions` or `.amaga/epochs`.
  - `add` uses `default`. `seal` and `dismiss` run the stale guard for each selected secret's
    partition before writing anything.
  - `status` judges staleness per partition, and an unwrap failure becomes that secret's error
    (7.2).
  - `membership.rs`:
    - `reencrypt` takes the partition set (7.1); `rotate` passes every partition.
    - `user add` adds the name to `default/members` before re-wrapping `default`.
    - `user remove` edits the `members` files of the partitions it re-encrypts, deletes the user
      files, then edits the other partitions' `members` files (those the actor is not in) after the
      pointers. `LastMember` becomes `LastMember { user, partition }`, checked against every
      partition.
  - `error.rs`: `PartitionInvalid(String)`, `UnknownPartition`, and `EpochStale(String)`, which
    now names the partition.
- Test edits:
  - `common::current_epoch_id` takes a partition.
  - Tests 41, 46 and 48 use the new pointer path.
  - Every test that writes a user file by hand also appends the name to `default/members`, the
    state that `user add` leaves (a `common::join_default` helper). This covers `write_member`,
    test 44, `age_member_seals_for_gpg_member_without_gpg` and
    `status_stale_compares_key_sets_not_names`.
  - Test 17 is unchanged: a hand-deleted user file leaves its name in `default/members`, which
    grants nothing and makes `default` stale.
- Fails before, passes after: the `partition.rs` unit tests (section 11) and test 53. Every
  existing test passes after the edits above.

### 16.4 `partitions: create, add --partition, access rule`

- Files:
  - `crates/core/src/`: `membership.rs`, `commands.rs`, `context.rs`, `status.rs`, `outcome.rs`,
    `audit.rs`, `error.rs` and `lib.rs`, plus a new `selection.rs`: `secret_paths_for` moves there
    from `context.rs`, which would pass ~400 lines, and gains `all_secret_paths` for `status`.
  - `crates/cli/src/main.rs` and `crates/cli/tests/partitions.rs`.
- Change:
  - `cmd_partition_create` (7). **API**
  - `cmd_add` gains `partition`. **API**
  - `Context::in_partition`, `NotInPartition` in `decrypt`, and the no-argument filter in
    `secret_paths_for` (7).
  - `status`: `not a member`, `SecretStatus.partition`, `StatusReport.partitions` and
    `Warning::UnknownMember` (7.2). **API**
  - `audit::append` gains a `partition` field (5.3).
  - `error.rs`: `InvalidPartitionName`, `PartitionExists` and `NotInPartition`.
  - CLI: `partition create <p> <member>…`, `add --partition`, and the status rendering (14.3).
- Fails before, passes after: 54 and 55.

### 16.5 `rotate --partition; user remove re-encrypts only the actor's partitions`

- Files: `membership.rs`, `outcome.rs` (`Rotation`, `Warning::PartitionNotRotated`), `audit.rs`
  (only if 16.4 left `rotated` without its partition), `lib.rs`, `crates/cli/src/main.rs` (`rotate
  --partition`, warnings for `rotate`/`user remove`) and `crates/cli/tests/partitions.rs`.
- Change: the `rotate` and `user remove` rows of 7, and decision 16. **API**:
  `cmd_rotate(dir, partitions)`, and `Rotation` from `cmd_rotate` and `cmd_user_remove`.
- Fails before, passes after: 56, 57 and 58.

### 16.6 `partition add and partition remove`

- Files: `membership.rs`, `error.rs` (`AlreadyInPartition`, `NotAPartitionMember`), `lib.rs`,
  `crates/cli/src/main.rs` and `crates/cli/tests/partitions.rs`.
- Change: `cmd_partition_add` and `cmd_partition_remove` (7). **API**
  - The grant sequence (`members` file, audit, re-wrap) becomes one function, shared with
    `user add`.
  - If `membership.rs` passes ~400 lines without tests, move the `cmd_partition_*` functions into
    a new `partition_commands.rs`.
- Fails before, passes after: 59, 60 and 61.

### 16.7 `user add --partition`

- Files: `membership.rs`, `crates/cli/src/main.rs` and `crates/cli/tests/partitions.rs`.
- Change: the `user add` row of 7, using the grant sequence for each partition. **API**:
  `cmd_user_add` gains `partitions`.
- Fails before, passes after: 62.

### 16.8 `partition move`

- Files: `membership.rs` (or `partition_commands.rs`), `audit.rs` (only if a `secret.moved` helper
  is needed), `lib.rs`, `crates/cli/src/main.rs` and `crates/cli/tests/partitions.rs`.
- Change: the `partition move` row of 7. **API**: `cmd_partition_move`.
- Fails before, passes after: 63.

### 16.9 `amaga-partition attribute at add; status flags a mismatch`

- Files: `git.rs`, `commands.rs`, `status.rs`, `error.rs` (`PartitionAttributeInvalid`) and
  `crates/cli/tests/partitions.rs`.
- Change:
  - `git.rs`: `check_attr(root, attrs, paths)`, which runs `git check-attr -z --stdin` and
    returns `(path, attr, value)` triples. Skip this if 16.10 already added it.
  - `add`: choose the partition as in 5.7.
  - `status`: the mismatch error (7.2).
- Fails before, passes after: 64 (which also covers `unspecified` and a value), a `git.rs` unit
  test of the `check-attr -z` output parser on canned output, and a test that a `set` attribute
  makes `add` fail. No unit test runs git: the checks include `GIT_DIR=/nonexistent cargo test`.

### 16.10 `import-git-crypt (ADR-0018)`

- Files:
  - New `import.rs`, holding the command and its pure helpers. If it passes ~400 lines without
    tests, the pure helpers move to `gitcrypt.rs`.
  - `git.rs`: `tracked_files`, `staged_paths`, `rm_cached` (7.5, step 5), and `check_attr`
    unless 16.9 added it.
  - `outcome.rs`: `Imported`, `Warning::KeySkipped` and `Warning::GitCryptHistory`.
  - `error.rs`: `ImportNotFresh`, `NothingToImport`, `GitCryptLocked`, `ImportStagedChanges`,
    `ImportUnknownFingerprint` and `GitCryptAttributeRemains`.
  - `lib.rs`.
  - `crates/cli/src/main.rs`: `ImportGitCrypt { #[arg(long = "name", value_name = "FPR=NAME")]
    names: Vec<String> }`, documented as "Migrate an unlocked git-crypt repository", rendered as
    in 14.3.
  - New `crates/cli/tests/import_git_crypt.rs`.
  - `crates/cli/tests/common/mod.rs`: a skip helper for a missing `git-crypt`, beside the gpg one.
  - `.github/workflows/ci.yml`: a Linux-only step, `sudo apt-get install -y git-crypt`.
- Change: 7.5. **API**: `cmd_import_git_crypt` and `Imported`.
- Fails before, passes after: the import unit tests (section 11), and 65, 66, 67, 68 and 69.
  Acceptance: the ubuntu CI log shows test 69 ran, with no skip notice.

### 16.11 `docs: README for partitions and git-crypt import`

- Files: `README.md`, excluding the install section.
- Change:
  - "How it works": partitions, labels and the pointer path.
  - The escape hatch path.
  - Team workflow: a member restricted to one partition.
  - Command reference rows: `add --partition`, `user add --partition`, `rotate --partition`,
    `partition create|add|remove|move` and `import-git-crypt`.
  - A new section, "Migrating from git-crypt": `git-crypt unlock`, then `init` and commit, then
    `import-git-crypt`, review and commit. Teammates run `open` after pulling. It covers the
    history warning and the local git-crypt config left in place.
  - The removal workflow, with the partition warning.
  - Branches: `members` conflicts.
  - Security bullets: partition access is cryptographic, labels and member lists are readable,
    and git-crypt history stays readable.
- Acceptance: every command in the reference appears in `git-amaga --help` or
  `git-amaga partition --help`, and `grep -n 'amaga/current-epoch' README.md` prints nothing.

### 16.12 `docs: CLAUDE.md module map`

- Files: `CLAUDE.md`.
- Change: add `files.rs` (repo file helpers), `partition.rs` (partition directory, pointers),
  `selection.rs` (which secrets a command acts on),
  `import.rs` (`import-git-crypt`, plus `gitcrypt.rs` and `partition_commands.rs` if they were
  split out). `membership.rs` becomes "`rotate`, `user add`/`user remove`, `partition`
  commands". `secret.rs` gains "partition label". The tests list gains
  `crates/cli/tests/partitions.rs` and `crates/cli/tests/import_git_crypt.rs`.
- Acceptance: every path named in `CLAUDE.md` exists (`ls` each).
