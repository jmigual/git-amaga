# git-amaga v1 plan

**Goal:** a single self-contained Rust binary that encrypts whole secret files in a Git repository
as explicit, tracked `*.amaga` ciphertext files next to ignored plaintext, with user add/remove,
key rotation, an audit log, and reliable tracking of which secrets still need their real
credentials rotated after someone lost access. Members hold either an age key or a GPG
(OpenPGP) key.

**Runtime dependencies:** the `git` executable. Members who decrypt with a GPG key also need `gpg`
(2.1+, with gpg-agent). Nobody needs the `age` CLI, and age-only members never need `gpg`.

**Decision records:** the decisions below are summarised as ADRs in [`docs/adrs/README.md`](docs/adrs/README.md).

## 1. Changes from the original plan

| # | Change | Reason |
|---|--------|--------|
| 1 | Each secret is one `age` file encrypted directly to all current recipients. Dropped epochs, `current_epoch`, `key.age`, HKDF, XChaCha20-Poly1305 and the custom binary container. | Removes a hand-built crypto composition and a whole class of "mixed epoch" states. Membership changes still rewrite every secret, as before. Trade-offs are covered in section 4. |
| 2 | Replaced `content_generation` / `last_exposure_*` with one rule: every write records the recipient set. A rewrite that drops recipients without changing the plaintext adds them to `exposed_to`. A plaintext change clears `exposed_to`. | Gives the same results for the original scenarios. It also handles cases the original missed: secrets merged in from a branch that still include a removed user, interrupted removals, and hand-edited membership. |
| 3 | Dropped the transaction journal and the `recover` command. Every secret is decrypted first, then membership is changed, then secrets are rewritten. If the run is interrupted, `status` reports "stale recipients" and running `rotate` again finishes the job. | `rotate` is idempotent, and Git already keeps the previous state. No local journal is needed. |
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
| 16 | GPG members: each secret stays one age file, and a GPG member gets an extra `pgp` stanza holding the age file key encrypted to their OpenPGP key (5.2.1). Encryption is in-process with rPGP; decryption runs `gpg --decrypt`. | Requested: the user's own keys are GPG (smartcards via gpg-agent), with age as an option. One file format and one set of rules; `age -d` keeps working for age members; age-only members never need gpg. Considered: a separate `.gpg` file per secret (two formats, two exposure states) and OpenPGP as the outer format (loses the age escape hatch). |
| 17 | A GPG key is identified by its **encryption subkey** fingerprint (`pgp:<FPR>`), not the primary. | Replacing a lost card's subkey is then a key change: secrets go stale and `rotate` flags exposure, exactly as for a removed age key. Extending expiry keeps the fingerprint, so it changes nothing. |
| 18 | GPG key expiry is checked only at `init`/`user add`. Structure, signatures and revocation are checked on every load. | Loading stays deterministic (no clock), and an expired key still decrypts in gpg. See decision 9. |
| 19 | A `KEY` can be a GPG key ID, fingerprint or email: the tool looks it up in the local keyring and exports it export-minimal (7.4). `keygen` prints the `user add` line for the new age key. | Requested: users should not type `gpg`/`age` commands, and the tool then always stores the right export format. ADR-0013. |

## 2. Open decisions for the user

Defaults are already chosen in this plan. Each item below can be flipped.

1. **Per-file age instead of epoch keys.** Choose epochs instead only if you need "only members can produce valid ciphertext". That property does not hold against repository writers anyway (section 4).
2. **SSH `ssh-ed25519` recipients are deferred.** age's `ssh` feature adds `aes`, `cbc` and `bcrypt-pbkdf`, and decrypts `ssh-rsa` identities in-process. `rsa 0.9` is already in the tree via `pgp`, but only for public-key encryption and signature verification. RUSTSEC-2023-0071 (Marvin) is a timing attack on RSA *private-key* operations, which this tool never performs (gpg does GPG decryption). `ssh-rsa` identities would change that.
3. **Release targets:** `x86_64-unknown-linux-musl` and `x86_64-pc-windows-msvc`. Possible additions: macOS (aarch64/x86_64) and aarch64 Linux.
4. **`status` exit code:** "needs rotation" alone exits 0. It is a known, tracked condition and could last weeks. Everything else that `status` flags exits 1.
5. **Changing an existing member's key:** edit `.amaga/users/<name>.txt` or replace `<name>.asc`, then run `rotate`. Removing any key marks secrets exposed to that member, which is conservative: correct for a lost device, noisy for a routine swap. The alternative is a `user key add/remove` subcommand that can skip marking. The same rule means a removed user who is later re-added stays in `exposed_to` until each file's content changes.
6. **Audit log as a separate file vs `git log` only.** Kept because the goal names it. It is informational (unsigned, editable) and is not a security control.
7. **Dropping `audit verify` and the hash chain.** Both were in the original scope. The chain cannot survive two branches that both append (change 4), and a writer who can rewrite history can recompute it anyway. Restoring it means either forbidding parallel security changes or adding a merge-repair command.
8. **`open` vs `unlock`.** You called the decrypt-all command `unlock`. The plan keeps `open` because it pairs with `seal`/`close`. Renaming it, or adding a clap alias, is one line.
9. **Expired GPG keys (change 18).** By default, a key that expires after `user add` is still encrypted to. The alternative is to refuse, as `gpg -e` does. That blocks every `seal` and `rotate` for the whole team until the member re-exports an extended key. It also makes loading depend on the clock.
10. **Confirming a looked-up GPG key (change 19).** By default the tool prints the fingerprint and user ID it used and does not prompt. The alternative is a yes/no prompt before writing, which blocks scripting. The printed line, the audit event and the committed `.asc` diff are the review points.
11. **Fetching GPG keys from the network.** By default the lookup reads only the local keyring. Fetching from a keyserver or WKD (`gpg --locate-keys`) is deferred (section 13): the key would still need out-of-band verification, which the user does by importing it first.

## 3. Principles and scope

- **Explicit files, no Git filters.** `secrets/prod.env` (plaintext, ignored) sits next to `secrets/prod.env.amaga` (age ciphertext, tracked). `git status` always shows exactly what will be committed.
- **Never stage, commit, or silently overwrite/delete plaintext.** Commands change the working tree and print which repository files changed.
- **Whole-file semantics.** Exposure and "changed" are per file, not per value inside a file. Status says "content changed since exposure", never "credential rotated".
- **Re-encryption is not credential rotation.**
- **Established crypto only:** the age format via the `age` crate. OpenPGP encryption via `pgp` (rPGP), and OpenPGP decryption via the user's `gpg`. Nothing hand-rolled. The only extension is the `pgp` stanza, written through age's public `Recipient`/`Identity` traits.
- **One crate, no traits of our own, no async, no daemon.** Run the `git` and `gpg` CLIs as subprocesses (no libgit2, no gpgme). Never through a shell.
- **Fail closed.** Decrypt/auth failure, unknown header version, invalid user file → error with a remediation hint. Never write partial plaintext. Panics are bugs.

Out of scope for v1: per-file ACLs, rotating external credentials, a key server/KMS, merge helpers, history rewriting, signed audit, malicious authorised users or malicious repository writers, symlinked secrets (rejected), passphrase-protected identity files.

## 4. Threat model

**Guarantees**
- People who can read the repository without a member identity cannot decrypt current secrets.
- After `user remove X`, every secret in the working tree is re-encrypted without X's keys.
- A newly added member cannot decrypt ciphertext from history before they were added. It was never encrypted to them.
- Modified ciphertext fails authentication (age payload AEAD and header MAC).
- Every secret that a removed key could have read is flagged until its content changes.
- Plaintext that is tracked or not ignored is reported as critical.

**Limitations (README and `--help`)**
- A removed user keeps any plaintext they saw, and can still decrypt historical commits from when they were a member. Only rotating the external credential fixes that. The tool can only flag it.
- age has no sender authentication. Anyone with write access can replace user files or forge ciphertext. Use branch protection, review and signed commits. The original design had the same exposure via `users/` and `key.age`.
- A compromised member identity exposes everything that member can read.
- The audit log is informational. Its integrity is whatever Git history gives you.
- GPG keys come only from the committed `.asc` files. `init`/`user add` may export a key from the local public keyring (7.4), but loading never reads the keyring, and the tool never contacts a keyserver. A revocation or a new subkey takes effect when the member commits a re-exported `.asc` and someone runs `rotate`.
- A GPG key that expires after `user add` is still encrypted to (decision 9).
- GPG decryption trusts the `gpg` on PATH and its agent. It costs one `gpg` call per secret: `open`, `status` and `rotate` on N secrets mean N calls. The agent caches the PIN, but a card set to touch-always needs one touch per file.
- Manual escape hatch: age members can use `age -d`. GPG members cannot decrypt without the tool, because the age CLI cannot take a file key that gpg has unwrapped.

**Per-file age vs epoch keys (decision 1)**

Per-file age loses three things:
- Forgery resistance. Moot here: writers are not trusted anyway.
- Recipient-set visibility without decrypting. X25519 stanzas are anonymous, so the set is recorded inside the encrypted header and `status` needs an identity. (`pgp` stanzas name their subkey, but that fingerprint is already public in `.amaga/users`.)
- About 100 bytes per recipient per file.

Per-file age gains:
- No custom container, KDF or AEAD composition.
- No epoch directory or current-epoch pointer.
- No mixed-epoch state.
- Interoperability: `age -d -i key.txt f.amaga | tail -n +2` recovers the plaintext for age members.

## 5. On-disk formats

```text
repo/
├── .amaga/
│   ├── users/alice.txt          # age recipients file: "age1…" per line, '#' comments, blank lines ok
│   ├── users/bob.asc            # one armored OpenPGP public key (gpg --export --armor --export-options export-minimal)
│   └── audit.jsonl              # append-only, merge=union
├── .gitattributes               # "*.amaga binary", ".amaga/audit.jsonl merge=union", ".gitignore merge=union"
├── .gitignore                   # managed block, see 5.4
└── secrets/prod.env.amaga       # tracked ciphertext; secrets/prod.env is ignored plaintext
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
- The set of user files *is* the current membership. There is no other pointer.

### 5.2 Secret file (`*.amaga`)

A standard binary age file encrypted to every member key: X25519 stanzas for `.txt` keys, `pgp` stanzas (5.2.1) for `.asc` keys. The decrypted payload is:

```text
{"v":1,"recipients":{"alice":["age1…"],"bob":["pgp:97509ABD…"]},"exposed_to":{"charlie":["age1…"]}}\n
<body: the plaintext bytes, arbitrary binary>
```

- The header is one compact JSON line (serde_json never emits a raw newline).
- Parse rules: split at the first `\n`, use `deny_unknown_fields`, `v` must be `1` or it is an error and the file is not modified. `exposed_to` is omitted when empty.
- Both maps are `BTreeMap<String, BTreeSet<String>>` (user name → key strings, 5.1).
- "Stale": the header's key set differs from the current key set. Compare keys only; names are just labels.

### 5.2.1 `pgp` stanza

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
  - `rotated`
  - `secret.added` / `secret.updated` / `secret.removed` (with `path`)
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
- **Decryption identities:** age identities first, then one `GpgIdentity` for the held members. age takes the first identity that claims any stanza (`find_map` over identities in `Decryptor::decrypt`), so gpg runs only when no age identity matches.
- **Base hashes:** stored at `$(git rev-parse --path-format=absolute --git-path amaga-base)`. Verified: in a linked worktree this resolves to `.git/worktrees/<wt>/amaga-base`, i.e. per worktree.
- Base file format: lines of `<sha256-hex> <repo-relative-path>`, rewritten atomically. It records the SHA-256 of the body the local plaintext was last synchronised with.

## 6. Core rules (pure functions, unit-tested)

### 6.1 Exposure rule: `next_header(old: Option<&Header>, plaintext_changed: bool, current: &Recipients) -> Header`

```text
recipients = current
exposed_to = if old is None or plaintext_changed: {}
             else: old.exposed_to ∪ { (user, key) in old.recipients | key ∉ keys(current) }
```

Every ciphertext write goes through this function. Consequences:

- `user remove` flags every existing secret.
- `rotate` / `user add` change nothing.
- An edited and sealed file is cleared.
- A secret added after a removal is never flagged.
- A file merged in from a branch that still lists the removed user gets flagged on the next `rotate`.

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

Every ciphertext, plaintext and base-file write goes through one helper:
1. Write `<path>.amaga-tmp`. On Unix, plaintext temp files are created with mode `0600`.
2. `sync_all`.
3. `std::fs::rename` (replaces the target on Windows too).

Commands that need an identity load it once (5.5), and the actor comes from it. Encryption never needs gpg or any identity beyond that.

`KEY` arguments (`init`, `user add`) are classified in this order (ADR-0013):
1. Starts with `age1`: an age recipient.
2. An existing file whose name ends in `.asc`: an armored OpenPGP public key file.
3. Anything else: a GPG key spec (key ID, fingerprint, email or user ID) looked up in the local keyring (7.4).

At most one OpenPGP key (file or lookup) is allowed per member. It must pass 5.1 and the add-time check: neither the primary key nor the selected subkey may be expired, judged from the `key_expiration_time()` of the newest self-signature plus the key's `created_at()`. The `.asc` (file contents or gpg's export) is stored byte-for-byte. For each OpenPGP key, print `<name>: GPG key <PRIMARY-FPR> "<first user ID>"`.

| Command | Behaviour |
|---------|-----------|
| `keygen [PATH]` | Generate `x25519::Identity`. Default path is `home_dir()/.config/git-amaga/identity.txt`. Refuse to overwrite. Write `# public key: age1…` followed by the secret key (0600 on Unix). If `amaga.identity` is unset in global config, set it. Print the public key on stdout (kept alone so scripts can capture it), then on stderr: `to join a repository, send this to a member: git-amaga user add <name> age1…` with the real key. |
| `init <name> [KEY…]` | Requires a Git repo and no `.amaga/`. With no `KEY`, use the configured age identity's public keys (error if there is none). `KEY`s follow the rules above, so `init alice alice@example.org` works with a key in the local keyring. Writes `users/<name>.txt` and/or `users/<name>.asc`, `.gitattributes` lines, the `.gitignore` block, and the audit `init` event. |
| `add [--force] <path>…` | Path must be a regular file (not a symlink), inside the repo, and not tracked (`git ls-files --error-unmatch`). If tracked, print the `git rm --cached -- <path>` remediation and stop; never run it. Refuse if `<path>.amaga` already exists. Warn if the plaintext path appears in history (`git rev-list -n1 --all -- <path>`). If `<path>.amaga` appears in history, refuse unless `--force`, and point to `git checkout <rev> -- <path>.amaga` followed by `seal` to keep its exposure state; `--force` says that exposure history is dropped. Run the ensure-ignored step. Encrypt with `next_header(None, …)`. Record the base. Audit `secret.added`. |
| `seal [--force] [<path>…]` | No paths means every secret whose plaintext exists. Run the ensure-ignored step. Decide by plaintext state: `InSync` → no-op (ciphertext bytes untouched; the base is re-recorded when it differs). `Modified` → encrypt with `plaintext_changed = true`, record base, audit `secret.updated`. `Outdated` / `Conflict` → refuse unless `--force`. When `--force` clears a non-empty `exposed_to`, warn that the needs-rotation flag is being cleared and that the local copy may hold the old value. |
| `open [--force] [<path>…]` | No paths means all. Decrypt and authenticate fully, refuse if the plaintext path is tracked in the index (same remediation as `add`), then run the ensure-ignored step, before writing anything. `Closed` / `Outdated` → write the plaintext. `InSync` → no-op, except the base is re-recorded when it differs. `Modified` / `Conflict` → refuse unless `--force`. Record base. |
| `close [<path>…]` | Delete the plaintext only when `InSync`. Drop the base entry. |
| `remove <path>…` | Delete the `.amaga` file and the base entry. Leave the plaintext and its ignore entry alone. Audit `secret.removed`. |
| `user add <name> <KEY>…` | Refuse if `users/<name>.txt` or `.asc` exists (key changes: decision 5). Resolve `KEY`s with the same code as `init` (age key, `.asc` file, or keyring lookup). Validate (5.1 + add-time expiry) before re-encrypting. Re-encrypt all (7.1). |
| `user remove <name>` | Must exist and must not be the last user. The files being removed are not validated, so a revoked or broken key can still be removed. Re-encrypt all (7.1). |
| `rotate` | Re-encrypt all with fresh age file keys. Audit `rotated`. This is also the recovery command. |
| `status` | See 7.2. |

### 7.1 Re-encrypt all (shared by `rotate`, `user add`, `user remove`)

1. Read and decrypt **every** secret into memory. If any fails, abort before writing anything and list the files that failed.
2. `user add/remove` only: write or delete the user file and append the audit event.
3. Load the current recipients from `.amaga/users`.
4. For each secret, write `encrypt(next_header(Some(old), false, current), body)` atomically.

If a run is interrupted after step 2:
- The membership change is already on disk.
- Some secrets are stale; `status` reports them.
- Rerunning `rotate` completes the work, and exposure marking is still correct because it comes from each file's own header.
- If the actor removed themselves, they are no longer a member and get `NotAMember`. Another member reruns `rotate`.

There is no clean-tree precondition. Unsealed local edits are unaffected, because re-encryption uses the ciphertext payload and plaintext hashes do not change.

Ceiling: all secrets are held in memory at once. Stream per file if anyone stores large files.

### 7.2 `status`

Requires an identity. Prints the members, then one line per secret. Problems first.

**Errors (exit 1):**
- Invalid user files.
- `.amaga` paths that `git check-attr text` does not report as `unset`.
- A secret that fails to decrypt (no matching key, tampered, unknown `v`).
- Unmerged `.amaga` files.
- **Critical:** plaintext tracked (`git ls-files`), or any managed plaintext path not ignored (`check-ignore --no-index`), checked whether or not the plaintext exists.
- Stale recipients. Hint: `run git-amaga rotate`.
- Plaintext state `Modified`, `Outdated` or `Conflict`, each with its action.

**Warning (exit 0):** `NEEDS ROTATION: exposed to charlie`, taken from `exposed_to`.

Usage errors exit 2 (clap's default).

### 7.3 Running gpg

- Decrypt: `gpg --quiet --max-output 16 --decrypt`. The stanza body goes to stdin, which must be closed before waiting. Capture stdout and stderr. `--max-output` bounds the output (verified: gpg exits 2 when it is exceeded).
- Do **not** pass `--batch` or `--pinentry-mode`. gpg-agent must be able to run pinentry for the PIN or for an "insert card" prompt. Piping gpg's stdin and stderr does not affect pinentry.
- On non-zero exit, or output that is not 16 bytes: `GpgError { fpr, stderr }`, reported per secret with the member's name. Pass gpg's stderr through verbatim (for example `decryption failed: No secret key`, or `Operation cancelled` when the card prompt is dismissed), followed by the fixed hint "is the card inserted, and can gpg-agent show a PIN prompt (`export GPG_TTY=$(tty)`)?". Do not parse gpg's messages.
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

## 8. Branches and merges

- `*.amaga` files are `binary`, so concurrent edits produce a normal conflict with "ours" left in the working tree and no markers. To resolve: `git checkout --ours|--theirs -- f.amaga && git add f.amaga` (verified: `checkout --theirs` alone leaves the path unmerged), then `git-amaga open --force f` and edit / `seal`. The three-way check makes the stale-plaintext case visible.
- Concurrent membership changes touch different files under `.amaga/users/` and normally merge cleanly. After the merge, `status` reports secrets as stale until someone runs `rotate`.
- Secrets that exist only on a branch which predates a removal still list the removed user. After the merge they are reported as **stale**, and `rotate` flags them `exposed_to` that user. This is correct whenever that branch was pushed while the user had access.
- `.gitignore` and `audit.jsonl` merge by union (verified). Lines from both sides are kept, ordered by side rather than by time. If a hosting platform's merge ignores `merge=union`, resolve the conflict by keeping both sides' lines.
- A sealed but uncommitted `.amaga` file discarded with `git checkout`/`reset` makes the plaintext `Outdated`. The plaintext is then the only copy of that content: `seal --force` it rather than `open` (README).

## 9. Removal workflow (README)

1. Revoke the person's repository access at the hosting provider.
2. `git-amaga user remove charlie`, review `git status`, and commit everything in one commit.
3. `git-amaga status` lists every secret marked `NEEDS ROTATION`.
4. Rotate each real credential, edit the plaintext, `seal`, and commit, until nothing is flagged.

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
- `next_header`: every row of 6.1, including a re-added user and a rename where the same key now sits under a new name.
- `plaintext_state`: every row of 6.2.
- Header parsing rejects missing `\n`, unknown fields, and `v != 1`.
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
12. `user_add_new_member_decrypts_current_not_history`
13. `user_remove_locks_out_and_flags_all`
14. `seal_change_clears_only_that_file`
15. `secret_added_after_removal_not_flagged`
16. `rotate_preserves_exposure`
17. `interrupted_remove_reported_stale_and_rotate_completes`: delete a user file by hand, then check that `status` exits 1 and that `rotate` flags exposure.
18. `works_in_linked_worktree`: `.git` is a file, and the base file is per worktree.
19. `merged_branch_secret_flagged_after_removal`: a branch adds a secret before a removal on main; after the merge, `status` reports it stale and `rotate` flags it.
20. `user_remove_with_undecryptable_secret_changes_nothing`: `users/` and `audit.jsonl` are untouched.
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

## 12. Implementation steps

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

SSH recipients · `user key` subcommands · backup copy of a plaintext before `open` overwrites it · pre-commit hook that blocks tracked plaintext · `git diff` textconv for decrypted diffs · `--stage` · signed audit/commits integration · per-secret ACLs · passphrase-protected age identities / age plugins (`age-plugin-yubikey`; YubiKeys already work as GPG cards) · honouring `gpg.program` · warning before a GPG key expires · encrypting to an OpenPGP primary key that has no encryption subkey · one gpg call for many files · fetching GPG keys from a keyserver/WKD (`gpg --locate-keys`) at `init`/`user add` · macOS/aarch64 release targets.
