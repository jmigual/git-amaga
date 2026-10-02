//! Typed errors for git-amaga. One variant per user-actionable failure (plan section 10.2).

use thiserror::Error;

use crate::secret::PlaintextState;

#[derive(Debug, Error)]
pub enum Error {
    /// age failed to encrypt a secret to its recipients.
    #[error("failed to encrypt secret: {0}")]
    Encrypt(#[from] age::EncryptError),

    /// age failed to decrypt a secret (no matching identity, tampered ciphertext, ...).
    #[error("failed to decrypt secret: {0}")]
    Decrypt(#[from] age::DecryptError),

    /// I/O failure while streaming ciphertext through age.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The decrypted payload has no `\n` separating the header from the body.
    #[error("secret header is not terminated by a newline")]
    HeaderMissingNewline,

    /// The header is not valid JSON, has unknown fields, or fails to (de)serialize.
    #[error("secret header is not valid JSON: {0}")]
    HeaderJson(#[from] serde_json::Error),

    /// The header's `v` field is not `1`.
    #[error("unsupported secret format version {0}")]
    UnsupportedVersion(u8),

    /// An armored OpenPGP key could not be parsed.
    #[error("armored OpenPGP key is not valid: {0}")]
    GpgKeyParse(String),

    /// An armored OpenPGP key file contains more than one key.
    #[error("armored OpenPGP key file must contain exactly one key")]
    GpgKeyMultiple,

    /// An armored OpenPGP key failed signature binding verification (for example, a
    /// third-party certification).
    #[error(
        "armored OpenPGP key failed binding verification: {0} (hint: re-export with `gpg --export --armor --export-options export-minimal <fpr>`)"
    )]
    GpgKeyBindings(String),

    /// The primary key carries a `KeyRevocation` signature.
    #[error("armored OpenPGP key has been revoked")]
    GpgKeyRevoked,

    /// No subkey is suitable for encryption (not revoked, flagged for encryption, capable
    /// algorithm).
    #[error(
        "armored OpenPGP key has no usable encryption subkey (hint: `gpg --quick-add-key <fpr> default encr`)"
    )]
    GpgKeyNoEncryptionSubkey,

    /// The primary key or the selected encryption subkey is expired (add-time check only).
    #[error("armored OpenPGP key is expired")]
    GpgKeyExpired,

    /// A `git` subprocess exited with a non-zero status for a reason other than "unset config
    /// key" (plan 10.2: git.rs runs git as a subprocess, never through a shell).
    #[error("git failed: {0}")]
    Git(String),

    /// `git rev-parse --show-toplevel` failed: the current directory is not inside a Git
    /// repository (plan: `init` "requires a Git repo").
    #[error("not inside a Git repository")]
    NotAGitRepo,

    /// `std::env::home_dir()` returned `None` while resolving the default identity path
    /// (plan 5.5 / `keygen`).
    #[error("could not determine the home directory")]
    NoHomeDir,

    /// `keygen` refuses to overwrite an existing identity file (plan: `keygen`).
    #[error("identity file '{0}' already exists (refusing to overwrite)")]
    IdentityExists(String),

    /// An `age1…` string failed to parse: a `.txt` recipients line, or an `init`/`user add`
    /// `KEY` argument. Both are public keys, so it is safe to echo the offending text.
    #[error("invalid age key: '{0}'")]
    AgeRecipientParse(String),

    /// An `AGE-SECRET-KEY-1…` line in an identity file failed to parse (plan 5.5). Never echoes
    /// the line itself, since it may be secret key material.
    #[error("invalid age identity at {path}:{line}")]
    IdentityParse { path: String, line: usize },

    /// An I/O operation failed on a specific, named file (a `KEY` argument, an identity file):
    /// carries the path, unlike a bare [`Error::Io`].
    #[error("{path}: {source}")]
    IoPath {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// A file in `.amaga/users/` is not `<name>.txt` or `<name>.asc` with a valid lowercase
    /// name (plan 5.1).
    #[error(
        "'{0}' in .amaga/users is not a valid member file (expected '<name>.txt' or '<name>.asc' with a lowercase name)"
    )]
    UsersInvalidFile(String),

    /// `.amaga/users` has no member files at all (plan 5.1).
    #[error("no user files found in .amaga/users (repository has no members)")]
    NoUsers,

    /// A member file stem has zero usable keys (plan 5.1).
    #[error("member '{0}' has no usable keys")]
    UsersEmptyMember(String),

    /// The same key string, or the same OpenPGP primary fingerprint, appears twice across all
    /// members (plan 5.1).
    #[error("key '{0}' is used by more than one member")]
    UsersDuplicateKey(String),

    /// A member file's content failed to validate (plan 5.1): names which file, wrapping the
    /// underlying cause.
    #[error("{file}: {source}")]
    UsersFileError {
        file: String,
        #[source]
        source: Box<Error>,
    },

    /// No loaded identity (age or GPG) matches any member (plan 5.5).
    #[error(
        "not a member of this repository (members: {0}). Run `keygen` and have a member run `user add`, set `amaga.identity`, or import your GPG secret key / insert your card."
    )]
    NotAMember(String),

    /// No age identity is configured, and no `KEY` was given to supply one (plan: `init`).
    #[error(
        "no age identity configured (hint: run `git-amaga keygen`, or pass KEY arguments explicitly)"
    )]
    NoIdentity,

    /// A path argument resolves outside the repository (plan section 7).
    #[error("path '{0}' is outside the repository")]
    PathOutsideRepo(String),

    /// A path argument contains control characters (plan section 7).
    #[error("path '{0}' contains control characters")]
    PathControlChar(String),

    /// A path argument lies under `.git/` or `.amaga/` (plan section 7).
    #[error("path '{0}' is under .git/ or .amaga/")]
    PathManaged(String),

    /// A path argument's plaintext name ends in `.amaga` or `.amaga-tmp` (plan section 7).
    #[error("path '{0}' must not end in .amaga or .amaga-tmp")]
    PathBadSuffix(String),

    /// `init`'s `<name>` argument is not a valid member name (plan 5.1).
    #[error("'{0}' is not a valid member name (expected [a-z0-9][a-z0-9._-]{{0,63}})")]
    InvalidMemberName(String),

    /// `init` found an existing `.amaga/` directory (plan: `init`).
    #[error(".amaga already exists (repository is already initialized)")]
    AlreadyInitialized,

    /// More than one OpenPGP key file was given among the `KEY` arguments (plan section 7:
    /// "at most one is allowed per member").
    #[error("at most one OpenPGP key file is allowed per member")]
    MultipleGpgKeys,

    /// An `add` path is not a regular file (symlinks are rejected, plan section 7).
    #[error("'{0}' is not a regular file")]
    NotARegularFile(String),

    /// A plaintext path is tracked by git; the remediation is printed, never run.
    #[error(
        "'{0}' is already tracked by git; run `git rm --cached -- {0}` to untrack it, then retry"
    )]
    PlaintextTracked(String),

    /// `add` found `<path>.amaga` already on disk.
    #[error("'{0}' already exists; run `seal` to update it instead of `add`")]
    CiphertextExists(String),

    /// `add` found `<path>.amaga` in history and `--force` was not given.
    #[error(
        "'{0}' already exists in git history; run `git checkout <rev> -- {0}` then `seal` to keep its exposure history, or rerun `add` with --force to drop it"
    )]
    CiphertextInHistory(String),

    /// `git ls-files -u -- '*.amaga'` is non-empty (plan section 7).
    #[error("unmerged *.amaga files must be resolved first: {0}")]
    UnmergedAmagaFiles(String),

    /// The ensure-ignored step (plan 5.4) could not make the path ignored, for example because
    /// of a negation rule elsewhere.
    #[error("'{0}' could not be ignored (check for a conflicting negation rule in .gitignore)")]
    PlaintextNotIgnored(String),

    /// A secret failed to decrypt; names the `.amaga` file and, for a gpg failure, the member.
    #[error("{path}{}: {source}", .member.as_ref().map(|m| format!(" (member {m})")).unwrap_or_default())]
    SecretUndecryptable {
        path: String,
        member: Option<String>,
        #[source]
        source: Box<Error>,
    },

    /// `seal` refused an `Outdated` or `Conflict` plaintext without `--force`.
    #[error(
        "'{0}' is not in sync with the repository (state: {1:?}); `seal --force` overwrites the repository version with your local copy, `open --force` replaces your copy"
    )]
    SealRefused(String, PlaintextState),

    /// `open` refused to replace a `Modified` or `Conflict` plaintext without `--force`.
    #[error(
        "'{0}' has local changes that --force would discard (state: {1:?}); rerun with --force, or `seal` first"
    )]
    OpenRefused(String, PlaintextState),

    /// `close` refused to delete a plaintext that is not `InSync`.
    #[error(
        "'{0}' has not been sealed (state: {1:?}); run `seal` first, or `open --force` to discard local changes"
    )]
    CloseRefused(String, PlaintextState),
}
