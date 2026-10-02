//! Typed errors for git-amaga. One variant per user-actionable failure (plan section 10.2).

use thiserror::Error;

use crate::secret::PlaintextState;

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to encrypt secret: {0}")]
    Encrypt(#[from] age::EncryptError),

    #[error("failed to decrypt secret: {0}")]
    Decrypt(#[from] age::DecryptError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("secret header is not terminated by a newline")]
    HeaderMissingNewline,

    /// Also raised for unknown fields.
    #[error("secret header is not valid JSON: {0}")]
    HeaderJson(#[from] serde_json::Error),

    #[error("unsupported secret format version {0}")]
    UnsupportedVersion(u8),

    #[error("armored OpenPGP key is not valid: {0}")]
    GpgKeyParse(String),

    #[error("armored OpenPGP key file must contain exactly one key")]
    GpgKeyMultiple,

    #[error(
        "armored OpenPGP key failed binding verification: {0} (hint: re-export with `gpg --export --armor --export-options export-minimal <fpr>`)"
    )]
    GpgKeyBindings(String),

    #[error("armored OpenPGP key has been revoked")]
    GpgKeyRevoked,

    #[error(
        "armored OpenPGP key has no usable encryption subkey (hint: `gpg --quick-add-key <fpr> default encr`)"
    )]
    GpgKeyNoEncryptionSubkey,

    /// Add-time check only.
    #[error("armored OpenPGP key is expired")]
    GpgKeyExpired,

    /// A git subprocess failed, other than for an unset config key.
    #[error("git failed: {0}")]
    Git(String),

    #[error("not inside a Git repository")]
    NotAGitRepo,

    #[error("could not determine the home directory")]
    NoHomeDir,

    #[error("identity file '{0}' already exists (refusing to overwrite)")]
    IdentityExists(String),

    /// Public keys, so echoing the offending text is safe.
    #[error("invalid age key: '{0}'")]
    AgeRecipientParse(String),

    /// Never echoes the line: it may be secret key material.
    #[error("invalid age identity at {path}:{line}")]
    IdentityParse { path: String, line: usize },

    /// Like [`Error::Io`], but names the file.
    #[error("{path}: {source}")]
    IoPath {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "'{0}' in .amaga/users is not a valid member file (expected '<name>.txt' or '<name>.asc' with a lowercase name)"
    )]
    UsersInvalidFile(String),

    #[error("no user files found in .amaga/users (repository has no members)")]
    NoUsers,

    #[error("member '{0}' has no usable keys")]
    UsersEmptyMember(String),

    /// Same key string or OpenPGP primary fingerprint across members.
    #[error("key '{0}' is used by more than one member")]
    UsersDuplicateKey(String),

    #[error("{file}: {source}")]
    UsersFileError {
        file: String,
        #[source]
        source: Box<Error>,
    },

    #[error(
        "not a member of this repository (members: {0}). Run `keygen` and have a member run `user add`, set `amaga.identity`, or import your GPG secret key / insert your card."
    )]
    NotAMember(String),

    #[error(
        "no age identity configured (hint: run `git-amaga keygen`, or pass KEY arguments explicitly)"
    )]
    NoIdentity,

    #[error("path '{0}' is outside the repository")]
    PathOutsideRepo(String),

    #[error("path '{0}' contains control characters")]
    PathControlChar(String),

    #[error("path '{0}' is under .git/ or .amaga/")]
    PathManaged(String),

    #[error("path '{0}' must not end in .amaga or .amaga-tmp")]
    PathBadSuffix(String),

    #[error("'{0}' is not a valid member name (expected [a-z0-9][a-z0-9._-]{{0,63}})")]
    InvalidMemberName(String),

    #[error(".amaga already exists (repository is already initialized)")]
    AlreadyInitialized,

    #[error("at most one OpenPGP key file is allowed per member")]
    MultipleGpgKeys,

    #[error("'{0}' is not a regular file")]
    NotARegularFile(String),

    /// The remediation is printed, never run.
    #[error(
        "'{0}' is already tracked by git; run `git rm --cached -- {0}` to untrack it, then retry"
    )]
    PlaintextTracked(String),

    #[error("'{0}' already exists; run `seal` to update it instead of `add`")]
    CiphertextExists(String),

    #[error(
        "'{0}' already exists in git history; run `git checkout <rev> -- {0}` then `seal` to keep its exposure history, or rerun `add` with --force to drop it"
    )]
    CiphertextInHistory(String),

    #[error("unmerged *.amaga files must be resolved first: {0}")]
    UnmergedAmagaFiles(String),

    #[error("'{0}' could not be ignored (check for a conflicting negation rule in .gitignore)")]
    PlaintextNotIgnored(String),

    /// Names the `.amaga` file and, for a gpg failure, the member.
    #[error("{path}{}: {source}", .member.as_ref().map(|m| format!(" (member {m})")).unwrap_or_default())]
    SecretUndecryptable {
        path: String,
        member: Option<String>,
        #[source]
        source: Box<Error>,
    },

    #[error(
        "'{0}' is not in sync with the repository (state: {1:?}); `seal --force` overwrites the repository version with your local copy, `open --force` replaces your copy"
    )]
    SealRefused(String, PlaintextState),

    #[error(
        "'{0}' has local changes that --force would discard (state: {1:?}); rerun with --force, or `seal` first"
    )]
    OpenRefused(String, PlaintextState),

    #[error(
        "'{0}' has not been sealed (state: {1:?}); run `seal` first, or `open --force` to discard local changes"
    )]
    CloseRefused(String, PlaintextState),
}
