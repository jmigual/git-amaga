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

    #[error(
        "'{spec}' is not in your local gpg keyring (import it with `gpg --import`, or pass an exported `.asc` file)\n{stderr}"
    )]
    GpgKeyNotFound { spec: String, stderr: String },

    /// A `.asc`-looking or path-looking `KEY` that is neither a file nor in the keyring.
    #[error("'{0}' is not an existing file, and it is not in your local gpg keyring either")]
    KeyFileNotFound(String),

    #[error(
        "'{spec}' matches more than one key in your local gpg keyring (pass a fingerprint):\n{keys}"
    )]
    GpgKeyAmbiguous { spec: String, keys: String },

    #[error("gpg not found on PATH; pass an exported `.asc` file instead")]
    GpgNotFound,

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

    #[error("'{0}' is not a managed secret; use `add`")]
    NotManagedSecret(String),

    #[error(
        "'{0}' already exists in git history; run `git checkout <rev> -- {0}` then `seal` to keep its exposure history, or rerun `add` with --force to drop it"
    )]
    CiphertextInHistory(String),

    #[error("unmerged *.amaga files must be resolved first: {0}")]
    UnmergedAmagaFiles(String),

    #[error("'{0}' could not be ignored (check for a conflicting negation rule in .gitignore)")]
    PlaintextNotIgnored(String),

    #[error("{path}: {source}")]
    SecretUndecryptable {
        path: String,
        #[source]
        source: Box<Error>,
    },

    /// Names the epoch file and, for a gpg failure, the member.
    #[error("{path}{}: {source}", .member.as_ref().map(|m| format!(" (member {m})")).unwrap_or_default())]
    EpochUndecryptable {
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

    #[error(
        "member '{0}' already exists (to change its keys, edit its file in .amaga/users, then run `rotate`)"
    )]
    UserExists(String),

    #[error("no member named '{0}' in .amaga/users")]
    UserNotFound(String),

    #[error(
        "'{user}' is the only member of partition '{partition}'; removing them would leave nobody who can decrypt it"
    )]
    LastMember { user: String, partition: String },

    /// Nothing was written; every failing secret is listed.
    #[error(
        "cannot re-encrypt, these secrets cannot be read or decrypted (nothing was changed):\n{0}"
    )]
    ReencryptAborted(String),

    #[error("no paths given")]
    NoPaths,

    /// `remove` cannot prove the user keeps a copy of a secret it cannot read.
    #[error("{source}\nto drop it without a copy anyway, run `git rm {path}`")]
    RemoveUnreadable {
        path: String,
        #[source]
        source: Box<Error>,
    },

    #[error(
        "'{0}' must be open and in sync before its `.amaga` is removed (state: {1:?}); run `open` (or `seal`) first so you keep a copy"
    )]
    RemoveRefused(String, PlaintextState),

    #[error(
        ".amaga/partitions/default/current-epoch is missing (repository written by git-amaga 0.1.0 or 0.2.0, or `init` was interrupted); open the secrets with that version and run `init` anew, or delete `.amaga/` and rerun `init`"
    )]
    NoEpoch,

    #[error("invalid epoch: {0}")]
    EpochInvalid(String),

    #[error(
        "partition '{0}' differs from its current epoch; run `git-amaga rotate --partition {0}` first"
    )]
    EpochStale(String),

    #[error("invalid partition {0} (see .amaga/partitions)")]
    PartitionInvalid(String),

    #[error("partition '{0}' does not exist")]
    UnknownPartition(String),

    #[error("'{0}' is not a valid partition name (expected [a-z0-9][a-z0-9._-]{{0,63}})")]
    InvalidPartitionName(String),

    #[error("partition '{0}' already exists")]
    PartitionExists(String),

    #[error("'{user}' is already in partition '{partition}'")]
    AlreadyInPartition { user: String, partition: String },

    #[error("'{user}' is not listed in partition '{partition}'")]
    NotAPartitionMember { user: String, partition: String },

    /// `path` is set when the command was reading that secret.
    #[error("you are not a member of partition '{partition}'{}", .path.as_ref().map(|p| format!(" (needed for '{p}')")).unwrap_or_default())]
    NotInPartition {
        partition: String,
        path: Option<String>,
    },

    #[error(
        "unmerged epoch files must be resolved first: {0}\nrun `git checkout --ours -- <paths> && git add <paths>`, then `git-amaga rotate`"
    )]
    UnmergedEpoch(String),

    /// The label is missing, repeated, or not a valid partition name (plan 5.2).
    #[error("'{0}' has no valid partition label (expected exactly one `amaga-partition` stanza)")]
    PartitionLabelInvalid(String),

    #[error("nothing to dismiss: name at least one path or `--user`")]
    DismissNoTarget,

    #[error("'{0}' is not exposed in any of the selected secrets")]
    NotExposed(String),
}
