//! Typed errors for git-amaga. One variant per user-actionable failure (plan section 10.2).

use thiserror::Error;

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
}
