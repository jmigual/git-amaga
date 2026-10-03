//! A cached failure to unwrap an epoch (plan 5.6). `Error` is not `Clone`, so this keeps what a
//! repeat lookup needs to return the same variant without unwrapping the epoch again.

use std::io;

use crate::Error;

pub(crate) enum EpochFailure {
    /// The epoch file has no stanza for our keys; no gpg was run.
    NotARecipient {
        path: String,
    },
    Invalid(String),
    Io {
        path: String,
        kind: io::ErrorKind,
        message: String,
    },
    Undecryptable {
        path: String,
        member: Option<String>,
        message: String,
    },
}

/// Whether `err` is [`EpochFailure::NotARecipient`], as opposed to a real failure to unwrap.
pub(crate) fn is_not_a_recipient(err: &Error) -> bool {
    matches!(
        err,
        Error::EpochUndecryptable { source, .. }
            if matches!(**source, Error::Decrypt(age::DecryptError::NoMatchingKeys))
    )
}

impl EpochFailure {
    /// `err` is what unwrapping epoch file `path` returned.
    pub(crate) fn of(path: &str, err: &Error) -> Self {
        match err {
            _ if is_not_a_recipient(err) => Self::NotARecipient { path: path.into() },
            Error::EpochInvalid(message) => Self::Invalid(message.clone()),
            Error::IoPath { path, source } => Self::Io {
                path: path.clone(),
                kind: source.kind(),
                message: source.to_string(),
            },
            Error::EpochUndecryptable {
                path,
                member,
                source,
            } => Self::Undecryptable {
                path: path.clone(),
                member: member.clone(),
                message: source.to_string(),
            },
            other => Self::Undecryptable {
                path: path.into(),
                member: None,
                message: other.to_string(),
            },
        }
    }

    /// The error again, with the same variant; a wrapped cause is rebuilt from its message.
    pub(crate) fn error(&self) -> Error {
        match self {
            Self::NotARecipient { path } => Error::EpochUndecryptable {
                path: path.clone(),
                member: None,
                source: Box::new(Error::Decrypt(age::DecryptError::NoMatchingKeys)),
            },
            Self::Invalid(message) => Error::EpochInvalid(message.clone()),
            Self::Io {
                path,
                kind,
                message,
            } => Error::IoPath {
                path: path.clone(),
                source: io::Error::new(*kind, message.clone()),
            },
            Self::Undecryptable {
                path,
                member,
                message,
            } => Error::EpochUndecryptable {
                path: path.clone(),
                member: member.clone(),
                source: Box::new(Error::Io(io::Error::other(message.clone()))),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn again(err: Error) -> Error {
        EpochFailure::of(".amaga/epochs/x.age", &err).error()
    }

    #[test]
    fn a_cached_failure_returns_the_same_variant() {
        let undecryptable = Error::EpochUndecryptable {
            path: "p".into(),
            member: Some("alice".into()),
            source: Box::new(Error::Io(io::Error::other("gpg said no"))),
        };
        assert!(matches!(
            again(undecryptable),
            Error::EpochUndecryptable { member: Some(m), .. } if m == "alice"
        ));
        assert!(matches!(
            again(Error::EpochInvalid("bad".into())),
            Error::EpochInvalid(m) if m == "bad"
        ));
        let io_path = Error::IoPath {
            path: "p".into(),
            source: io::ErrorKind::PermissionDenied.into(),
        };
        assert!(matches!(
            again(io_path),
            Error::IoPath { source, .. } if source.kind() == io::ErrorKind::PermissionDenied
        ));
    }

    #[test]
    fn not_a_recipient_stays_not_a_recipient() {
        let miss = Error::EpochUndecryptable {
            path: "p".into(),
            member: None,
            source: Box::new(Error::Decrypt(age::DecryptError::NoMatchingKeys)),
        };
        assert!(is_not_a_recipient(&again(miss)));
    }
}
