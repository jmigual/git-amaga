//! What the commands return instead of printing (ADR-0014, plan 14.2).

use std::fmt;

use crate::Error;
use crate::keyring::GpgKey;

/// The result of `add`, `seal`, `open`, `close` and `remove`.
#[derive(Debug, Default)]
pub struct Outcome {
    /// The paths the command wrote or deleted, in order.
    pub changed: Vec<String>,
    /// Problems that did not stop the command.
    pub warnings: Vec<Warning>,
}

/// A problem that did not stop a command; `Display` is the text without any prefix.
#[derive(Debug)]
pub enum Warning {
    /// The plaintext path already appears in git history.
    PlaintextInHistory(String),
    /// `add --force` dropped the exposure history of a `.amaga` path found in git history.
    ExposureHistoryDropped(String),
    /// `seal --force` cleared `NEEDS ROTATION` for some members.
    ExposureCleared {
        /// The plaintext path that was sealed.
        plaintext: String,
        /// How many members were flagged as exposed.
        members: usize,
    },
    /// `rotate` or `user remove` left a partition alone because the actor is not in it.
    PartitionNotRotated(String),
    /// A git-crypt key holder was not imported as a member.
    KeySkipped {
        /// The holder's fingerprint, or the file name that is not one.
        fpr: String,
        /// Why not.
        error: Error,
    },
    /// Importing does not remove the old git-crypt ciphertext from history.
    GitCryptHistory,
    /// A partition lists a name that is not in `.amaga/users`; it grants nothing.
    UnknownMember {
        /// The partition.
        partition: String,
        /// The listed name.
        name: String,
    },
    /// A managed secret with an invalid path was left out of a command that lists them all.
    Skipped {
        /// The `.amaga` path.
        path: String,
        /// Why the path is invalid.
        error: Error,
    },
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlaintextInHistory(path) => write!(f, "'{path}' already appears in git history"),
            Self::ExposureHistoryDropped(path) => write!(
                f,
                "'{path}' appears in git history; its exposure history is dropped"
            ),
            Self::ExposureCleared { plaintext, members } => write!(
                f,
                "sealing '{plaintext}' with --force clears NEEDS ROTATION for {members} member(s); \
                 the local copy may still hold an old value"
            ),
            Self::PartitionNotRotated(partition) => write!(
                f,
                "partition '{partition}' was not re-encrypted: you are not a member; a member must run `git-amaga rotate --partition {partition}`"
            ),
            Self::KeySkipped { fpr, error } => {
                write!(f, "git-crypt key holder {fpr} not imported: {error}")
            }
            Self::GitCryptHistory => write!(
                f,
                "every former git-crypt key holder, including anyone given an exported key, can still read the imported files in git history; treat those credentials as exposed"
            ),
            Self::UnknownMember { partition, name } => write!(
                f,
                "partition '{partition}' lists '{name}', who is not in .amaga/users; it grants nothing"
            ),
            Self::Skipped { path, error } => write!(f, "skipping '{path}': {error}"),
        }
    }
}

/// The result of `rotate` and `user remove`.
#[derive(Debug, Default)]
pub struct Rotation {
    /// The secrets that were re-encrypted, in write order.
    pub written: Vec<Reencrypted>,
    /// Problems that did not stop the command.
    pub warnings: Vec<Warning>,
}

/// The result of `import-git-crypt`.
#[derive(Debug)]
pub struct Imported {
    /// The new members, with the GPG key each was exported from.
    pub members: Vec<(String, GpgKey)>,
    /// The partitions the import created.
    pub created: Vec<String>,
    /// The `.amaga` paths written.
    pub changed: Vec<String>,
    /// Problems that did not stop the import; the history warning is last.
    pub warnings: Vec<Warning>,
}

/// One secret rewritten by `rotate` or `user remove`.
#[derive(Debug)]
pub struct Reencrypted {
    /// The `.amaga` path.
    pub path: String,
    /// Removed members who could read an earlier version (`NEEDS ROTATION`).
    pub exposed_to: Vec<String>,
}

/// How serious a secret's status is; the derived order puts errors first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// A problem that makes `status` fail.
    Error,
    /// Needs attention, such as a pending rotation.
    Warn,
    /// Nothing to do.
    Ok,
}

/// The state of one secret in a [`StatusReport`].
#[derive(Debug)]
pub struct SecretStatus {
    /// The worst level among the messages.
    pub level: Level,
    /// The `.amaga` path.
    pub path: String,
    /// The partition in the label; empty when the label could not be read.
    pub partition: String,
    /// What was found; a single plain state such as `in sync` when there is no problem.
    pub messages: Vec<String>,
}

/// The result of `status`: every problem is data, not an [`Error`].
#[derive(Debug)]
pub struct StatusReport {
    /// A one-line description of the members, such as `alice (age), bob (gpg)`.
    pub members: String,
    /// Each partition and the names it lists.
    pub partitions: Vec<(String, Vec<String>)>,
    /// One entry per secret, errors first.
    pub secrets: Vec<SecretStatus>,
    /// Problems that did not stop the report.
    pub warnings: Vec<Warning>,
}

impl StatusReport {
    /// The number of secrets at [`Level::Error`].
    pub fn error_count(&self) -> usize {
        self.secrets
            .iter()
            .filter(|s| s.level == Level::Error)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(level: Level) -> SecretStatus {
        SecretStatus {
            level,
            path: "a.env.amaga".into(),
            partition: "default".into(),
            messages: vec!["in sync".into()],
        }
    }

    #[test]
    fn error_count_counts_only_errors() {
        let report = StatusReport {
            members: "alice (age)".into(),
            partitions: Vec::new(),
            secrets: vec![
                status(Level::Error),
                status(Level::Warn),
                status(Level::Error),
                status(Level::Ok),
            ],
            warnings: Vec::new(),
        };
        assert_eq!(report.error_count(), 2);
    }

    #[test]
    fn levels_sort_errors_first() {
        let mut levels = [Level::Ok, Level::Warn, Level::Error];
        levels.sort();
        assert_eq!(levels, [Level::Error, Level::Warn, Level::Ok]);
    }

    #[test]
    fn skipped_warning_includes_the_path_and_the_cause() {
        let warning = Warning::Skipped {
            path: "x.amaga.amaga".into(),
            error: Error::PathBadSuffix("x.amaga.amaga".into()),
        };
        assert!(
            warning
                .to_string()
                .starts_with("skipping 'x.amaga.amaga': ")
        );
    }
}
