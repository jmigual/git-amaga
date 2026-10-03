//! What the commands return instead of printing (ADR-0014, plan 14.2).

use std::fmt;

use crate::Error;

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
            Self::Skipped { path, error } => write!(f, "skipping '{path}': {error}"),
        }
    }
}

/// One secret rewritten by `rotate`, `user add` or `user remove`.
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
    /// What was found; a single plain state such as `in sync` when there is no problem.
    pub messages: Vec<String>,
}

/// The result of `status`: every problem is data, not an [`Error`].
#[derive(Debug)]
pub struct StatusReport {
    /// A one-line description of the members, such as `alice (age), bob (gpg)`.
    pub members: String,
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
            messages: vec!["in sync".into()],
        }
    }

    #[test]
    fn error_count_counts_only_errors() {
        let report = StatusReport {
            members: "alice (age)".into(),
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
