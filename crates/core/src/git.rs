//! Runs `git` as a subprocess, never through a shell (plan 10.2).

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use crate::error::Error;

// Runs `git` in `dir`. An unusable `dir` is an `Error::IoPath` naming it, not a bare spawn error.
fn output(dir: &Path, args: &[&str]) -> Result<Output, Error> {
    let io_error = |source| Error::IoPath {
        path: dir.display().to_string(),
        source,
    };
    if !dir.metadata().map_err(io_error)?.is_dir() {
        return Err(io_error(io::ErrorKind::NotADirectory.into()));
    }
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(Error::Io)
}

// Runs `git` in `dir`, returning trimmed stdout; a non-zero exit is `Error::Git`.
fn run_in(dir: &Path, args: &[&str]) -> Result<String, Error> {
    let output = output(dir, args)?;
    if !output.status.success() {
        return Err(Error::Git(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .trim_end_matches('\n')
        .to_string())
}

// Exit 0 is true, exit 1 is false, anything else is an error.
fn succeeds_in(root: &Path, args: &[&str]) -> Result<bool, Error> {
    let output = output(root, args)?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(Error::Git(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        )),
    }
}

// Exit code 1 (`git config --get` for an unset key) becomes `Ok(None)`.
fn run_optional(dir: &Path, args: &[&str]) -> Result<Option<String>, Error> {
    let output = output(dir, args)?;
    if output.status.code() == Some(1) {
        return Ok(None);
    }
    if !output.status.success() {
        return Err(Error::Git(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    Ok(Some(
        String::from_utf8_lossy(&output.stdout)
            .trim_end_matches('\n')
            .to_string(),
    ))
}

/// [`Error::NotAGitRepo`] when `dir` is outside a Git repository.
pub fn toplevel(dir: &Path) -> Result<PathBuf, Error> {
    let output = output(dir, &["rev-parse", "--show-toplevel"])?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if is_not_a_git_repo_error(&stderr) {
            return Err(Error::NotAGitRepo);
        }
        // Other failures (e.g. "dubious ownership") must not read as "not a repo".
        return Err(Error::Git(stderr));
    }
    Ok(PathBuf::from(
        String::from_utf8_lossy(&output.stdout)
            .trim_end_matches('\n')
            .to_string(),
    ))
}

fn is_not_a_git_repo_error(stderr: &str) -> bool {
    stderr.to_ascii_lowercase().contains("not a git repository")
}

/// `dir` relative to the repository root, with a trailing slash; empty at the root.
pub fn show_prefix(dir: &Path) -> Result<String, Error> {
    run_in(dir, &["rev-parse", "--show-prefix"])
}

/// Absolute path of a per-worktree file under `.git/` (plan 5.5).
pub fn git_path(dir: &Path, name: &str) -> Result<PathBuf, Error> {
    run_in(
        dir,
        &["rev-parse", "--path-format=absolute", "--git-path", name],
    )
    .map(PathBuf::from)
}

/// `None` when unset.
pub fn config_get_global(dir: &Path, key: &str) -> Result<Option<String>, Error> {
    run_optional(dir, &["config", "--global", "--get", key])
}

pub fn config_set_global(dir: &Path, key: &str, value: &str) -> Result<(), Error> {
    run_in(dir, &["config", "--global", key, value]).map(|_| ())
}

/// Reads across all scopes, with `~` expansion (plan 5.5).
pub fn config_get_path(dir: &Path, key: &str) -> Result<Option<String>, Error> {
    run_optional(dir, &["config", "--type=path", "--get", key])
}

/// Every `*.amaga` path git knows (tracked or not), sorted and deduplicated.
pub fn managed_secrets(root: &Path) -> Result<Vec<String>, Error> {
    let out = run_in(
        root,
        &[
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "*.amaga",
        ],
    )?;
    let mut paths: Vec<String> = out
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    paths.sort();
    paths.dedup();
    Ok(paths)
}

pub fn unmerged_secrets(root: &Path) -> Result<Vec<String>, Error> {
    // `-z`: without it git C-quotes non-ASCII paths.
    let out = run_in(root, &["ls-files", "-u", "-z", "--", "*.amaga"])?;
    let mut paths: Vec<String> = out
        .split('\0')
        .filter_map(|entry| entry.split('\t').nth(1))
        .map(str::to_string)
        .collect();
    paths.sort();
    paths.dedup();
    Ok(paths)
}

// The `./` prefix on paths in `is_tracked`, `path_in_history` and `is_ignored` stops a leading `:`
// being read as pathspec magic.
pub fn is_tracked(root: &Path, path: &str) -> Result<bool, Error> {
    succeeds_in(
        root,
        &["ls-files", "--error-unmatch", "--", &format!("./{path}")],
    )
}

pub fn path_in_history(root: &Path, path: &str) -> Result<bool, Error> {
    let out = run_in(
        root,
        &["rev-list", "-n1", "--all", "--", &format!("./{path}")],
    )?;
    Ok(!out.is_empty())
}

/// Uses `--no-index`, so it also answers for paths that do not exist yet (plan 5.4).
pub fn is_ignored(root: &Path, path: &str) -> Result<bool, Error> {
    succeeds_in(
        root,
        &[
            "check-ignore",
            "-q",
            "--no-index",
            "--",
            &format!("./{path}"),
        ],
    )
}

/// Whether `git check-attr` reports the `text` attribute of `path` as `unset`.
pub fn text_is_unset(root: &Path, path: &str) -> Result<bool, Error> {
    Ok(run_in(root, &["check-attr", "text", "--", path])?.ends_with(": unset"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_not_a_git_repo_error_matches_only_that_failure() {
        assert!(is_not_a_git_repo_error(
            "fatal: not a git repository (or any of the parent directories): .git"
        ));
        // Case-insensitive, since git's own casing isn't a stable contract.
        assert!(is_not_a_git_repo_error(
            "fatal: Not a Git repository (or any of the parent directories): .git"
        ));
        assert!(!is_not_a_git_repo_error(
            "fatal: detected dubious ownership in repository at '/repo'\nTo add an exception for this directory, call:\n\n\tgit config --global --add safe.directory /repo"
        ));
    }
}
