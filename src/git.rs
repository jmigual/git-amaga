//! Runs `git` as a subprocess (never through a shell), and the `toplevel`/`show-prefix`/
//! `git-path` helpers used to resolve repository-relative paths and per-worktree state
//! (plan 10.2).

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::Error;

fn command(args: &[&str]) -> Command {
    let mut cmd = Command::new("git");
    cmd.args(args);
    cmd
}

/// Runs `git` with `args`, returning trimmed stdout. A non-zero exit is [`Error::Git`] carrying
/// git's stderr.
pub fn run(args: &[&str]) -> Result<String, Error> {
    stdout_of(&mut command(args))
}

fn run_in(root: &Path, args: &[&str]) -> Result<String, Error> {
    stdout_of(command(args).current_dir(root))
}

fn stdout_of(cmd: &mut Command) -> Result<String, Error> {
    let output = cmd.output().map_err(Error::Io)?;
    if !output.status.success() {
        return Err(Error::Git(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .trim_end_matches('\n')
        .to_string())
}

/// Runs `git` in `root`: exit 0 is `true`, exit 1 is `false`, anything else is an error.
fn succeeds_in(root: &Path, args: &[&str]) -> Result<bool, Error> {
    let output = command(args)
        .current_dir(root)
        .output()
        .map_err(Error::Io)?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(Error::Git(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        )),
    }
}

/// Like [`run`], but an exit code of 1 (the convention `git config --get` uses for "key unset")
/// becomes `Ok(None)` instead of an error.
fn run_optional(args: &[&str]) -> Result<Option<String>, Error> {
    let output = command(args).output().map_err(Error::Io)?;
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

/// `git rev-parse --show-toplevel` (plan section 7). [`Error::NotAGitRepo`] if the current
/// directory is not inside a Git repository.
pub fn toplevel() -> Result<PathBuf, Error> {
    let output = command(&["rev-parse", "--show-toplevel"])
        .output()
        .map_err(Error::Io)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if is_not_a_git_repo_error(&stderr) {
            return Err(Error::NotAGitRepo);
        }
        // Any other failure (for example "detected dubious ownership", which names the
        // `git config --global --add safe.directory` remediation) must not be hidden behind
        // the generic "not inside a Git repository" message.
        return Err(Error::Git(stderr));
    }
    Ok(PathBuf::from(
        String::from_utf8_lossy(&output.stdout)
            .trim_end_matches('\n')
            .to_string(),
    ))
}

/// Whether `rev-parse --show-toplevel`'s stderr means "not inside a Git repository", as opposed
/// to some other failure (for example "detected dubious ownership"). Split out from [`toplevel`]
/// so the classification is unit-testable without spawning git.
fn is_not_a_git_repo_error(stderr: &str) -> bool {
    stderr.to_ascii_lowercase().contains("not a git repository")
}

/// `git rev-parse --show-prefix` (plan section 7): the current directory's path relative to the
/// repository root, `/`-separated with a trailing slash, or empty at the root.
pub fn show_prefix() -> Result<String, Error> {
    run(&["rev-parse", "--show-prefix"])
}

/// `git rev-parse --path-format=absolute --git-path <name>` (plan 5.5): the absolute path to a
/// per-worktree file or directory under `.git/`.
pub fn git_path(name: &str) -> Result<PathBuf, Error> {
    run(&["rev-parse", "--path-format=absolute", "--git-path", name]).map(PathBuf::from)
}

/// `git config --global --get <key>` (plan: `keygen` only sets `amaga.identity` when this is
/// unset).
pub fn config_get_global(key: &str) -> Result<Option<String>, Error> {
    run_optional(&["config", "--global", "--get", key])
}

/// `git config --global <key> <value>`.
pub fn config_set_global(key: &str, value: &str) -> Result<(), Error> {
    run(&["config", "--global", key, value]).map(|_| ())
}

/// `git config --type=path --get <key>` (plan 5.5): reads `key` across all scopes, with `~`
/// expansion.
pub fn config_get_path(key: &str) -> Result<Option<String>, Error> {
    run_optional(&["config", "--type=path", "--get", key])
}

/// The managed secret list (plan section 7): every `*.amaga` path git knows, sorted and
/// deduplicated (an unmerged path appears once per stage).
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

/// `*.amaga` paths with unresolved merge conflicts, sorted and deduplicated.
pub fn unmerged_secrets(root: &Path) -> Result<Vec<String>, Error> {
    let out = run_in(root, &["ls-files", "-u", "--", "*.amaga"])?;
    let mut paths: Vec<String> = out
        .lines()
        .filter_map(|line| line.split('\t').nth(1))
        .map(str::to_string)
        .collect();
    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// Whether `path` is tracked. The `./` prefix in this and the next two helpers stops a leading
/// `:` from being read as pathspec magic.
pub fn is_tracked(root: &Path, path: &str) -> Result<bool, Error> {
    succeeds_in(
        root,
        &["ls-files", "--error-unmatch", "--", &format!("./{path}")],
    )
}

/// Whether `path` appears anywhere in history.
pub fn path_in_history(root: &Path, path: &str) -> Result<bool, Error> {
    let out = run_in(
        root,
        &["rev-list", "-n1", "--all", "--", &format!("./{path}")],
    )?;
    Ok(!out.is_empty())
}

/// `git check-ignore --no-index`, which also answers for paths that do not exist yet (plan 5.4).
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
