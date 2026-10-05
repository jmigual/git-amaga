//! Runs `git` as a subprocess, never through a shell (plan 10.2).

use std::collections::{BTreeSet, HashSet};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use crate::error::Error;

// An unusable `dir` is an `Error::IoPath` naming it, not a bare spawn error.
fn check_dir(dir: &Path) -> Result<(), Error> {
    let io_error = |source| Error::IoPath {
        path: dir.display().to_string(),
        source,
    };
    if !dir.metadata().map_err(io_error)?.is_dir() {
        return Err(io_error(io::ErrorKind::NotADirectory.into()));
    }
    Ok(())
}

// Runs `git` in `dir`.
fn output(dir: &Path, args: &[&str]) -> Result<Output, Error> {
    check_dir(dir)?;
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(Error::Io)
}

// Like `output`, with `input` on stdin.
fn output_with_stdin(dir: &Path, args: &[&str], input: &[u8]) -> Result<Output, Error> {
    check_dir(dir)?;
    let mut child = Command::new("git")
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    // A thread, so a large input and a large output cannot block each other. A write error means
    // git exited early, which its status reports.
    std::thread::scope(|scope| {
        scope.spawn(move || stdin.write_all(input));
        child.wait_with_output().map_err(Error::Io)
    })
}

fn git_error(output: &Output) -> Error {
    Error::Git(String::from_utf8_lossy(&output.stderr).trim().to_string())
}

// Runs `git` in `dir`, returning stdout; a non-zero exit is `Error::Git`.
fn run_in(dir: &Path, args: &[&str]) -> Result<Vec<u8>, Error> {
    let output = output(dir, args)?;
    if !output.status.success() {
        return Err(git_error(&output));
    }
    Ok(output.stdout)
}

// Exit 0 is true, exit 1 is false, anything else is an error.
fn succeeds_in(root: &Path, args: &[&str]) -> Result<bool, Error> {
    let output = output(root, args)?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(git_error(&output)),
    }
}

// Exit code 1 (`git config --get` for an unset key) becomes `Ok(None)`.
fn run_optional(dir: &Path, args: &[&str]) -> Result<Option<String>, Error> {
    let output = output(dir, args)?;
    if output.status.code() == Some(1) {
        return Ok(None);
    }
    if !output.status.success() {
        return Err(git_error(&output));
    }
    line(&output.stdout).map(Some)
}

// A path git printed; never decoded lossily, so a non-UTF-8 name cannot turn into another one.
fn utf8_path(bytes: &[u8]) -> Result<String, Error> {
    String::from_utf8(bytes.to_vec())
        .map_err(|_| Error::PathNotUtf8(String::from_utf8_lossy(bytes).into_owned()))
}

// One-line output (a path or a config value) without its trailing newline.
fn line(stdout: &[u8]) -> Result<String, Error> {
    Ok(utf8_path(stdout)?.trim_end_matches('\n').to_string())
}

fn nul_fields(output: &[u8]) -> impl Iterator<Item = &[u8]> {
    output.split(|b| *b == 0).filter(|field| !field.is_empty())
}

fn nul_separated(output: &[u8]) -> Result<Vec<String>, Error> {
    nul_fields(output).map(utf8_path).collect()
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
    line(&output.stdout).map(PathBuf::from)
}

fn is_not_a_git_repo_error(stderr: &str) -> bool {
    stderr.to_ascii_lowercase().contains("not a git repository")
}

/// `dir` relative to the repository root, with a trailing slash; empty at the root.
pub fn show_prefix(dir: &Path) -> Result<String, Error> {
    line(&run_in(dir, &["rev-parse", "--show-prefix"])?)
}

/// Absolute path of a per-worktree file under `.git/` (plan 5.5).
pub fn git_path(dir: &Path, name: &str) -> Result<PathBuf, Error> {
    let out = run_in(
        dir,
        &["rev-parse", "--path-format=absolute", "--git-path", name],
    )?;
    line(&out).map(PathBuf::from)
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

/// Every `*.amaga` path git knows (tracked or not), sorted and deduplicated. A path that is not
/// UTF-8 is an `Err` holding its lossy form, for the caller to report, unless it is missing from
/// the worktree: callers skip missing secrets, and only the raw name can be checked.
pub fn managed_secrets(root: &Path) -> Result<Vec<Result<String, String>>, Error> {
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
    Ok(sorted_paths(&out, |raw| raw_exists(root, raw)))
}

// `exists` is asked only about names that are not UTF-8.
fn sorted_paths(output: &[u8], exists: impl Fn(&[u8]) -> bool) -> Vec<Result<String, String>> {
    let mut fields: Vec<&[u8]> = nul_fields(output).collect();
    fields.sort();
    fields.dedup();
    fields
        .into_iter()
        .filter_map(|field| match String::from_utf8(field.to_vec()) {
            Ok(path) => Some(Ok(path)),
            Err(_) if exists(field) => Some(Err(String::from_utf8_lossy(field).into_owned())),
            Err(_) => None,
        })
        .collect()
}

#[cfg(unix)]
fn raw_exists(root: &Path, raw: &[u8]) -> bool {
    use std::os::unix::ffi::OsStrExt;
    root.join(std::ffi::OsStr::from_bytes(raw)).exists()
}

// Git for Windows prints UTF-8 only, so a name that is not cannot be checked; it is reported.
#[cfg(not(unix))]
fn raw_exists(_root: &Path, _raw: &[u8]) -> bool {
    true
}

/// Every tracked path.
pub fn tracked_files(root: &Path) -> Result<Vec<String>, Error> {
    run_in(root, &["ls-files", "-z"]).and_then(|out| nul_separated(&out))
}

/// The untracked paths that are not ignored.
pub fn untracked_files(root: &Path) -> Result<Vec<String>, Error> {
    run_in(root, &["ls-files", "-z", "--others", "--exclude-standard"])
        .and_then(|out| nul_separated(&out))
}

/// The tracked paths matching `pathspecs`.
pub fn tracked_matching(root: &Path, pathspecs: &[&str]) -> Result<Vec<String>, Error> {
    let mut args = vec!["ls-files", "-z", "--"];
    args.extend(pathspecs);
    run_in(root, &args).and_then(|out| nul_separated(&out))
}

/// The paths with staged changes.
pub fn staged_paths(root: &Path) -> Result<Vec<String>, Error> {
    run_in(root, &["diff", "--cached", "--name-only", "-z"]).and_then(|out| nul_separated(&out))
}

/// `git rm --cached` for `paths`: removes them from the index only (plan 7.5).
pub fn rm_cached(root: &Path, paths: &[&str]) -> Result<(), Error> {
    let args = [
        "--literal-pathspecs",
        "rm",
        "--cached",
        "-q",
        "--pathspec-from-file=-",
        "--pathspec-file-nul",
    ];
    let input: Vec<u8> = paths
        .iter()
        .flat_map(|p| format!("{p}\0").into_bytes())
        .collect();
    let output = output_with_stdin(root, &args, &input)?;
    match output.status.success() {
        true => Ok(()),
        false => Err(git_error(&output)),
    }
}

/// The unmerged paths matching `pathspecs`, sorted and deduplicated.
pub fn unmerged_paths(root: &Path, pathspecs: &[&str]) -> Result<Vec<String>, Error> {
    // `-z`: without it git C-quotes non-ASCII paths.
    let mut args = vec!["ls-files", "-u", "-z", "--"];
    args.extend(pathspecs);
    unmerged_from(&run_in(root, &args)?)
}

// `ls-files -u -z` entries are `<mode> <object> <stage>\t<path>`.
fn unmerged_from(output: &[u8]) -> Result<Vec<String>, Error> {
    let mut paths = nul_fields(output)
        .filter_map(|entry| {
            let tab = entry.iter().position(|b| *b == b'\t')?;
            Some(utf8_path(&entry[tab + 1..]))
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    paths.dedup();
    Ok(paths)
}

// The `./` prefix on paths in `is_tracked`, `path_in_history` and `is_ignored` stops a leading `:`
// being read as pathspec magic; `--literal-pathspecs` stops `*` or `?` matching other paths.
pub fn is_tracked(root: &Path, path: &str) -> Result<bool, Error> {
    let path = format!("./{path}");
    succeeds_in(
        root,
        &[
            "--literal-pathspecs",
            "ls-files",
            "--error-unmatch",
            "--",
            &path,
        ],
    )
}

pub fn path_in_history(root: &Path, path: &str) -> Result<bool, Error> {
    let path = format!("./{path}");
    let out = run_in(
        root,
        &[
            "--literal-pathspecs",
            "rev-list",
            "-n1",
            "--all",
            "--",
            &path,
        ],
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

/// The `paths` that are tracked, from one `git ls-files`.
pub fn tracked_among(root: &Path, paths: &[&str]) -> Result<BTreeSet<String>, Error> {
    let out = run_in(root, &["ls-files", "-z"])?;
    let tracked: HashSet<&[u8]> = nul_fields(&out).collect();
    Ok(paths
        .iter()
        .filter(|path| tracked.contains(path.as_bytes()))
        .map(|path| path.to_string())
        .collect())
}

/// [`is_ignored`] for every one of `paths`, from one `git check-ignore`: the ignored ones.
pub fn ignored_among(root: &Path, paths: &[&str]) -> Result<BTreeSet<String>, Error> {
    let args = ["check-ignore", "-z", "--stdin", "--no-index"];
    let input: Vec<u8> = paths
        .iter()
        .flat_map(|p| format!("./{p}\0").into_bytes())
        .collect();
    let output = output_with_stdin(root, &args, &input)?;
    // Exit 1 means none is ignored.
    if !matches!(output.status.code(), Some(0 | 1)) {
        return Err(git_error(&output));
    }
    // Each ignored path is echoed as given.
    let ignored: HashSet<&[u8]> = nul_fields(&output.stdout).collect();
    Ok(paths
        .iter()
        .filter(|path| ignored.contains(format!("./{path}").as_bytes()))
        .map(|path| path.to_string())
        .collect())
}

/// `(path, attribute, value)` for each of `attrs` on each of `paths`, from `git check-attr`. The
/// value is `unspecified`, `set`, `unset` or the attribute's value.
pub fn check_attr(
    root: &Path,
    attrs: &[&str],
    paths: &[&str],
) -> Result<Vec<(String, String, String)>, Error> {
    let mut args = vec!["check-attr", "-z", "--stdin"];
    args.extend(attrs);
    let input: Vec<u8> = paths
        .iter()
        .flat_map(|p| format!("{p}\0").into_bytes())
        .collect();
    let output = output_with_stdin(root, &args, &input)?;
    if !output.status.success() {
        return Err(git_error(&output));
    }
    // Fail closed: a misaligned, short or undecodable answer must not read as "no attribute".
    let unexpected = || Error::Git("unexpected `git check-attr` output".into());
    let stdout = String::from_utf8(output.stdout).map_err(|_| unexpected())?;
    let triples = parse_check_attr(&stdout);
    if triples.len() != paths.len() * attrs.len() {
        return Err(unexpected());
    }
    Ok(triples)
}

// `-z` output: `path NUL attribute NUL value NUL` per pair. A value can be empty (`attr=`), so
// empty fields are kept.
fn parse_check_attr(output: &str) -> Vec<(String, String, String)> {
    let fields: Vec<&str> = output
        .strip_suffix('\0')
        .unwrap_or(output)
        .split('\0')
        .collect();
    let (triples, _) = fields.as_chunks::<3>();
    triples
        .iter()
        .map(|[path, attr, value]| (path.to_string(), attr.to_string(), value.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_attribute_value_does_not_shift_the_next_triple() {
        let got = parse_check_attr("a\0filter\0\0b\0filter\0git-crypt\0");
        let triple =
            |path: &str, value: &str| (path.to_string(), "filter".to_string(), value.to_string());
        assert_eq!(got, [triple("a", ""), triple("b", "git-crypt")]);
        assert!(parse_check_attr("").is_empty());
    }

    #[test]
    fn check_attr_output_is_one_triple_per_path_and_attribute() {
        let output = "a.env\0amaga-partition\0production\0flag.txt\0amaga-partition\0set\0x\0amaga-partition\0unspecified\0";
        let got = parse_check_attr(output);
        let triple = |path: &str, value: &str| {
            (
                path.to_string(),
                "amaga-partition".to_string(),
                value.to_string(),
            )
        };
        assert_eq!(
            got,
            [
                triple("a.env", "production"),
                triple("flag.txt", "set"),
                triple("x", "unspecified"),
            ]
        );
    }

    #[test]
    fn a_non_utf8_managed_secret_is_kept_as_an_error() {
        let output = b"b.amaga\0caf\xe9.amaga\0a.amaga\0b.amaga\0gon\xe9.amaga\0";
        let got = sorted_paths(output, |raw| raw == b"caf\xe9.amaga");
        assert_eq!(
            got,
            [
                Ok("a.amaga".to_string()),
                Ok("b.amaga".to_string()),
                Err("caf\u{fffd}.amaga".to_string()),
            ]
        );
    }

    #[test]
    fn non_utf8_paths_are_errors_not_lossy() {
        assert!(matches!(
            nul_separated(b"a\0caf\xe9\0"),
            Err(Error::PathNotUtf8(_))
        ));
        assert_eq!(nul_separated(b"a\0b\0").unwrap(), ["a", "b"]);
        assert!(matches!(line(b"/r\xe9po\n"), Err(Error::PathNotUtf8(_))));
        assert_eq!(line(b"/repo\n").unwrap(), "/repo");
    }

    #[test]
    fn unmerged_entries_keep_the_path_after_the_tab() {
        let entry = |path: &[u8]| [b"100644 0123 1\t", path, b"\0"].concat();
        let output = [entry(b"b.amaga"), entry(b"a b.amaga"), entry(b"b.amaga")].concat();
        assert_eq!(unmerged_from(&output).unwrap(), ["a b.amaga", "b.amaga"]);
        assert!(matches!(
            unmerged_from(&entry(b"caf\xe9.amaga")),
            Err(Error::PathNotUtf8(_))
        ));
    }

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
