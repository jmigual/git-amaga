//! Repository-relative path handling, the `.gitignore`/`.gitattributes` managed block (plan 5.4),
//! and the atomic write helper (plan section 7).

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::error::Error;

/// Writes `contents` to `path` via a temp file + `sync_all` + rename (plan section 7): `path`
/// never observes a partially written file. `mode` sets Unix permissions on the temp file (for
/// example `0600` for secret-bearing files); ignored on other platforms. Removes any stale temp
/// file first, since `OpenOptions::mode` only applies when *creating* a file (a leftover temp
/// file would otherwise keep its old permissions, or — if it were a symlink — be followed
/// instead of replaced), and cleans up the temp file again if writing *or* the final rename
/// fails.
pub fn atomic_write(path: &Path, contents: &[u8], mode: Option<u32>) -> io::Result<()> {
    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(".amaga-tmp");
    let tmp_path = PathBuf::from(tmp_name);

    match fs::remove_file(&tmp_path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let result = (|| -> io::Result<()> {
        let mut file = create_tmp_file(&tmp_path, mode)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp_path, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

#[cfg(unix)]
fn create_tmp_file(path: &Path, mode: Option<u32>) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode.unwrap_or(0o666))
        .open(path)
}

#[cfg(not(unix))]
fn create_tmp_file(path: &Path, _mode: Option<u32>) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// A path argument resolved to repository-relative plaintext and ciphertext paths (plan
/// section 7).
pub struct SecretPath {
    pub plaintext: String,
    pub ciphertext: String,
}

/// `\` is a path separator only on Windows; on Unix it is a legal filename character (plan
/// section 7: "On Windows, convert `\` to `/`").
#[cfg(windows)]
fn normalize_separators(arg: &str) -> String {
    arg.replace('\\', "/")
}

#[cfg(not(windows))]
fn normalize_separators(arg: &str) -> String {
    arg.to_string()
}

/// Whether `arg` looks like a filesystem-absolute path rather than one meant to be resolved
/// against the repository (a leading `/` — also covers a Windows UNC path like `\\server\share`
/// once [`normalize_separators`] has converted it to `//server/share` — or a drive letter like
/// `C:`, checked on every platform since a repo-relative path is never meant to start that way).
/// Callers must apply this to the *normalized* argument: a raw `\Users\x` does not start with
/// `/` until backslashes have been converted.
fn is_absolute_like(arg: &str) -> bool {
    if arg.starts_with('/') {
        return true;
    }
    let bytes = arg.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// Converts a `<path>` CLI argument to repository-relative plaintext/ciphertext paths (plan
/// section 7): lexical normalisation against `prefix` (from `git rev-parse --show-prefix`), `\`
/// converted to `/` on Windows, and rejection of absolute/drive-prefixed paths, paths that leave
/// the repository, paths with control characters, paths under `.git/`/`.amaga/`, and plaintext
/// names ending in `.amaga` or `.amaga-tmp`. `arg` may be either the plaintext or the `.amaga`
/// path.
pub fn resolve_arg(prefix: &str, arg: &str) -> Result<SecretPath, Error> {
    let normalized_arg = normalize_separators(arg);
    if is_absolute_like(&normalized_arg) {
        return Err(Error::PathOutsideRepo(arg.to_string()));
    }
    if normalized_arg.chars().any(|c| c.is_control()) {
        return Err(Error::PathControlChar(arg.to_string()));
    }

    let combined = format!("{prefix}{normalized_arg}");
    let mut components: Vec<&str> = Vec::new();
    for part in combined.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(Error::PathOutsideRepo(arg.to_string()));
                }
            }
            other => components.push(other),
        }
    }
    if components.is_empty() {
        return Err(Error::PathOutsideRepo(arg.to_string()));
    }
    if components
        .iter()
        .any(|c| c.eq_ignore_ascii_case(".git") || c.eq_ignore_ascii_case(".amaga"))
    {
        return Err(Error::PathManaged(arg.to_string()));
    }

    let repo_relative = components.join("/");
    let plaintext = repo_relative
        .strip_suffix(".amaga")
        .map(str::to_string)
        .unwrap_or(repo_relative);
    if plaintext.ends_with(".amaga") || plaintext.ends_with(".amaga-tmp") {
        return Err(Error::PathBadSuffix(arg.to_string()));
    }

    let ciphertext = format!("{plaintext}.amaga");
    Ok(SecretPath {
        plaintext,
        ciphertext,
    })
}

const GITIGNORE_BEGIN: &[u8] = b"# BEGIN git-amaga";
const GITIGNORE_END: &[u8] = b"# END git-amaga";

/// Reads `path` as bytes, treating a missing file as empty (plan 5.4: `.gitignore`/
/// `.gitattributes` may not exist yet). Propagates every other I/O error instead of discarding
/// the file's real content (for example on a permission error, or non-UTF-8 content if the
/// caller were to mistakenly use `read_to_string`).
fn read_or_empty(path: &Path) -> io::Result<Vec<u8>> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// Splits `bytes` into lines on `\n`, byte-for-byte (no UTF-8 assumption, so non-UTF-8 content
/// round-trips unchanged). A single trailing empty "line" from a final `\n` is dropped, so
/// `join_lines` round-trips a file with or without a trailing newline... (see `join_lines`,
/// which always adds one back per line).
fn split_lines(bytes: &[u8]) -> Vec<&[u8]> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<&[u8]> = bytes.split(|&b| b == b'\n').collect();
    if lines.last() == Some(&&b""[..]) {
        lines.pop();
    }
    lines
}

/// Strips a single trailing `\r` for comparison (CRLF line endings, for example from
/// `core.autocrlf`), without touching the stored bytes: a matched line is still written back
/// with whatever line ending it already had.
fn strip_cr(line: &[u8]) -> &[u8] {
    match line.last() {
        Some(b'\r') => &line[..line.len() - 1],
        _ => line,
    }
}

fn join_lines(lines: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in lines {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out
}

/// Ensures `line` is present in the managed `.gitignore` block (plan 5.4), creating the block if
/// none exists (or if `# END git-amaga` precedes `# BEGIN git-amaga`, which can't happen from
/// this tool but is possible after a hand-edited merge). Idempotent: a `line` already present
/// anywhere in the file is left alone. Marker lines are matched as whole lines, so a line like
/// `foo # END git-amaga` is not mistaken for the marker. Operates on bytes, so content outside
/// the block — including non-UTF-8 content — round-trips unchanged.
pub fn ensure_gitignore_line(gitignore_path: &Path, line: &str) -> Result<(), Error> {
    let existing = read_or_empty(gitignore_path).map_err(|source| Error::IoPath {
        path: gitignore_path.display().to_string(),
        source,
    })?;
    let mut lines = split_lines(&existing);
    let line_bytes = line.as_bytes();
    if lines.iter().any(|l| strip_cr(l) == line_bytes) {
        return Ok(());
    }

    let begin = lines.iter().position(|l| strip_cr(l) == GITIGNORE_BEGIN);
    let end = lines.iter().rposition(|l| strip_cr(l) == GITIGNORE_END);
    match (begin, end) {
        (Some(b), Some(e)) if b < e => {
            lines.insert(e, line_bytes);
        }
        _ => {
            lines.push(GITIGNORE_BEGIN);
            lines.push(line_bytes);
            lines.push(GITIGNORE_END);
        }
    }
    atomic_write(gitignore_path, &join_lines(&lines), None)?;
    Ok(())
}

/// Formats `repo_relative_path` as a root-anchored `.gitignore` entry (plan 5.4), backslash-
/// escaping `\ * ? [ ! #` and trailing spaces.
pub fn gitignore_escape(repo_relative_path: &str) -> String {
    let literal_len = repo_relative_path.trim_end_matches(' ').len();
    let mut out = String::from("/");
    for (i, c) in repo_relative_path.char_indices() {
        if matches!(c, '\\' | '*' | '?' | '[' | '!' | '#') || (c == ' ' && i >= literal_len) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Appends each line in `lines` that is not already present verbatim (plan 5.4:
/// `.gitattributes`, which has no managed block, unlike `.gitignore`). Operates on bytes, like
/// [`ensure_gitignore_line`].
pub fn ensure_lines_present(path: &Path, lines: &[&str]) -> Result<(), Error> {
    let existing = read_or_empty(path).map_err(|source| Error::IoPath {
        path: path.display().to_string(),
        source,
    })?;
    let mut file_lines = split_lines(&existing);
    let present: BTreeSet<&[u8]> = file_lines.iter().map(|l| strip_cr(l)).collect();
    let missing: Vec<&[u8]> = lines
        .iter()
        .map(|l| l.as_bytes())
        .filter(|l| !present.contains(l))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }

    file_lines.extend(missing);
    atomic_write(path, &join_lines(&file_lines), None)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_arg_handles_plaintext_and_ciphertext_forms() {
        let plain = resolve_arg("", "secrets/prod.env").unwrap();
        assert_eq!(plain.plaintext, "secrets/prod.env");
        assert_eq!(plain.ciphertext, "secrets/prod.env.amaga");

        let cipher = resolve_arg("", "secrets/prod.env.amaga").unwrap();
        assert_eq!(cipher.plaintext, "secrets/prod.env");
        assert_eq!(cipher.ciphertext, "secrets/prod.env.amaga");
    }

    #[test]
    fn resolve_arg_applies_prefix() {
        let resolved = resolve_arg("secrets/", "prod.env").unwrap();
        assert_eq!(resolved.plaintext, "secrets/prod.env");
    }

    #[cfg(windows)]
    #[test]
    fn resolve_arg_converts_backslashes_on_windows() {
        let resolved = resolve_arg("", "secrets\\prod.env").unwrap();
        assert_eq!(resolved.plaintext, "secrets/prod.env");
    }

    #[cfg(not(windows))]
    #[test]
    fn resolve_arg_keeps_backslashes_literal_outside_windows() {
        // `\` is a legal filename character on Unix; it must not be reinterpreted as `/`.
        let resolved = resolve_arg("", "weird\\name").unwrap();
        assert_eq!(resolved.plaintext, "weird\\name");
    }

    #[test]
    fn resolve_arg_rejects_paths_leaving_the_repository() {
        let err = resolve_arg("", "../prod.env").err().unwrap();
        assert!(matches!(err, Error::PathOutsideRepo(_)));
    }

    #[test]
    fn resolve_arg_rejects_absolute_and_drive_prefixed_paths() {
        assert!(matches!(
            resolve_arg("", "/etc/passwd").err().unwrap(),
            Error::PathOutsideRepo(_)
        ));
        assert!(matches!(
            resolve_arg("", "C:\\secrets\\prod.env").err().unwrap(),
            Error::PathOutsideRepo(_)
        ));
    }

    #[test]
    fn is_absolute_like_covers_unix_and_normalized_windows_forms() {
        assert!(is_absolute_like("/etc/passwd"));
        assert!(is_absolute_like("C:/secrets/prod.env"));
        // What a Windows UNC path (`\\server\share\a`) looks like once
        // `normalize_separators` has converted it: still absolute-like.
        assert!(is_absolute_like("//server/share/a"));
        // What a Windows rooted-but-no-drive path (`\Users\x\repo\a`) looks like once
        // normalized: still absolute-like (leading `/`).
        assert!(is_absolute_like("/Users/x/repo/a"));
        assert!(!is_absolute_like("secrets/prod.env"));
    }

    // Regression: `is_absolute_like` must run on the *normalized* argument. Raw backslash
    // forms are only meaningfully exercised on an actual Windows target (`normalize_separators`
    // is `#[cfg(windows)]`); `is_absolute_like_covers_unix_and_normalized_windows_forms` above
    // covers the same classification logic on every platform.
    #[cfg(windows)]
    #[test]
    fn resolve_arg_rejects_raw_windows_absolute_and_unc_paths() {
        assert!(matches!(
            resolve_arg("", "\\Users\\x\\repo\\a").err().unwrap(),
            Error::PathOutsideRepo(_)
        ));
        assert!(matches!(
            resolve_arg("", "\\\\server\\share\\a").err().unwrap(),
            Error::PathOutsideRepo(_)
        ));
    }

    #[test]
    fn resolve_arg_rejects_control_characters() {
        let err = resolve_arg("", "prod\n.env").err().unwrap();
        assert!(matches!(err, Error::PathControlChar(_)));
    }

    #[test]
    fn resolve_arg_rejects_dot_git_and_dot_amaga() {
        assert!(matches!(
            resolve_arg("", ".git/config").err().unwrap(),
            Error::PathManaged(_)
        ));
        assert!(matches!(
            resolve_arg("", ".amaga/users/alice.txt").err().unwrap(),
            Error::PathManaged(_)
        ));
        // Case-insensitive: `.GIT`/`.AMAGA` must not slip through on a case-insensitive
        // filesystem (plan section 7).
        assert!(matches!(
            resolve_arg("", ".GIT/config").err().unwrap(),
            Error::PathManaged(_)
        ));
    }

    #[test]
    fn resolve_arg_rejects_amaga_tmp_plaintext_name() {
        let err = resolve_arg("", "prod.env.amaga-tmp").err().unwrap();
        assert!(matches!(err, Error::PathBadSuffix(_)));
    }

    #[test]
    fn resolve_arg_rejects_doubled_amaga_suffix() {
        // `secret.amaga.amaga` as the `.amaga` form has plaintext `secret.amaga`, itself
        // ending in `.amaga`.
        let err = resolve_arg("", "secret.amaga.amaga").err().unwrap();
        assert!(matches!(err, Error::PathBadSuffix(_)));
    }

    #[test]
    fn gitignore_escape_escapes_special_characters_and_trailing_space() {
        assert_eq!(gitignore_escape("secrets/prod.env"), "/secrets/prod.env");
        assert_eq!(gitignore_escape("a*b"), "/a\\*b");
        assert_eq!(gitignore_escape("a?b"), "/a\\?b");
        assert_eq!(gitignore_escape("a[b"), "/a\\[b");
        assert_eq!(gitignore_escape("a!b"), "/a\\!b");
        assert_eq!(gitignore_escape("a\\b"), "/a\\\\b");
        assert_eq!(gitignore_escape("#comment"), "/\\#comment");
        assert_eq!(gitignore_escape("trailing "), "/trailing\\ ");
    }

    #[test]
    fn ensure_gitignore_line_creates_block_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".gitignore");
        fs::write(&path, "*.log\n").unwrap();

        ensure_gitignore_line(&path, "*.amaga-tmp").unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(
            contents,
            "*.log\n# BEGIN git-amaga\n*.amaga-tmp\n# END git-amaga\n"
        );
    }

    #[test]
    fn ensure_gitignore_line_inserts_into_existing_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".gitignore");
        fs::write(&path, "# BEGIN git-amaga\n*.amaga-tmp\n# END git-amaga\n").unwrap();

        ensure_gitignore_line(&path, "/secrets/prod.env").unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(
            contents,
            "# BEGIN git-amaga\n*.amaga-tmp\n/secrets/prod.env\n# END git-amaga\n"
        );
    }

    #[test]
    fn ensure_gitignore_line_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".gitignore");
        fs::write(&path, "# BEGIN git-amaga\n*.amaga-tmp\n# END git-amaga\n").unwrap();

        ensure_gitignore_line(&path, "*.amaga-tmp").unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(
            contents,
            "# BEGIN git-amaga\n*.amaga-tmp\n# END git-amaga\n"
        );
    }

    #[test]
    fn ensure_gitignore_line_does_not_match_markers_mid_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".gitignore");
        // A real block, plus a decoy line *after* it that merely contains the end marker's
        // text. Substring search (`str::rfind`) would match the decoy instead of the real `#
        // END git-amaga` line, since it is the rightmost byte occurrence; exact whole-line
        // matching must still find the real marker.
        fs::write(
            &path,
            "# BEGIN git-amaga\n*.amaga-tmp\n# END git-amaga\nfoo # END git-amaga\n",
        )
        .unwrap();

        ensure_gitignore_line(&path, "/secrets/prod.env").unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(
            contents,
            "# BEGIN git-amaga\n*.amaga-tmp\n/secrets/prod.env\n# END git-amaga\nfoo # END git-amaga\n"
        );
    }

    #[test]
    fn ensure_gitignore_line_appends_new_block_when_end_precedes_begin() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".gitignore");
        fs::write(&path, "# END git-amaga\n# BEGIN git-amaga\n").unwrap();

        ensure_gitignore_line(&path, "*.amaga-tmp").unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(
            contents,
            "# END git-amaga\n# BEGIN git-amaga\n# BEGIN git-amaga\n*.amaga-tmp\n# END git-amaga\n"
        );
    }

    #[test]
    fn ensure_gitignore_line_preserves_non_utf8_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".gitignore");
        let mut original = b"caf\xe9\n*.log\n".to_vec();
        fs::write(&path, &original).unwrap();

        ensure_gitignore_line(&path, "*.amaga-tmp").unwrap();

        let contents = fs::read(&path).unwrap();
        original.extend_from_slice(b"# BEGIN git-amaga\n*.amaga-tmp\n# END git-amaga\n");
        assert_eq!(contents, original);
    }

    #[test]
    fn ensure_gitignore_line_matches_crlf_markers_and_keeps_crlf_endings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".gitignore");
        fs::write(
            &path,
            "# BEGIN git-amaga\r\n*.amaga-tmp\r\n# END git-amaga\r\n",
        )
        .unwrap();

        // Idempotent: the CRLF marker/entry lines must still be recognised, not duplicated.
        ensure_gitignore_line(&path, "*.amaga-tmp").unwrap();
        let contents = fs::read(&path).unwrap();
        assert_eq!(
            contents,
            b"# BEGIN git-amaga\r\n*.amaga-tmp\r\n# END git-amaga\r\n"
        );

        // A new entry is inserted before the (CRLF) end marker; existing lines keep their own
        // line ending, the new one is plain `\n`.
        ensure_gitignore_line(&path, "/secrets/prod.env").unwrap();
        let contents = fs::read(&path).unwrap();
        assert_eq!(
            contents,
            b"# BEGIN git-amaga\r\n*.amaga-tmp\r\n/secrets/prod.env\n# END git-amaga\r\n"
        );
    }

    #[test]
    fn ensure_lines_present_recognises_crlf_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".gitattributes");
        fs::write(&path, "*.amaga binary\r\n").unwrap();

        ensure_lines_present(&path, &["*.amaga binary", ".amaga/audit.jsonl merge=union"]).unwrap();

        let contents = fs::read(&path).unwrap();
        assert_eq!(
            contents,
            b"*.amaga binary\r\n.amaga/audit.jsonl merge=union\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ensure_gitignore_line_wraps_unreadable_file_error_with_path() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".gitignore");
        fs::write(&path, "*.log\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();

        if fs::read(&path).is_ok() {
            // Running as root: permission bits don't apply. Restore and skip.
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            println!(
                "skipping ensure_gitignore_line_wraps_unreadable_file_error_with_path: running as root"
            );
            return;
        }

        let err = ensure_gitignore_line(&path, "*.amaga-tmp").unwrap_err();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        match err {
            Error::IoPath { path: p, .. } => assert_eq!(p, path.display().to_string()),
            other => panic!("expected IoPath, got {other:?}"),
        }
        assert_eq!(fs::read_to_string(&path).unwrap(), "*.log\n");
    }

    #[test]
    fn atomic_write_removes_tmp_file_when_rename_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        // Renaming a file onto an existing directory fails, exercising the cleanup path.
        fs::create_dir(&path).unwrap();

        let result = atomic_write(&path, b"contents", None);
        assert!(result.is_err());

        let tmp_path = dir.path().join("out.txt.amaga-tmp");
        assert!(!tmp_path.exists());
    }

    #[test]
    fn ensure_lines_present_appends_only_missing_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".gitattributes");
        fs::write(&path, "*.amaga binary\n").unwrap();

        ensure_lines_present(&path, &["*.amaga binary", ".amaga/audit.jsonl merge=union"]).unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "*.amaga binary\n.amaga/audit.jsonl merge=union\n");
    }

    #[test]
    fn ensure_lines_present_preserves_non_utf8_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".gitattributes");
        let mut original = b"caf\xe9 binary\n".to_vec();
        fs::write(&path, &original).unwrap();

        ensure_lines_present(&path, &["*.amaga binary"]).unwrap();

        let contents = fs::read(&path).unwrap();
        original.extend_from_slice(b"*.amaga binary\n");
        assert_eq!(contents, original);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_ignores_stale_tmp_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        let tmp_path = dir.path().join("out.txt.amaga-tmp");
        fs::write(&tmp_path, b"stale").unwrap();
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o644)).unwrap();

        atomic_write(&path, b"fresh", Some(0o600)).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_does_not_follow_a_symlinked_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sensitive");
        fs::write(&target, b"do not touch").unwrap();
        let path = dir.path().join("out.txt");
        let tmp_path = dir.path().join("out.txt.amaga-tmp");
        std::os::unix::fs::symlink(&target, &tmp_path).unwrap();

        atomic_write(&path, b"new contents", None).unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "do not touch");
        assert_eq!(fs::read_to_string(&path).unwrap(), "new contents");
        assert!(
            !fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}
