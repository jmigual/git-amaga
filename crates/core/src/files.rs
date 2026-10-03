use std::fs;
use std::path::Path;

use crate::{Error, git, paths};

// Regular files only: following a symlinked secret could decrypt, then re-encrypt, a file from
// another repository (plan 3).
pub(crate) fn read_repo_file(root: &Path, path: &str) -> Result<Vec<u8>, Error> {
    let full = root.join(path);
    let io_error = |source| Error::IoPath {
        path: path.to_string(),
        source,
    };
    if !fs::symlink_metadata(&full)
        .map_err(io_error)?
        .file_type()
        .is_file()
    {
        return Err(Error::NotARegularFile(path.to_string()));
    }
    fs::read(&full).map_err(io_error)
}

// `None` only when the plaintext does not exist; other read errors must not look like `Closed`.
pub(crate) fn read_plaintext(root: &Path, path: &str) -> Result<Option<Vec<u8>>, Error> {
    match read_repo_file(root, path) {
        Err(Error::IoPath { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            Ok(None)
        }
        other => other.map(Some),
    }
}

pub(crate) fn write_repo_file(
    root: &Path,
    path: &str,
    contents: &[u8],
    mode: Option<u32>,
) -> Result<(), Error> {
    paths::atomic_write(&root.join(path), contents, mode).map_err(|source| Error::IoPath {
        path: path.to_string(),
        source,
    })
}

pub(crate) fn ensure_ignored(root: &Path, path: &str) -> Result<(), Error> {
    if git::is_ignored(root, path)? {
        return Ok(());
    }
    paths::ensure_gitignore_line(&root.join(".gitignore"), &paths::gitignore_escape(path))?;
    if !git::is_ignored(root, path)? {
        return Err(Error::PlaintextNotIgnored(path.to_string()));
    }
    Ok(())
}
