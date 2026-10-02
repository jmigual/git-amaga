//! age identity loading and `keygen` (plan 5.5).

use std::fs;
use std::path::{Path, PathBuf};

use age::secrecy::ExposeSecret;
use age::x25519;

use crate::error::Error;
use crate::git;

/// The default identity path when `amaga.identity` is unset (plan 5.5):
/// `~/.config/git-amaga/identity.txt`.
pub fn default_identity_path() -> Result<PathBuf, Error> {
    let home = std::env::home_dir().ok_or(Error::NoHomeDir)?;
    Ok(default_identity_path_under(&home))
}

/// The default identity path given a home directory, split out from [`default_identity_path`]
/// so the join logic is unit-testable without reading the real environment.
fn default_identity_path_under(home: &Path) -> PathBuf {
    home.join(".config").join("git-amaga").join("identity.txt")
}

/// Resolves the configured age identity file path (plan 5.5): `git config --type=path
/// amaga.identity` in any scope, falling back to [`default_identity_path`] only if that file
/// exists. `None` if neither is configured/present.
pub fn configured_identity_path() -> Result<Option<PathBuf>, Error> {
    let configured = git::config_get_path("amaga.identity")?;
    let default = default_identity_path()?;
    Ok(resolve_configured_identity_path(configured, &default))
}

/// The default-path-fallback half of [`configured_identity_path`], split out so it is
/// unit-testable without reading real Git config: `configured` wins if present, otherwise
/// `default_path` is used only if it exists.
fn resolve_configured_identity_path(
    configured: Option<String>,
    default_path: &Path,
) -> Option<PathBuf> {
    if let Some(path) = configured {
        return Some(PathBuf::from(path));
    }
    default_path.is_file().then(|| default_path.to_path_buf())
}

/// Parses every `AGE-SECRET-KEY-1…` line in `path` (plan 5.5). `\r` is stripped (autocrlf).
/// Blank lines and `#` comments are skipped.
pub fn load_identity_file(path: &Path) -> Result<Vec<x25519::Identity>, Error> {
    let contents = fs::read_to_string(path).map_err(|source| Error::IoPath {
        path: path.display().to_string(),
        source,
    })?;
    contents
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .enumerate()
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .map(|(i, line)| {
            line.parse::<x25519::Identity>()
                .map_err(|_| Error::IdentityParse {
                    path: path.display().to_string(),
                    line: i + 1,
                })
        })
        .collect()
}

/// Generates a new age identity and writes it to `path`, or [`default_identity_path`] if `None`
/// (plan: `keygen`). Refuses to overwrite an existing file. Sets `amaga.identity` in the global
/// config if it is unset there. Returns the path written and the public key.
pub fn keygen(path: Option<&Path>) -> Result<(PathBuf, x25519::Recipient), Error> {
    let (path, public) = write_identity(path)?;

    if git::config_get_global("amaga.identity")?.is_none() {
        git::config_set_global("amaga.identity", &path.to_string_lossy())?;
    }

    Ok((path, public))
}

/// The file-writing half of [`keygen`], kept separate so unit tests can exercise it without
/// touching any Git config (real or isolated): generates the identity and writes it to `path`,
/// or [`default_identity_path`] if `None`, refusing to overwrite an existing file.
fn write_identity(path: Option<&Path>) -> Result<(PathBuf, x25519::Recipient), Error> {
    let path = match path {
        Some(p) => p.to_path_buf(),
        None => default_identity_path()?,
    };
    // Lexical absolutization (not `canonicalize`, plan section 7): `amaga.identity` must resolve
    // the same way regardless of the cwd a later command runs from.
    let path = std::path::absolute(&path).map_err(|source| Error::IoPath {
        path: path.display().to_string(),
        source,
    })?;
    if path.exists() {
        return Err(Error::IdentityExists(path.display().to_string()));
    }

    let identity = x25519::Identity::generate();
    let public = identity.to_public();
    let contents = format!(
        "# public key: {public}\n{}\n",
        identity.to_string().expose_secret()
    );
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    write_atomic(&path, contents.as_bytes())?;

    Ok((path, public))
}

/// Writes `contents` to `path` via a `0600` temp file, `sync_all`, then rename (plan section 7):
/// never a partially written identity file at `path`. Removes any stale temp file first, since
/// `OpenOptions::mode` only applies when *creating* a file (a leftover temp file would otherwise
/// keep its old permissions, or — if it were a symlink — be followed instead of replaced), and
/// cleans up the temp file if writing or the final rename fails.
fn write_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(".amaga-tmp");
    let tmp_path = PathBuf::from(tmp_name);

    match fs::remove_file(&tmp_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let result = (|| -> std::io::Result<()> {
        let mut file = create_identity_file(&tmp_path)?;
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
fn create_identity_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_identity_file(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_configured_identity_path_prefers_configured_value() {
        let resolved = resolve_configured_identity_path(
            Some("/configured/identity.txt".to_string()),
            Path::new("/default/identity.txt"),
        );
        assert_eq!(resolved, Some(PathBuf::from("/configured/identity.txt")));
    }

    #[test]
    fn resolve_configured_identity_path_falls_back_to_existing_default() {
        let dir = tempfile::tempdir().unwrap();
        let default_path = dir.path().join("identity.txt");
        fs::write(&default_path, "placeholder").unwrap();

        assert_eq!(
            resolve_configured_identity_path(None, &default_path),
            Some(default_path)
        );
    }

    #[test]
    fn resolve_configured_identity_path_is_none_when_default_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let default_path = dir.path().join("identity.txt");

        assert_eq!(resolve_configured_identity_path(None, &default_path), None);
    }

    #[test]
    fn default_identity_path_under_joins_config_subdir() {
        let path = default_identity_path_under(Path::new("/home/alice"));
        assert_eq!(
            path,
            Path::new("/home/alice/.config/git-amaga/identity.txt")
        );
    }

    #[test]
    fn load_identity_file_parses_and_strips_cr_and_comments() {
        let dir = tempfile::tempdir().unwrap();
        let identity = x25519::Identity::generate();
        let secret_string = identity.to_string();
        let secret = secret_string.expose_secret();
        let path = dir.path().join("identity.txt");
        fs::write(&path, format!("# comment\r\n\r\n{secret}\r\n")).unwrap();

        let loaded = load_identity_file(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded[0].to_public().to_string(),
            identity.to_public().to_string()
        );
    }

    #[test]
    fn load_identity_file_rejects_invalid_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.txt");
        fs::write(&path, "not an identity\n").unwrap();

        let err = load_identity_file(&path).err().unwrap();
        match &err {
            Error::IdentityParse { line, .. } => assert_eq!(*line, 1),
            other => panic!("expected IdentityParse, got {other:?}"),
        }
        // The line is never echoed: it may be secret key material (plan 5.5).
        assert!(!err.to_string().contains("not an identity"));
    }

    #[test]
    fn write_identity_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.txt");
        fs::write(&path, "existing").unwrap();

        let err = write_identity(Some(&path)).unwrap_err();
        assert!(matches!(err, Error::IdentityExists(_)));
    }

    #[cfg(unix)]
    #[test]
    fn write_identity_creates_file_with_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.txt");

        let (written_path, public) = write_identity(Some(&path)).unwrap();
        assert_eq!(written_path, path);

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.starts_with(&format!("# public key: {public}\n")));
        assert!(contents.contains("AGE-SECRET-KEY-1"));
    }

    #[cfg(unix)]
    #[test]
    fn write_identity_ignores_stale_tmp_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.txt");
        let tmp_path = dir.path().join("identity.txt.amaga-tmp");
        fs::write(&tmp_path, b"stale").unwrap();
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o644)).unwrap();

        write_identity(Some(&path)).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
