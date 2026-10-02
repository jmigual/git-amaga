//! age identity loading and `keygen` (plan 5.5).

use std::fs;
use std::path::{Path, PathBuf};

use age::secrecy::ExposeSecret;
use age::x25519;
use pgp::types::KeyDetails;

use crate::error::Error;
use crate::git;
use crate::paths;
use crate::users;

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
    paths::atomic_write(&path, contents.as_bytes(), Some(0o600))?;

    Ok((path, public))
}

/// Finds the actor (plan 5.5): the member whose age key matches an identity, else the first
/// member holding a GPG key. Also returns the subkey fingerprints of every held GPG member, the
/// `GpgIdentity` input; empty without probing gpg when an age identity matches. `is_held` is
/// injected (production passes [`crate::gpg::is_held`]) so tests do not need a real `gpg`.
pub fn find_actor(
    members: &users::Members,
    age_identities: &[x25519::Identity],
    is_held: impl Fn(&str) -> std::io::Result<bool>,
) -> Result<(String, Vec<String>), Error> {
    let age_publics: Vec<String> = age_identities
        .iter()
        .map(|id| id.to_public().to_string())
        .collect();
    for (name, member) in members {
        if member
            .age_keys
            .iter()
            .any(|k| age_publics.contains(&k.to_string()))
        {
            return Ok((name.clone(), Vec::new()));
        }
    }

    let mut gpg_absent = false;
    let mut first_held = None;
    let mut gpg_fprs = Vec::new();
    for (name, member) in members {
        let Some(asc) = &member.asc else { continue };
        let primary_fpr = format!("{:X}", asc.key.primary_key.fingerprint());
        match is_held(&primary_fpr) {
            Ok(true) => {
                first_held.get_or_insert(name);
                gpg_fprs.extend(asc.subkey_fprs());
            }
            Ok(false) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => gpg_absent = true,
            Err(_) => {}
        }
    }

    match first_held {
        Some(name) => Ok((name.clone(), gpg_fprs)),
        None => Err(Error::NotAMember(member_summary(members, gpg_absent))),
    }
}

fn member_summary(members: &users::Members, gpg_absent: bool) -> String {
    let descriptions: Vec<String> = members
        .iter()
        .map(|(name, member)| {
            let mut kinds = Vec::new();
            if !member.age_keys.is_empty() {
                kinds.push("age");
            }
            if member.asc.is_some() {
                kinds.push("gpg");
            }
            format!("{name} ({})", kinds.join(", "))
        })
        // `members` is a `BTreeMap`, so iteration (and this collected `Vec`) is already sorted
        // by name.
        .collect();
    let mut summary = descriptions.join(", ");
    if gpg_absent {
        summary.push_str("; gpg not found on PATH");
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_actor_matches_age_before_probing_gpg() {
        let identity = x25519::Identity::generate();
        let asc =
            crate::gpg::validate(include_str!("../tests/fixtures/valid_cv25519.asc")).unwrap();
        let mut members = users::Members::new();
        members.insert(
            "alice".to_string(),
            users::Member {
                age_keys: vec![identity.to_public()],
                asc: Some(asc),
            },
        );

        let (actor, gpg_fprs) = find_actor(&members, std::slice::from_ref(&identity), |_| {
            panic!("gpg should not be probed when an age identity matches")
        })
        .unwrap();
        assert_eq!(actor, "alice");
        assert!(gpg_fprs.is_empty());
    }

    #[test]
    fn find_actor_falls_back_to_held_gpg_member() {
        let asc =
            crate::gpg::validate(include_str!("../tests/fixtures/valid_cv25519.asc")).unwrap();
        let mut members = users::Members::new();
        members.insert(
            "bob".to_string(),
            users::Member {
                age_keys: Vec::new(),
                asc: Some(asc),
            },
        );

        let (actor, _) = find_actor(&members, &[], |_| Ok(true)).unwrap();
        assert_eq!(actor, "bob");
    }

    #[test]
    fn find_actor_returns_every_subkey_fpr_of_held_gpg_members_only() {
        let held = crate::gpg::validate(include_str!("../tests/fixtures/two_subkeys.asc")).unwrap();
        let held_primary = format!("{:X}", held.key.primary_key.fingerprint());
        let all_subkeys = held.subkey_fprs();
        assert!(all_subkeys.len() > 1);
        let other = crate::gpg::validate(include_str!("../tests/fixtures/valid_rsa.asc")).unwrap();
        let mut members = users::Members::new();
        members.insert(
            "alice".to_string(),
            users::Member {
                age_keys: Vec::new(),
                asc: Some(held),
            },
        );
        members.insert(
            "bob".to_string(),
            users::Member {
                age_keys: Vec::new(),
                asc: Some(other),
            },
        );

        let (actor, mut fprs) = find_actor(&members, &[], |fpr| Ok(fpr == held_primary)).unwrap();
        fprs.sort();
        let mut expected = all_subkeys;
        expected.sort();
        assert_eq!(actor, "alice");
        assert_eq!(fprs, expected);
    }

    #[test]
    fn find_actor_errors_and_lists_members_when_nothing_matches() {
        let member_key = x25519::Identity::generate().to_public();
        let mut members = users::Members::new();
        members.insert(
            "alice".to_string(),
            users::Member {
                age_keys: vec![member_key],
                asc: None,
            },
        );

        let err = find_actor(&members, &[], |_| Ok(false)).unwrap_err();
        match err {
            Error::NotAMember(summary) => assert!(summary.contains("alice")),
            other => panic!("expected NotAMember, got {other:?}"),
        }
    }

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
    fn find_actor_reports_gpg_absent_in_the_member_summary() {
        let asc =
            crate::gpg::validate(include_str!("../tests/fixtures/valid_cv25519.asc")).unwrap();
        let mut members = users::Members::new();
        members.insert(
            "bob".to_string(),
            users::Member {
                age_keys: Vec::new(),
                asc: Some(asc),
            },
        );

        let err = find_actor(&members, &[], |_| {
            Err(std::io::Error::from(std::io::ErrorKind::NotFound))
        })
        .unwrap_err();
        match err {
            Error::NotAMember(summary) => assert!(summary.contains("gpg not found on PATH")),
            other => panic!("expected NotAMember, got {other:?}"),
        }
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
}
