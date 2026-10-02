//! Loads and validates `.amaga/users/` (plan 5.1): one member per file stem, `<name>.txt` (age
//! recipients) and/or `<name>.asc` (one OpenPGP public key). The set of user files *is* the
//! current membership.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use age::x25519;
use pgp::types::KeyDetails;

use crate::error::Error;
use crate::gpg::{self, AscKey};
use crate::secret::Recipients;

/// A member's keys, loaded from `<name>.txt` and/or `<name>.asc` (plan 5.1).
#[derive(Default)]
pub struct Member {
    pub age_keys: Vec<x25519::Recipient>,
    pub asc: Option<AscKey>,
}

/// Member name -> keys.
pub type Members = BTreeMap<String, Member>;

/// Loads and validates every file in `users_dir` (plan 5.1).
pub fn load(users_dir: &Path) -> Result<Members, Error> {
    let mut members: Members = BTreeMap::new();

    for entry in fs::read_dir(users_dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        if !path.is_file() || !valid_name(stem) || !(ext == "txt" || ext == "asc") {
            return Err(Error::UsersInvalidFile(file_name));
        }

        let member = members.entry(stem.to_string()).or_default();
        let file_error = |source: Error| Error::UsersFileError {
            file: file_name.clone(),
            source: Box::new(source),
        };
        if ext == "txt" {
            member.age_keys = parse_age_keys(&path).map_err(file_error)?;
        } else {
            let contents = fs::read_to_string(&path)
                .map_err(Error::Io)
                .map_err(file_error)?;
            member.asc = Some(gpg::validate(&contents).map_err(file_error)?);
        }
    }

    if members.is_empty() {
        return Err(Error::NoUsers);
    }

    let mut seen_keys: BTreeSet<String> = BTreeSet::new();
    let mut seen_primary_fprs: BTreeSet<String> = BTreeSet::new();
    for (name, member) in &members {
        if member.age_keys.is_empty() && member.asc.is_none() {
            return Err(Error::UsersEmptyMember(name.clone()));
        }
        for key in &member.age_keys {
            if !seen_keys.insert(key.to_string()) {
                return Err(Error::UsersDuplicateKey(key.to_string()));
            }
        }
        if let Some(asc) = &member.asc {
            let key_string = format!("pgp:{}", asc.fpr);
            if !seen_keys.insert(key_string.clone()) {
                return Err(Error::UsersDuplicateKey(key_string));
            }
            let primary_fpr = format!("{:X}", asc.key.primary_key.fingerprint());
            if !seen_primary_fprs.insert(primary_fpr.clone()) {
                return Err(Error::UsersDuplicateKey(primary_fpr));
            }
        }
    }

    Ok(members)
}

/// `[a-z0-9][a-z0-9._-]{0,63}` (plan 5.1): lowercase, so names cannot collide on
/// case-insensitive filesystems.
pub(crate) fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    name.len() <= 64
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

fn parse_age_keys(path: &Path) -> Result<Vec<x25519::Recipient>, Error> {
    let contents = fs::read_to_string(path)?;
    contents
        .lines()
        .map(|line| line.trim_end_matches('\r').trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            line.parse::<x25519::Recipient>()
                .map_err(|_| Error::AgeRecipientParse(line.to_string()))
        })
        .collect()
}

/// The current recipient set (plan 5.1/5.2): member name -> key strings, for
/// [`crate::secret::next_header`].
pub fn recipients(members: &Members) -> Recipients {
    members
        .iter()
        .map(|(name, member)| {
            let mut keys: BTreeSet<String> =
                member.age_keys.iter().map(|k| k.to_string()).collect();
            if let Some(asc) = &member.asc {
                keys.insert(format!("pgp:{}", asc.fpr));
            }
            (name.clone(), keys)
        })
        .collect()
}

// Fixture generation commands (plan section 11), run with a short-lived `GNUPGHOME` (never
// `~/.gnupg`):
//
//   rotated_subkey_old.asc / rotated_subkey_new.asc: same primary key, two exports taken before
//   and after a second encryption subkey is added, so each selects a different encryption
//   subkey (plan 5.1's "newest non-revoked" rule) while sharing one primary fingerprint.
//     gpg --batch --passphrase '' --quick-gen-key 'Rotate <rotate@example.invalid>' \
//       default default never
//     gpg --armor --export-options export-minimal --export <fpr> > rotated_subkey_old.asc
//     gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key <fpr> default encr \
//       never
//     gpg --armor --export-options export-minimal --export <fpr> > rotated_subkey_new.asc
#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, contents: &str) {
        fs::write(dir.join(name), contents).unwrap();
    }

    #[test]
    fn loads_age_keys_with_comments_and_crlf() {
        let dir = tempfile::tempdir().unwrap();
        let key = x25519::Identity::generate().to_public().to_string();
        write(
            dir.path(),
            "alice.txt",
            &format!("# laptop\r\n{key}\r\n\r\n# comment only\r\n"),
        );

        let members = load(dir.path()).unwrap();
        assert_eq!(members.len(), 1);
        let alice = &members["alice"];
        assert_eq!(alice.age_keys.len(), 1);
        assert_eq!(alice.age_keys[0].to_string(), key);
    }

    #[test]
    fn rejects_invalid_age_line() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "alice.txt", "not-a-key\n");

        let err = load(dir.path()).err().unwrap();
        match err {
            Error::UsersFileError { file, source } => {
                assert_eq!(file, "alice.txt");
                assert!(matches!(*source, Error::AgeRecipientParse(_)));
            }
            other => panic!("expected UsersFileError, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_member_name() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "Alice.txt", "age1\n");

        let err = load(dir.path()).err().unwrap();
        assert!(matches!(err, Error::UsersInvalidFile(_)));
    }

    #[test]
    fn rejects_duplicate_key_across_members() {
        let dir = tempfile::tempdir().unwrap();
        let key = x25519::Identity::generate().to_public().to_string();
        write(dir.path(), "alice.txt", &format!("{key}\n"));
        write(dir.path(), "bob.txt", &format!("{key}\n"));

        let err = load(dir.path()).err().unwrap();
        assert!(matches!(err, Error::UsersDuplicateKey(_)));
    }

    #[test]
    fn rejects_empty_member() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "alice.txt", "# only a comment\n");

        let err = load(dir.path()).err().unwrap();
        assert!(matches!(err, Error::UsersEmptyMember(_)));
    }

    #[test]
    fn no_user_files_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = load(dir.path()).err().unwrap();
        assert!(matches!(err, Error::NoUsers));
    }

    #[test]
    fn recipients_combines_age_and_pgp_keys() {
        let dir = tempfile::tempdir().unwrap();
        let key = x25519::Identity::generate().to_public().to_string();
        write(dir.path(), "alice.txt", &format!("{key}\n"));
        write(
            dir.path(),
            "bob.asc",
            include_str!("../tests/fixtures/valid_cv25519.asc"),
        );

        let members = load(dir.path()).unwrap();
        let recipients = recipients(&members);
        assert_eq!(recipients["alice"], BTreeSet::from([key]));
        let bob_fpr = members["bob"].asc.as_ref().unwrap().fpr.clone();
        assert_eq!(
            recipients["bob"],
            BTreeSet::from([format!("pgp:{bob_fpr}")])
        );
    }

    #[test]
    fn loads_asc_key() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "bob.asc",
            include_str!("../tests/fixtures/valid_cv25519.asc"),
        );

        let members = load(dir.path()).unwrap();
        assert_eq!(members.len(), 1);
        assert!(members["bob"].asc.is_some());
        assert!(members["bob"].age_keys.is_empty());
    }

    #[test]
    fn rejects_non_txt_asc_file() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "alice.pub", "age1\n");

        let err = load(dir.path()).err().unwrap();
        assert!(matches!(err, Error::UsersInvalidFile(_)));
    }

    #[test]
    fn rejects_subdirectory() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("alice")).unwrap();

        let err = load(dir.path()).err().unwrap();
        assert!(matches!(err, Error::UsersInvalidFile(_)));
    }

    #[test]
    fn rejects_duplicate_primary_fingerprint_with_different_subkey() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "alice.asc",
            include_str!("../tests/fixtures/rotated_subkey_old.asc"),
        );
        write(
            dir.path(),
            "bob.asc",
            include_str!("../tests/fixtures/rotated_subkey_new.asc"),
        );

        // Confirms the fixtures actually exercise the primary-fingerprint path: different
        // selected-subkey fingerprints, same primary key.
        let alice_asc =
            crate::gpg::validate(include_str!("../tests/fixtures/rotated_subkey_old.asc")).unwrap();
        let bob_asc =
            crate::gpg::validate(include_str!("../tests/fixtures/rotated_subkey_new.asc")).unwrap();
        assert_ne!(alice_asc.fpr, bob_asc.fpr);

        let err = load(dir.path()).err().unwrap();
        assert!(matches!(err, Error::UsersDuplicateKey(_)));
    }
}
