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
use crate::keyring::ResolvedKeys;
use crate::paths;
use crate::secret::Recipients;

/// A member's keys, loaded from `<name>.txt` and/or `<name>.asc` (plan 5.1).
#[derive(Default)]
pub struct Member {
    pub age_keys: Vec<x25519::Recipient>,
    pub asc: Option<AscKey>,
}

pub type Members = BTreeMap<String, Member>;

pub fn load(users_dir: &Path) -> Result<Members, Error> {
    load_tolerating(users_dir, None)
}

/// Like [`load`], but member `tolerated` is not validated: its invalid files are skipped and it is
/// left out of the empty and duplicate-key checks. `user remove` does not validate what it
/// removes (plan 7).
pub(crate) fn load_tolerating(users_dir: &Path, tolerated: Option<&str>) -> Result<Members, Error> {
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

        // The member entry is created only for a file that loads, so the result does not depend
        // on the order of the directory listing.
        match read_member_file(&path, ext) {
            Ok(parsed) => {
                let member = members.entry(stem.to_string()).or_default();
                if ext == "txt" {
                    member.age_keys = parsed.age_keys;
                } else {
                    member.asc = parsed.asc;
                }
            }
            Err(_) if tolerated == Some(stem) => {}
            Err(source) => {
                return Err(Error::UsersFileError {
                    file: file_name,
                    source: Box::new(source),
                });
            }
        }
    }

    if members.is_empty() {
        return Err(Error::NoUsers);
    }
    check(&members, tolerated)?;
    Ok(members)
}

// A member holding only what the one file at `path` provides.
fn read_member_file(path: &Path, ext: &str) -> Result<Member, Error> {
    let mut member = Member::default();
    if ext == "txt" {
        member.age_keys = parse_age_keys(path)?;
    } else {
        member.asc = Some(gpg::validate(&fs::read_to_string(path)?)?);
    }
    Ok(member)
}

/// Every member has keys, and no key or OpenPGP primary fingerprint is used twice (plan 5.1);
/// member `skipped` is not looked at.
pub(crate) fn check(members: &Members, skipped: Option<&str>) -> Result<(), Error> {
    let mut seen_keys: BTreeSet<String> = BTreeSet::new();
    let mut seen_primary_fprs: BTreeSet<String> = BTreeSet::new();
    for (name, member) in members.iter().filter(|(n, _)| Some(n.as_str()) != skipped) {
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
    Ok(())
}

/// The member those resolved `KEY`s describe.
pub(crate) fn member_from_keys(keys: &ResolvedKeys) -> Member {
    Member {
        age_keys: keys.age_keys.clone(),
        asc: keys.gpg.as_ref().map(|key| key.asc.clone()),
    }
}

/// Writes `<name>.txt` and/or `<name>.asc` (the `.asc` byte for byte) into `users_dir`.
pub(crate) fn write_member(users_dir: &Path, name: &str, keys: &ResolvedKeys) -> Result<(), Error> {
    if !keys.age_keys.is_empty() {
        let lines: Vec<String> = keys.age_keys.iter().map(|k| k.to_string()).collect();
        let contents = format!("{}\n", lines.join("\n"));
        paths::atomic_write(
            &users_dir.join(format!("{name}.txt")),
            contents.as_bytes(),
            None,
        )?;
    }
    if let Some(key) = &keys.gpg {
        let asc = users_dir.join(format!("{name}.asc"));
        paths::atomic_write(&asc, key.armored.as_bytes(), None)?;
    }
    Ok(())
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

/// Member name -> key strings, for [`crate::secret::next_header`] (plan 5.2).
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

// Fixture recipes: tests/fixtures/README.md (plan 11).
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
    fn tolerated_member_keeps_its_valid_files_in_any_listing_order() {
        // The listing order depends on the file names, so many names make both orders occur.
        for i in 0..20 {
            let name = format!("m{i}");
            let dir = tempfile::tempdir().unwrap();
            let key = x25519::Identity::generate().to_public().to_string();
            write(
                dir.path(),
                "alice.txt",
                &format!("{}\n", x25519::Identity::generate().to_public()),
            );
            write(dir.path(), &format!("{name}.txt"), &format!("{key}\n"));
            write(dir.path(), &format!("{name}.asc"), "not a key");

            let members = load_tolerating(dir.path(), Some(&name)).unwrap();
            assert_eq!(members[&name].age_keys.len(), 1);
            assert!(members[&name].asc.is_none());
        }
    }

    #[test]
    fn tolerated_member_is_not_checked_for_empty_or_duplicate_keys() {
        let dir = tempfile::tempdir().unwrap();
        let key = x25519::Identity::generate().to_public().to_string();
        write(dir.path(), "alice.txt", &format!("{key}\n"));
        write(dir.path(), "bob.txt", &format!("{key}\n"));
        write(dir.path(), "carol.txt", "# no keys\n");

        assert!(matches!(
            load_tolerating(dir.path(), Some("bob")).err().unwrap(),
            Error::UsersEmptyMember(_)
        ));
        fs::remove_file(dir.path().join("carol.txt")).unwrap();
        assert!(load_tolerating(dir.path(), Some("bob")).is_ok());
        assert!(matches!(
            load(dir.path()).err().unwrap(),
            Error::UsersDuplicateKey(_)
        ));
        fs::write(dir.path().join("bob.txt"), "# no keys\n").unwrap();
        assert!(load_tolerating(dir.path(), Some("bob")).is_ok());
    }

    #[test]
    fn tolerated_member_with_only_invalid_files_is_left_out() {
        let dir = tempfile::tempdir().unwrap();
        let key = x25519::Identity::generate().to_public().to_string();
        write(dir.path(), "alice.txt", &format!("{key}\n"));
        write(dir.path(), "bob.asc", "not a key");

        let members = load_tolerating(dir.path(), Some("bob")).unwrap();
        assert_eq!(members.keys().collect::<Vec<_>>(), ["alice"]);
        assert!(load(dir.path()).is_err());
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
