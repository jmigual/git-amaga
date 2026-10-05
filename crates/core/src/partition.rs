//! `.amaga/partitions/<p>/{members,current-epoch}` (plan 5.7, ADR-0017).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::str::FromStr;

use age::x25519;

use crate::error::Error;
use crate::users::{self, Members};
use crate::{epoch, paths};

/// The partition `init` creates, which always exists.
pub const DEFAULT: &str = "default";

const DIR: &str = ".amaga/partitions";

/// A partition: the member names it lists and its current epoch's public key (plan 5.7).
pub struct Partition {
    /// Listed names; one that is not a user grants nothing.
    pub members: BTreeSet<String>,
    /// The key `current-epoch` names.
    pub current: x25519::Recipient,
}

/// Partition name -> partition.
pub type Partitions = BTreeMap<String, Partition>;

/// The partition the `amaga-partition` git attribute gives `plaintext`, if any (plan 5.7). A
/// value that is `set`, `unset` or not a partition name is [`Error::PartitionAttributeInvalid`].
pub(crate) fn attribute(root: &Path, plaintext: &str) -> Result<Option<String>, Error> {
    let attrs = crate::git::check_attr(root, &["amaga-partition"], &[plaintext])?;
    let Some((_, _, value)) = attrs.into_iter().next() else {
        return Ok(None);
    };
    attribute_value(plaintext, value)
}

/// [`attribute`] for the `value` `git check-attr` already reported for `plaintext`.
pub(crate) fn attribute_value(plaintext: &str, value: String) -> Result<Option<String>, Error> {
    match value.as_str() {
        "unspecified" => Ok(None),
        v if users::valid_name(v) && v != "set" && v != "unset" => Ok(Some(value)),
        _ => Err(Error::PartitionAttributeInvalid(plaintext.to_string())),
    }
}

fn members_path(p: &str) -> String {
    format!("{DIR}/{p}/members")
}

fn pointer_path(p: &str) -> String {
    format!("{DIR}/{p}/current-epoch")
}

fn invalid(p: &str, why: &str) -> Error {
    Error::PartitionInvalid(format!("{p}: {why}"))
}

fn io_error(path: String) -> impl FnOnce(std::io::Error) -> Error {
    |source| Error::IoPath { path, source }
}

/// Loads every partition under `root` (plan 5.7). A missing `default` pointer is
/// [`Error::NoEpoch`]; anything else malformed is [`Error::PartitionInvalid`].
pub fn load(root: &Path, users: &Members) -> Result<Partitions, Error> {
    let mut names = Vec::new();
    match fs::read_dir(root.join(DIR)) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(io_error(DIR.into()))?;
                names.push((entry.file_name().to_string_lossy().into_owned(), entry));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::NoEpoch),
        Err(source) => return Err(io_error(DIR.into())(source)),
    }
    names.sort_by(|a, b| a.0.cmp(&b.0));
    let mut partitions = Partitions::new();
    for (name, entry) in names {
        if !users::valid_name(&name) || !entry.path().is_dir() {
            return Err(invalid(&name, "not a partition directory"));
        }
        let partition = load_one(root, &name, users)?;
        partitions.insert(name, partition);
    }
    if !partitions.contains_key(DEFAULT) {
        return Err(Error::NoEpoch);
    }
    Ok(partitions)
}

fn load_one(root: &Path, p: &str, users: &Members) -> Result<Partition, Error> {
    let members = read_members(root, p)?;
    if !members.iter().any(|name| users.contains_key(name)) {
        return Err(invalid(p, "lists no member that is a user"));
    }
    let current = match read_pointer(root, p) {
        Err(Error::NoEpoch) if p != DEFAULT => return Err(invalid(p, "current-epoch is missing")),
        other => other?,
    };
    Ok(Partition { members, current })
}

fn read_members(root: &Path, p: &str) -> Result<BTreeSet<String>, Error> {
    let path = members_path(p);
    let contents = match fs::read_to_string(root.join(&path)) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(invalid(p, "members is missing"));
        }
        Err(source) => return Err(io_error(path)(source)),
    };
    let mut names = BTreeSet::new();
    for line in contents.lines().map(|l| l.trim_end_matches('\r')) {
        if line.is_empty() {
            continue;
        }
        if !users::valid_name(line) {
            let why = format!("'{line}' is not a valid member name; edit {path}");
            return Err(invalid(p, &why));
        }
        names.insert(line.to_string());
    }
    Ok(names)
}

/// Writes the sorted names of `members` to partition `p`, creating its directory.
pub fn write_members(root: &Path, p: &str, members: &BTreeSet<String>) -> Result<(), Error> {
    let path = members_path(p);
    let full = root.join(&path);
    let contents: String = members.iter().map(|name| format!("{name}\n")).collect();
    let result = full
        .parent()
        .map_or(Ok(()), fs::create_dir_all)
        .and_then(|()| paths::atomic_write(&full, contents.as_bytes(), None));
    result.map_err(io_error(path))
}

/// The current epoch's public key of partition `p`; the epoch file must exist.
pub fn read_pointer(root: &Path, p: &str) -> Result<x25519::Recipient, Error> {
    let path = pointer_path(p);
    let contents = match fs::read_to_string(root.join(&path)) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::NoEpoch),
        Err(source) => return Err(io_error(path)(source)),
    };
    let recipient = x25519::Recipient::from_str(contents.trim())
        .map_err(|_| Error::EpochInvalid(format!("{path}: not an age public key")))?;
    let epoch_path = epoch::file_path(&recipient.to_string());
    if !root.join(&epoch_path).is_file() {
        return Err(Error::EpochInvalid(format!(
            "{path}: {epoch_path} does not exist"
        )));
    }
    Ok(recipient)
}

/// Points partition `p` at epoch `id`, atomically, creating its directory.
pub fn write_pointer(root: &Path, p: &str, id: &str) -> Result<(), Error> {
    let path = pointer_path(p);
    let full = root.join(&path);
    let result = full
        .parent()
        .map_or(Ok(()), fs::create_dir_all)
        .and_then(|()| paths::atomic_write(&full, format!("{id}\n").as_bytes(), None));
    result.map_err(io_error(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch::Epoch;
    use crate::secret::Recipients;
    use crate::users::Member;

    fn member() -> Member {
        Member {
            age_keys: vec![x25519::Identity::generate().to_public()],
            asc: None,
        }
    }

    fn users(names: &[&str]) -> Members {
        names.iter().map(|n| (n.to_string(), member())).collect()
    }

    // A partition `p` with the given `members` text and a pointer to a real epoch file.
    fn write_partition(root: &Path, p: &str, members: &str) {
        let key = x25519::Identity::generate().to_public();
        let epoch = Epoch::generate(Recipients::new());
        epoch::write(root, &epoch, &[&key]).unwrap();
        fs::create_dir_all(root.join(DIR).join(p)).unwrap();
        fs::write(root.join(members_path(p)), members).unwrap();
        write_pointer(root, p, &epoch.id()).unwrap();
    }

    fn assert_invalid(root: &Path, users: &Members) {
        assert!(matches!(load(root, users), Err(Error::PartitionInvalid(_))));
    }

    #[test]
    fn members_load_with_crlf_blank_lines_and_duplicates() {
        let root = tempfile::tempdir().unwrap();
        write_partition(root.path(), DEFAULT, "bob\r\n\r\nalice\nbob\n");
        let loaded = load(root.path(), &users(&["alice", "bob"])).unwrap();
        let names: Vec<&str> = loaded[DEFAULT].members.iter().map(String::as_str).collect();
        assert_eq!(names, ["alice", "bob"]);
    }

    #[test]
    fn a_name_that_is_not_a_user_loads_but_a_list_without_users_does_not() {
        let root = tempfile::tempdir().unwrap();
        write_partition(root.path(), DEFAULT, "alice\nghost\n");
        let loaded = load(root.path(), &users(&["alice"])).unwrap();
        assert!(loaded[DEFAULT].members.contains("ghost"));

        write_partition(root.path(), DEFAULT, "ghost\n");
        assert_invalid(root.path(), &users(&["alice"]));
    }

    #[test]
    fn malformed_partitions_are_invalid() {
        let users = users(&["alice"]);
        let cases: [fn(&Path); 5] = [
            |root| write_partition(root, DEFAULT, "Alice\n"),
            |root| write_partition(root, DEFAULT, "\n"),
            |root| write_partition(root, "Bad Name", "alice\n"),
            |root| fs::write(root.join(DIR).join("notes"), "").unwrap(),
            |root| {
                write_partition(root, "prod", "alice\n");
                fs::remove_file(root.join(pointer_path("prod"))).unwrap();
            },
        ];
        for case in cases {
            let root = tempfile::tempdir().unwrap();
            write_partition(root.path(), DEFAULT, "alice\n");
            case(root.path());
            assert_invalid(root.path(), &users);
        }
    }

    #[test]
    fn a_missing_default_is_no_epoch() {
        let root = tempfile::tempdir().unwrap();
        assert!(matches!(
            load(root.path(), &users(&["alice"])),
            Err(Error::NoEpoch)
        ));
        write_partition(root.path(), "prod", "alice\n");
        assert!(matches!(
            load(root.path(), &users(&["alice"])),
            Err(Error::NoEpoch)
        ));
        write_partition(root.path(), DEFAULT, "alice\n");
        fs::remove_file(root.path().join(pointer_path(DEFAULT))).unwrap();
        assert!(matches!(
            load(root.path(), &users(&["alice"])),
            Err(Error::NoEpoch)
        ));
    }

    #[test]
    fn write_members_writes_sorted_names() {
        let root = tempfile::tempdir().unwrap();
        let names = BTreeSet::from(["bob".to_string(), "alice".to_string()]);
        write_members(root.path(), "prod", &names).unwrap();
        let text = fs::read_to_string(root.path().join(members_path("prod"))).unwrap();
        assert_eq!(text, "alice\nbob\n");
    }

    #[test]
    fn the_pointer_is_read_with_crlf_and_must_name_an_existing_epoch() {
        let root = tempfile::tempdir().unwrap();
        assert!(matches!(
            read_pointer(root.path(), DEFAULT),
            Err(Error::NoEpoch)
        ));

        let alice = x25519::Identity::generate().to_public();
        let epoch = Epoch::generate(Recipients::new());
        let id = epoch.id();
        fs::create_dir_all(root.path().join(DIR).join(DEFAULT)).unwrap();
        fs::write(root.path().join(pointer_path(DEFAULT)), format!("{id}\r\n")).unwrap();
        assert!(matches!(
            read_pointer(root.path(), DEFAULT),
            Err(Error::EpochInvalid(_))
        ));

        epoch::write(root.path(), &epoch, &[&alice]).unwrap();
        assert_eq!(read_pointer(root.path(), DEFAULT).unwrap().to_string(), id);

        fs::write(root.path().join(pointer_path(DEFAULT)), "garbage\n").unwrap();
        assert!(matches!(
            read_pointer(root.path(), DEFAULT),
            Err(Error::EpochInvalid(_))
        ));
    }

    #[test]
    fn write_pointer_round_trips() {
        let root = tempfile::tempdir().unwrap();
        let alice = x25519::Identity::generate().to_public();
        let epoch = Epoch::generate(Recipients::new());
        epoch::write(root.path(), &epoch, &[&alice]).unwrap();
        write_pointer(root.path(), "prod", &epoch.id()).unwrap();
        assert_eq!(
            read_pointer(root.path(), "prod").unwrap().to_string(),
            epoch.id()
        );
    }
}
