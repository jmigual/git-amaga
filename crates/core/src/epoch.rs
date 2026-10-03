//! Epoch files and the `current-epoch` pointer (plan 5.6, ADR-0015).

use std::fs;
use std::path::Path;
use std::str::FromStr;

use age::secrecy::ExposeSecret;
use age::x25519;
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::paths;
use crate::secret::{self, Recipients};

const POINTER: &str = ".amaga/current-epoch";
const DIR: &str = ".amaga/epochs";

/// The JSON line of an epoch payload: the member keys the epoch is wrapped to.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    v: u8,
    members: Recipients,
}

/// An epoch key pair and the member key set its file is wrapped to (plan 5.6).
pub struct Epoch {
    /// The member keys the epoch file is wrapped to; the exposure record (plan 6.1).
    pub members: Recipients,
    identity: x25519::Identity,
}

impl Epoch {
    /// A fresh epoch wrapped to `members`.
    pub fn generate(members: Recipients) -> Self {
        Self {
            members,
            identity: x25519::Identity::generate(),
        }
    }

    /// The same key, to be wrapped to another member set (`user add`, plan 7).
    pub fn with_members(&self, members: Recipients) -> Self {
        Self {
            members,
            identity: self.identity.clone(),
        }
    }

    /// The public key string, which names the epoch file.
    pub fn id(&self) -> String {
        self.identity.to_public().to_string()
    }

    /// The recipient every secret of this epoch is encrypted to.
    pub fn recipient(&self) -> x25519::Recipient {
        self.identity.to_public()
    }

    /// The identity that decrypts the secrets of this epoch.
    pub fn identity(&self) -> &x25519::Identity {
        &self.identity
    }
}

/// The repo-relative path of the epoch file `id`.
pub fn file_path(id: &str) -> String {
    format!("{DIR}/{id}.age")
}

/// The epoch file's bytes: the epoch's secret key, age-encrypted to `recipients`.
pub fn wrap(epoch: &Epoch, recipients: &[&dyn age::Recipient]) -> Result<Vec<u8>, Error> {
    let header = Header {
        v: secret::VERSION,
        members: epoch.members.clone(),
    };
    let key = format!("{}\n", epoch.identity.to_string().expose_secret());
    secret::encrypt(&header, key.as_bytes(), recipients)
}

/// Writes the epoch file atomically, creating `.amaga/epochs/` if needed.
pub fn write(root: &Path, epoch: &Epoch, recipients: &[&dyn age::Recipient]) -> Result<(), Error> {
    let path = file_path(&epoch.id());
    let full = root.join(&path);
    let bytes = wrap(epoch, recipients)?;
    let result = full
        .parent()
        .map_or(Ok(()), fs::create_dir_all)
        .and_then(|()| paths::atomic_write(&full, &bytes, None));
    result.map_err(|source| Error::IoPath { path, source })
}

/// Decrypts an epoch file. The key in the payload must belong to `id`, the file's name.
pub fn unwrap(
    id: &str,
    ciphertext: &[u8],
    identities: &[&dyn age::Identity],
) -> Result<Epoch, Error> {
    let (header, body): (Header, _) = secret::decrypt(ciphertext, identities)?;
    let invalid = |why: &str| Error::EpochInvalid(format!("{}: {why}", file_path(id)));
    let body = String::from_utf8(body).map_err(|_| invalid("the key is not text"))?;
    let mut lines = body.lines();
    let (Some(line), None) = (lines.next(), lines.next()) else {
        return Err(invalid("expected exactly one key line"));
    };
    let identity =
        x25519::Identity::from_str(line).map_err(|_| invalid("not an age secret key"))?;
    if identity.to_public().to_string() != id {
        return Err(invalid("the key does not match the file name"));
    }
    Ok(Epoch {
        members: header.members,
        identity,
    })
}

/// The current epoch's public key from `.amaga/current-epoch`; the epoch file must exist.
pub fn read_pointer(root: &Path) -> Result<x25519::Recipient, Error> {
    let contents = match fs::read_to_string(root.join(POINTER)) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::NoEpoch),
        Err(source) => {
            return Err(Error::IoPath {
                path: POINTER.into(),
                source,
            });
        }
    };
    let recipient = x25519::Recipient::from_str(contents.trim())
        .map_err(|_| Error::EpochInvalid(format!("{POINTER}: not an age public key")))?;
    let path = file_path(&recipient.to_string());
    if !root.join(&path).is_file() {
        return Err(Error::EpochInvalid(format!(
            "{POINTER}: {path} does not exist"
        )));
    }
    Ok(recipient)
}

/// Points `.amaga/current-epoch` at `id`, atomically.
pub fn write_pointer(root: &Path, id: &str) -> Result<(), Error> {
    paths::atomic_write(&root.join(POINTER), format!("{id}\n").as_bytes(), None).map_err(|source| {
        Error::IoPath {
            path: POINTER.into(),
            source,
        }
    })
}

/// The ids of every epoch file, sorted; names that are not `<age1…>.age` are ignored.
pub fn list(root: &Path) -> Result<Vec<String>, Error> {
    let entries = match fs::read_dir(root.join(DIR)) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(Error::IoPath {
                path: DIR.into(),
                source,
            });
        }
    };
    let mut ids = Vec::new();
    for entry in entries {
        let name = entry?.file_name();
        if let Some(id) = name.to_str().and_then(|n| n.strip_suffix(".age"))
            && x25519::Recipient::from_str(id).is_ok_and(|key| key.to_string() == id)
        {
            ids.push(id.to_string());
        }
    }
    ids.sort();
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpg::{self, PgpRecipient};

    fn members(pairs: &[(&str, &x25519::Recipient)]) -> Recipients {
        pairs
            .iter()
            .map(|(name, key)| (name.to_string(), [key.to_string()].into()))
            .collect()
    }

    // An epoch payload with the given body, wrapped to `to`, as `unwrap` would read it.
    fn payload_to(to: &x25519::Recipient, body: &str) -> Vec<u8> {
        let header = Header {
            v: secret::VERSION,
            members: Recipients::new(),
        };
        secret::encrypt(&header, body.as_bytes(), &[to as &dyn age::Recipient]).unwrap()
    }

    #[test]
    fn two_members_unwrap_with_their_own_identity() {
        let (alice, bob) = (x25519::Identity::generate(), x25519::Identity::generate());
        let (alice_pub, bob_pub) = (alice.to_public(), bob.to_public());
        let epoch = Epoch::generate(members(&[("alice", &alice_pub), ("bob", &bob_pub)]));
        let bytes = wrap(&epoch, &[&alice_pub, &bob_pub]).unwrap();

        for identity in [&alice, &bob] {
            let got = unwrap(&epoch.id(), &bytes, &[identity as &dyn age::Identity]).unwrap();
            assert_eq!(got.members, epoch.members);
            assert_eq!(got.id(), epoch.id());
        }
    }

    #[test]
    fn a_third_identity_cannot_unwrap() {
        let alice = x25519::Identity::generate();
        let epoch = Epoch::generate(Recipients::new());
        let bytes = wrap(&epoch, &[&alice.to_public()]).unwrap();
        let mallory = x25519::Identity::generate();
        let err = unwrap(&epoch.id(), &bytes, &[&mallory as &dyn age::Identity])
            .err()
            .unwrap();
        assert!(matches!(
            err,
            Error::Decrypt(age::DecryptError::NoMatchingKeys)
        ));
    }

    #[test]
    fn a_key_that_does_not_match_the_file_name_is_invalid() {
        let alice = x25519::Identity::generate();
        let other = x25519::Identity::generate();
        let key = other.to_string();
        let bytes = payload_to(&alice.to_public(), &format!("{}\n", key.expose_secret()));
        let id = Epoch::generate(Recipients::new()).id();
        let err = unwrap(&id, &bytes, &[&alice as &dyn age::Identity])
            .err()
            .unwrap();
        assert!(matches!(err, Error::EpochInvalid(_)));
    }

    #[test]
    fn zero_or_two_key_lines_are_invalid() {
        let alice = x25519::Identity::generate();
        let epoch = Epoch::generate(Recipients::new());
        let key = epoch.identity().to_string();
        let key = key.expose_secret();
        for body in ["".to_string(), format!("{key}\n{key}\n")] {
            let bytes = payload_to(&alice.to_public(), &body);
            let err = unwrap(&epoch.id(), &bytes, &[&alice as &dyn age::Identity])
                .err()
                .unwrap();
            assert!(matches!(err, Error::EpochInvalid(_)));
        }
    }

    #[test]
    fn the_pointer_is_read_with_crlf_and_must_name_an_existing_epoch() {
        let root = tempfile::tempdir().unwrap();
        assert!(matches!(read_pointer(root.path()), Err(Error::NoEpoch)));

        let alice = x25519::Identity::generate().to_public();
        let epoch = Epoch::generate(members(&[("alice", &alice)]));
        let id = epoch.id();
        fs::create_dir_all(root.path().join(".amaga")).unwrap();
        fs::write(root.path().join(POINTER), format!("{id}\r\n")).unwrap();
        assert!(matches!(
            read_pointer(root.path()),
            Err(Error::EpochInvalid(_))
        ));

        write(root.path(), &epoch, &[&alice]).unwrap();
        assert_eq!(read_pointer(root.path()).unwrap().to_string(), id);

        fs::write(root.path().join(POINTER), "garbage\n").unwrap();
        assert!(matches!(
            read_pointer(root.path()),
            Err(Error::EpochInvalid(_))
        ));
    }

    #[test]
    fn write_pointer_round_trips() {
        let root = tempfile::tempdir().unwrap();
        let alice = x25519::Identity::generate().to_public();
        let epoch = Epoch::generate(Recipients::new());
        write(root.path(), &epoch, &[&alice]).unwrap();
        write_pointer(root.path(), &epoch.id()).unwrap();
        assert_eq!(read_pointer(root.path()).unwrap().to_string(), epoch.id());
    }

    #[test]
    fn list_ignores_names_that_are_not_epoch_files() {
        let root = tempfile::tempdir().unwrap();
        assert!(list(root.path()).unwrap().is_empty());

        let alice = x25519::Identity::generate().to_public();
        let (first, second) = (
            Epoch::generate(Recipients::new()),
            Epoch::generate(Recipients::new()),
        );
        write(root.path(), &first, &[&alice]).unwrap();
        write(root.path(), &second, &[&alice]).unwrap();
        let dir = root.path().join(DIR);
        fs::write(dir.join(format!("{}.age.amaga-tmp", first.id())), "").unwrap();
        fs::write(dir.join("notes.age"), "").unwrap();
        fs::write(dir.join("README"), "").unwrap();

        let mut expected = vec![first.id(), second.id()];
        expected.sort();
        assert_eq!(list(root.path()).unwrap(), expected);
    }

    #[test]
    fn an_epoch_wrapped_to_x25519_and_pgp_unwraps_with_the_x25519_identity_alone() {
        let alice = x25519::Identity::generate();
        let asc = gpg::validate(include_str!("../tests/fixtures/valid_cv25519.asc")).unwrap();
        let pgp = PgpRecipient::new(&asc);
        let epoch = Epoch::generate(members(&[("alice", &alice.to_public())]));
        let bytes = wrap(&epoch, &[&alice.to_public(), &pgp]).unwrap();

        let got = unwrap(&epoch.id(), &bytes, &[&alice as &dyn age::Identity]).unwrap();
        assert_eq!(got.members, epoch.members);
    }
}
