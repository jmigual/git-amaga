//! Secret file header, payload encoding, age encryption/decryption, and the pure exposure and
//! plaintext-state rules (plan sections 5.2, 6.1, 6.2).

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::Error;

/// User name -> set of key strings (`age1…` or `pgp:<FPR>`), plan 5.1.
pub type Recipients = BTreeMap<String, BTreeSet<String>>;

/// SHA-256 digest, used for base-hash comparisons (plan 6.2).
pub type Hash = [u8; 32];

/// Returns the SHA-256 digest of `data`.
pub fn hash(data: &[u8]) -> Hash {
    Sha256::digest(data).into()
}

/// The JSON header stored as the first line of a decrypted secret payload (plan 5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub v: u8,
    pub recipients: Recipients,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub exposed_to: Recipients,
}

/// Serializes `header` as one compact JSON line followed by `body` (plan 5.2).
pub fn encode_payload(header: &Header, body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut payload = serde_json::to_vec(header)?;
    payload.push(b'\n');
    payload.extend_from_slice(body);
    Ok(payload)
}

/// Only the version, for the lenient pre-check in [`decode_payload`]: an unrecognized `v`
/// must report `UnsupportedVersion`, even if a future header version adds fields this binary
/// does not know (which the strict, `deny_unknown_fields` [`Header`] parse would otherwise
/// reject first).
#[derive(Deserialize)]
struct VersionProbe {
    v: u8,
}

/// Splits a decrypted payload into its header and body (plan 5.2 parse rules).
pub fn decode_payload(payload: &[u8]) -> Result<(Header, Vec<u8>), Error> {
    let newline = payload
        .iter()
        .position(|&b| b == b'\n')
        .ok_or(Error::HeaderMissingNewline)?;
    let header_bytes = &payload[..newline];
    let probe: VersionProbe = serde_json::from_slice(header_bytes)?;
    if probe.v != 1 {
        return Err(Error::UnsupportedVersion(probe.v));
    }
    let header: Header = serde_json::from_slice(header_bytes)?;
    Ok((header, payload[newline + 1..].to_vec()))
}

/// Encrypts `header` and `body` as a standard age file to every given recipient.
pub fn encrypt(
    header: &Header,
    body: &[u8],
    recipients: &[&dyn age::Recipient],
) -> Result<Vec<u8>, Error> {
    let payload = encode_payload(header, body)?;
    let encryptor = age::Encryptor::with_recipients(recipients.iter().copied())?;
    let mut ciphertext = Vec::new();
    let mut writer = encryptor.wrap_output(&mut ciphertext)?;
    writer.write_all(&payload)?;
    writer.finish()?;
    Ok(ciphertext)
}

/// Decrypts an age file written by [`encrypt`] with any of the given identities.
pub fn decrypt(
    ciphertext: &[u8],
    identities: &[&dyn age::Identity],
) -> Result<(Header, Vec<u8>), Error> {
    let decryptor = age::Decryptor::new_buffered(ciphertext)?;
    let mut reader = decryptor.decrypt(identities.iter().copied())?;
    let mut payload = Vec::new();
    reader.read_to_end(&mut payload)?;
    decode_payload(&payload)
}

/// The exposure rule (plan 6.1): every ciphertext write goes through this function.
pub fn next_header(old: Option<&Header>, plaintext_changed: bool, current: &Recipients) -> Header {
    let exposed_to = match old {
        None => Recipients::new(),
        Some(_) if plaintext_changed => Recipients::new(),
        Some(old) => {
            let current_keys: BTreeSet<&String> = current.values().flatten().collect();
            let mut exposed_to = old.exposed_to.clone();
            for (user, keys) in &old.recipients {
                let stale: BTreeSet<String> = keys
                    .iter()
                    .filter(|key| !current_keys.contains(key))
                    .cloned()
                    .collect();
                if !stale.is_empty() {
                    exposed_to.entry(user.clone()).or_default().extend(stale);
                }
            }
            exposed_to
        }
    };
    Header {
        v: 1,
        recipients: current.clone(),
        exposed_to,
    }
}

/// The local plaintext's state relative to the decrypted ciphertext body and the recorded base
/// hash (plan 6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaintextState {
    Closed,
    InSync,
    Modified,
    Outdated,
    Conflict,
}

/// Classifies the local plaintext `p` against the decrypted ciphertext body `c` and the base
/// hash `b` recorded at the last sync (plan 6.2).
pub fn plaintext_state(p: Option<&[u8]>, c: &[u8], b: Option<Hash>) -> PlaintextState {
    let Some(p) = p else {
        return PlaintextState::Closed;
    };
    if p == c {
        return PlaintextState::InSync;
    }
    if b == Some(hash(c)) {
        return PlaintextState::Modified;
    }
    if b == Some(hash(p)) {
        return PlaintextState::Outdated;
    }
    PlaintextState::Conflict
}

/// Per-worktree base hashes (plan 5.5): repo-relative plaintext path -> SHA-256 of the body it
/// was last synchronised with.
pub type BaseMap = BTreeMap<String, Hash>;

fn hash_to_hex(h: &Hash) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

fn hash_from_hex(s: &str) -> Option<Hash> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Loads the base file (plan 5.5). A missing file is empty, and an unparseable line is skipped:
/// a lost entry only degrades that path to the safe `Conflict` state.
pub fn load_base(path: &Path) -> Result<BaseMap, Error> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BaseMap::new()),
        Err(source) => {
            return Err(Error::IoPath {
                path: path.display().to_string(),
                source,
            });
        }
    };
    let mut base = BaseMap::new();
    for line in contents.lines() {
        if let Some((hex, repo_path)) = line.split_once(' ')
            && let Some(hash) = hash_from_hex(hex)
        {
            base.insert(repo_path.to_string(), hash);
        }
    }
    Ok(base)
}

/// Rewrites the base file atomically, mode 0600: unsalted plaintext hashes must not be readable
/// by other local users.
pub fn save_base(path: &Path, base: &BaseMap) -> Result<(), Error> {
    let mut contents = String::new();
    for (repo_path, hash) in base {
        contents.push_str(&hash_to_hex(hash));
        contents.push(' ');
        contents.push_str(repo_path);
        contents.push('\n');
    }
    crate::paths::atomic_write(path, contents.as_bytes(), Some(0o600)).map_err(|source| {
        Error::IoPath {
            path: path.display().to_string(),
            source,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipients(pairs: &[(&str, &[&str])]) -> Recipients {
        pairs
            .iter()
            .map(|(user, keys)| {
                (
                    (*user).to_string(),
                    keys.iter().map(|k| k.to_string()).collect(),
                )
            })
            .collect()
    }

    // --- Header parsing ---

    #[test]
    fn decode_payload_rejects_missing_newline() {
        let payload = br#"{"v":1,"recipients":{}}"#;
        assert!(matches!(
            decode_payload(payload),
            Err(Error::HeaderMissingNewline)
        ));
    }

    #[test]
    fn decode_payload_rejects_unknown_fields() {
        let payload = b"{\"v\":1,\"recipients\":{},\"bogus\":true}\nbody";
        assert!(matches!(decode_payload(payload), Err(Error::HeaderJson(_))));
    }

    #[test]
    fn decode_payload_rejects_unsupported_version() {
        let payload = b"{\"v\":2,\"recipients\":{}}\nbody";
        assert!(matches!(
            decode_payload(payload),
            Err(Error::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn decode_payload_reports_unsupported_version_before_unknown_fields() {
        // A future v2 header may add fields this binary does not know. The version check must
        // win over `deny_unknown_fields`, or every v2 header looks like a parse error instead
        // of the actionable "unsupported version" error.
        let payload = b"{\"v\":2,\"recipients\":{},\"x\":1}\nbody";
        assert!(matches!(
            decode_payload(payload),
            Err(Error::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn encode_decode_payload_round_trip() {
        let header = Header {
            v: 1,
            recipients: recipients(&[("alice", &["age1alice"])]),
            exposed_to: Recipients::new(),
        };
        let body = b"arbitrary\x00binary\r\n";
        let payload = encode_payload(&header, body).unwrap();
        let (decoded_header, decoded_body) = decode_payload(&payload).unwrap();
        assert_eq!(decoded_header, header);
        assert_eq!(decoded_body, body);
    }

    // --- next_header (plan 6.1) ---

    #[test]
    fn next_header_new_secret_has_no_exposure() {
        let current = recipients(&[("alice", &["age1alice"])]);
        let header = next_header(None, false, &current);
        assert_eq!(header.recipients, current);
        assert!(header.exposed_to.is_empty());
    }

    #[test]
    fn next_header_user_remove_flags_secret() {
        let old = Header {
            v: 1,
            recipients: recipients(&[("alice", &["age1alice"]), ("bob", &["age1bob"])]),
            exposed_to: Recipients::new(),
        };
        let current = recipients(&[("alice", &["age1alice"])]);
        let header = next_header(Some(&old), false, &current);
        assert_eq!(header.exposed_to, recipients(&[("bob", &["age1bob"])]));
    }

    #[test]
    fn next_header_rotate_or_user_add_changes_nothing() {
        let old = Header {
            v: 1,
            recipients: recipients(&[("alice", &["age1alice"])]),
            exposed_to: Recipients::new(),
        };
        let current = recipients(&[("alice", &["age1alice"]), ("bob", &["age1bob"])]);
        let header = next_header(Some(&old), false, &current);
        assert!(header.exposed_to.is_empty());
    }

    #[test]
    fn next_header_plaintext_change_clears_exposure() {
        let old = Header {
            v: 1,
            recipients: recipients(&[("alice", &["age1alice"]), ("bob", &["age1bob"])]),
            exposed_to: recipients(&[("charlie", &["age1charlie"])]),
        };
        let current = recipients(&[("alice", &["age1alice"])]);
        let header = next_header(Some(&old), true, &current);
        assert!(header.exposed_to.is_empty());
    }

    #[test]
    fn next_header_readded_user_stays_exposed_until_content_changes() {
        // charlie was removed (flagged), then re-added: exposure is carried forward because
        // only a plaintext change clears it (decision 5).
        let old = Header {
            v: 1,
            recipients: recipients(&[("alice", &["age1alice"])]),
            exposed_to: recipients(&[("charlie", &["age1charlie"])]),
        };
        let current = recipients(&[("alice", &["age1alice"]), ("charlie", &["age1charlie"])]);
        let header = next_header(Some(&old), false, &current);
        assert_eq!(
            header.exposed_to,
            recipients(&[("charlie", &["age1charlie"])])
        );
    }

    #[test]
    fn next_header_rename_with_same_key_is_not_flagged() {
        // The same key now sits under a new user name: keys are compared, not names, so it is
        // not stale.
        let old = Header {
            v: 1,
            recipients: recipients(&[("alice", &["age1shared"])]),
            exposed_to: Recipients::new(),
        };
        let current = recipients(&[("alice2", &["age1shared"])]);
        let header = next_header(Some(&old), false, &current);
        assert!(header.exposed_to.is_empty());
    }

    // --- plaintext_state (plan 6.2) ---

    #[test]
    fn plaintext_state_absent_is_closed() {
        assert_eq!(plaintext_state(None, b"body", None), PlaintextState::Closed);
    }

    #[test]
    fn plaintext_state_equal_is_in_sync() {
        assert_eq!(
            plaintext_state(Some(b"body"), b"body", None),
            PlaintextState::InSync
        );
    }

    #[test]
    fn plaintext_state_base_matches_ciphertext_is_modified() {
        let c = b"repo body";
        assert_eq!(
            plaintext_state(Some(b"local edit"), c, Some(hash(c))),
            PlaintextState::Modified
        );
    }

    #[test]
    fn plaintext_state_base_matches_plaintext_is_outdated() {
        let p = b"old local copy";
        assert_eq!(
            plaintext_state(Some(p), b"new repo body", Some(hash(p))),
            PlaintextState::Outdated
        );
    }

    #[test]
    fn plaintext_state_base_unknown_is_conflict() {
        assert_eq!(
            plaintext_state(Some(b"local"), b"repo", None),
            PlaintextState::Conflict
        );
    }

    #[test]
    fn plaintext_state_base_matches_neither_is_conflict() {
        assert_eq!(
            plaintext_state(Some(b"local"), b"repo", Some(hash(b"something else"))),
            PlaintextState::Conflict
        );
    }

    // --- age encrypt/decrypt round trip ---

    #[test]
    fn two_recipient_round_trip_and_third_identity_fails() {
        let alice = age::x25519::Identity::generate();
        let bob = age::x25519::Identity::generate();
        let mallory = age::x25519::Identity::generate();

        let header = Header {
            v: 1,
            recipients: recipients(&[("alice", &["a"]), ("bob", &["b"])]),
            exposed_to: Recipients::new(),
        };
        let body = b"super secret";
        let alice_pub = alice.to_public();
        let bob_pub = bob.to_public();
        let recipients: Vec<&dyn age::Recipient> = vec![&alice_pub, &bob_pub];
        let ciphertext = encrypt(&header, body, &recipients).unwrap();

        for identity in [&alice, &bob] {
            let (decoded_header, decoded_body) =
                decrypt(&ciphertext, &[identity as &dyn age::Identity]).unwrap();
            assert_eq!(decoded_header, header);
            assert_eq!(decoded_body, body);
        }

        let err = decrypt(&ciphertext, &[&mallory as &dyn age::Identity]).unwrap_err();
        assert!(matches!(
            err,
            Error::Decrypt(age::DecryptError::NoMatchingKeys)
        ));
    }

    // --- base file (plan 5.5) ---

    #[test]
    fn load_base_treats_missing_file_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let base = load_base(&dir.path().join("amaga-base")).unwrap();
        assert!(base.is_empty());
    }

    #[test]
    fn base_round_trips_through_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("amaga-base");
        let mut base = BaseMap::new();
        base.insert("secrets/prod.env".to_string(), hash(b"prod"));
        base.insert("secrets/dev.env".to_string(), hash(b"dev"));

        save_base(&path, &base).unwrap();
        let loaded = load_base(&path).unwrap();
        assert_eq!(loaded, base);
    }

    #[cfg(unix)]
    #[test]
    fn save_base_is_not_readable_by_others() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("amaga-base");

        save_base(&path, &BaseMap::new()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn load_base_skips_unparseable_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("amaga-base");
        std::fs::write(
            &path,
            format!(
                "not-hex secrets/a.env\n{} secrets/b.env\n",
                hash_to_hex(&hash(b"b"))
            ),
        )
        .unwrap();

        let loaded = load_base(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded["secrets/b.env"], hash(b"b"));
    }
}
