//! Secret file header, payload encoding, age encryption/decryption, and the pure exposure and
//! plaintext-state rules (plan sections 5.2, 6.1, 6.2).

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{Read, Write};
use std::path::Path;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::users;

/// User name -> set of key strings (`age1…` or `pgp:<FPR>`), plan 5.1.
pub type Recipients = BTreeMap<String, BTreeSet<String>>;

/// SHA-256 digest, used for base-hash comparisons (plan 6.2).
pub type Hash = [u8; 32];

pub fn hash(data: &[u8]) -> Hash {
    Sha256::digest(data).into()
}

/// The format version of secret and epoch headers (plan 5.2, 5.6).
pub const VERSION: u8 = 2;

/// The JSON header stored as the first line of a decrypted secret payload (plan 5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub v: u8,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub exposed_to: Recipients,
}

/// Serializes `header` as one compact JSON line followed by `body` (plan 5.2).
pub fn encode_payload<H: Serialize>(header: &H, body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut payload = serde_json::to_vec(header)?;
    payload.push(b'\n');
    payload.extend_from_slice(body);
    Ok(payload)
}

// Lenient version-only pre-check: an unknown `v` must report `UnsupportedVersion` even when a
// future header has fields the strict [`Header`] parse rejects.
#[derive(Deserialize)]
struct VersionProbe {
    v: u8,
}

/// Splits a decrypted payload into its header and body (plan 5.2 parse rules).
pub fn decode_payload<H: DeserializeOwned>(payload: &[u8]) -> Result<(H, Vec<u8>), Error> {
    let newline = payload
        .iter()
        .position(|&b| b == b'\n')
        .ok_or(Error::HeaderMissingNewline)?;
    let header_bytes = &payload[..newline];
    let probe: VersionProbe = serde_json::from_slice(header_bytes)?;
    if probe.v != VERSION {
        return Err(Error::UnsupportedVersion(probe.v));
    }
    let header: H = serde_json::from_slice(header_bytes)?;
    Ok((header, payload[newline + 1..].to_vec()))
}

pub fn encrypt<H: Serialize>(
    header: &H,
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

pub fn decrypt<H: DeserializeOwned>(
    ciphertext: &[u8],
    identities: &[&dyn age::Identity],
) -> Result<(H, Vec<u8>), Error> {
    let decryptor = age::Decryptor::new_buffered(ciphertext)?;
    let mut reader = decryptor.decrypt(identities.iter().copied())?;
    let mut payload = Vec::new();
    reader.read_to_end(&mut payload)?;
    decode_payload(&payload)
}

const LABEL_TAG: &str = "amaga-partition";

/// The partition label stanza of a secret (plan 5.2, ADR-0017): an age recipient that adds
/// `-> amaga-partition <p>` with an empty body and wraps nothing.
pub struct Label(String);

impl Label {
    /// [`Error::PartitionLabelInvalid`] unless `partition` follows the name rule (plan 5.1).
    pub fn new(partition: &str) -> Result<Self, Error> {
        match users::valid_name(partition) {
            true => Ok(Self(partition.to_string())),
            false => Err(Error::PartitionLabelInvalid(partition.to_string())),
        }
    }
}

impl age::Recipient for Label {
    fn wrap_file_key(
        &self,
        _file_key: &age_core::format::FileKey,
    ) -> Result<(Vec<age_core::format::Stanza>, HashSet<String>), age::EncryptError> {
        let stanza = age_core::format::Stanza {
            tag: LABEL_TAG.to_string(),
            args: vec![self.0.clone()],
            body: Vec::new(),
        };
        Ok((vec![stanza], HashSet::new()))
    }
}

/// The partition label of the age file `ciphertext`, read without any key (plan 5.2).
/// [`Error::PartitionLabelInvalid`] (naming `path`) unless there is exactly one valid label.
pub fn label_of(path: &str, ciphertext: &[u8]) -> Result<String, Error> {
    let invalid = || Error::PartitionLabelInvalid(path.to_string());
    let mut lines = ciphertext.split(|&b| b == b'\n');
    if lines.next() != Some(b"age-encryption.org/v1") {
        return Err(invalid());
    }
    let mut labels = Vec::new();
    let mut terminated = false;
    for line in lines {
        if line.starts_with(b"---") {
            terminated = true;
            break;
        }
        if let Some(stanza) = line.strip_prefix(b"-> ") {
            let mut args = stanza.split(|&b| b == b' ');
            if args.next() == Some(LABEL_TAG.as_bytes()) {
                labels.push(args.collect::<Vec<_>>());
            }
        }
    }
    match labels.as_slice() {
        [args] if terminated && args.len() == 1 => std::str::from_utf8(args[0])
            .ok()
            .filter(|name| users::valid_name(name))
            .map(str::to_string)
            .ok_or_else(invalid),
        _ => Err(invalid()),
    }
}

/// The exposure rule (plan 6.1): every ciphertext write goes through this function. `old` pairs
/// the file's header with the `members` of the epoch that decrypted it; `new_members` are those of
/// the epoch it is written to.
pub fn next_header(
    old: Option<(&Header, &Recipients)>,
    plaintext_changed: bool,
    new_members: &Recipients,
) -> Header {
    let exposed_to = match old {
        None => Recipients::new(),
        Some(_) if plaintext_changed => Recipients::new(),
        Some((old, old_members)) => {
            let new_keys: BTreeSet<&String> = new_members.values().flatten().collect();
            let mut exposed_to = old.exposed_to.clone();
            for (user, keys) in old_members {
                let lost: BTreeSet<String> = keys
                    .iter()
                    .filter(|key| !new_keys.contains(key))
                    .cloned()
                    .collect();
                if !lost.is_empty() {
                    exposed_to.entry(user.clone()).or_default().extend(lost);
                }
            }
            exposed_to
        }
    };
    Header {
        v: VERSION,
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

/// `p` is the local plaintext, `c` the decrypted ciphertext body, `b` the base hash (plan 6.2).
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

/// Per-worktree base hashes (plan 5.5): plaintext path -> SHA-256 of the body last synced.
pub type BaseMap = BTreeMap<String, Hash>;

fn hash_to_hex(h: &Hash) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

fn hash_from_hex(s: &str) -> Option<Hash> {
    if s.len() != 64 || !s.is_ascii() {
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
    let contents = match std::fs::read(path) {
        Ok(c) => String::from_utf8_lossy(&c).into_owned(),
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
        let payload = br#"{"v":2}"#;
        assert!(matches!(
            decode_payload::<Header>(payload),
            Err(Error::HeaderMissingNewline)
        ));
    }

    #[test]
    fn decode_payload_rejects_unknown_fields() {
        // Including 0.1.0's `recipients`.
        for payload in [
            &b"{\"v\":2,\"bogus\":true}\nbody"[..],
            &b"{\"v\":2,\"recipients\":{}}\nbody"[..],
        ] {
            assert!(matches!(
                decode_payload::<Header>(payload),
                Err(Error::HeaderJson(_))
            ));
        }
    }

    #[test]
    fn decode_payload_rejects_a_0_1_0_header() {
        let payload = b"{\"v\":1,\"recipients\":{}}\nbody";
        assert!(matches!(
            decode_payload::<Header>(payload),
            Err(Error::UnsupportedVersion(1))
        ));
    }

    #[test]
    fn decode_payload_reports_unsupported_version_before_unknown_fields() {
        // The version check must win over `deny_unknown_fields` (see `VersionProbe`).
        let payload = b"{\"v\":3,\"x\":1}\nbody";
        assert!(matches!(
            decode_payload::<Header>(payload),
            Err(Error::UnsupportedVersion(3))
        ));
    }

    #[test]
    fn a_new_secret_header_is_just_the_version() {
        let header = next_header(None, false, &Recipients::new());
        let payload = encode_payload(&header, b"").unwrap();
        assert_eq!(payload, b"{\"v\":2}\n");
    }

    #[test]
    fn encode_decode_payload_round_trip() {
        let header = Header {
            v: VERSION,
            exposed_to: recipients(&[("charlie", &["age1charlie"])]),
        };
        let body = b"arbitrary\x00binary\r\n";
        let payload = encode_payload(&header, body).unwrap();
        let (decoded_header, decoded_body) = decode_payload::<Header>(&payload).unwrap();
        assert_eq!(decoded_header, header);
        assert_eq!(decoded_body, body);
    }

    // --- next_header (plan 6.1) ---

    fn header_with(exposed_to: Recipients) -> Header {
        Header {
            v: VERSION,
            exposed_to,
        }
    }

    #[test]
    fn next_header_new_secret_has_no_exposure() {
        let current = recipients(&[("alice", &["age1alice"])]);
        assert!(next_header(None, false, &current).exposed_to.is_empty());
    }

    #[test]
    fn next_header_user_remove_flags_secret() {
        let old_members = recipients(&[("alice", &["age1alice"]), ("bob", &["age1bob"])]);
        let new_members = recipients(&[("alice", &["age1alice"])]);
        let old = header_with(Recipients::new());
        let got = next_header(Some((&old, &old_members)), false, &new_members);
        assert_eq!(got.exposed_to, recipients(&[("bob", &["age1bob"])]));
    }

    #[test]
    fn next_header_rotate_or_user_add_changes_nothing() {
        let old_members = recipients(&[("alice", &["age1alice"])]);
        let new_members = recipients(&[("alice", &["age1alice"]), ("bob", &["age1bob"])]);
        let old = header_with(Recipients::new());
        let got = next_header(Some((&old, &old_members)), false, &new_members);
        assert!(got.exposed_to.is_empty());
    }

    #[test]
    fn next_header_rewrite_under_the_same_epoch_adds_nothing() {
        let members = recipients(&[("alice", &["age1alice"]), ("bob", &["age1bob"])]);
        let old = header_with(recipients(&[("charlie", &["age1charlie"])]));
        let got = next_header(Some((&old, &members)), false, &members);
        assert_eq!(got, old);
    }

    #[test]
    fn next_header_plaintext_change_clears_exposure() {
        let old_members = recipients(&[("alice", &["age1alice"]), ("bob", &["age1bob"])]);
        let new_members = recipients(&[("alice", &["age1alice"])]);
        let old = header_with(recipients(&[("charlie", &["age1charlie"])]));
        let got = next_header(Some((&old, &old_members)), true, &new_members);
        assert!(got.exposed_to.is_empty());
    }

    #[test]
    fn next_header_readded_user_stays_exposed_until_content_changes() {
        // charlie was removed (flagged), then re-added: exposure is carried forward because
        // only a plaintext change clears it (decision 5).
        let old_members = recipients(&[("alice", &["age1alice"])]);
        let new_members = recipients(&[("alice", &["age1alice"]), ("charlie", &["age1charlie"])]);
        let old = header_with(recipients(&[("charlie", &["age1charlie"])]));
        let got = next_header(Some((&old, &old_members)), false, &new_members);
        assert_eq!(got.exposed_to, old.exposed_to);
    }

    #[test]
    fn next_header_rename_with_same_key_is_not_flagged() {
        // The same key now sits under a new user name: keys are compared, not names, so it is
        // not stale.
        let old_members = recipients(&[("alice", &["age1shared"])]);
        let new_members = recipients(&[("alice2", &["age1shared"])]);
        let old = header_with(Recipients::new());
        let got = next_header(Some((&old, &old_members)), false, &new_members);
        assert!(got.exposed_to.is_empty());
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

        let header = header_with(recipients(&[("charlie", &["age1charlie"])]));
        let body = b"super secret";
        let alice_pub = alice.to_public();
        let bob_pub = bob.to_public();
        let recipients: Vec<&dyn age::Recipient> = vec![&alice_pub, &bob_pub];
        let ciphertext = encrypt(&header, body, &recipients).unwrap();

        for identity in [&alice, &bob] {
            let (decoded_header, decoded_body) =
                decrypt::<Header>(&ciphertext, &[identity as &dyn age::Identity]).unwrap();
            assert_eq!(decoded_header, header);
            assert_eq!(decoded_body, body);
        }

        let err = decrypt::<Header>(&ciphertext, &[&mallory as &dyn age::Identity]).unwrap_err();
        assert!(matches!(
            err,
            Error::Decrypt(age::DecryptError::NoMatchingKeys)
        ));
    }

    // --- partition label (plan 5.2) ---

    fn encrypt_labelled(labels: &[&str]) -> (Vec<u8>, age::x25519::Identity) {
        let epoch = age::x25519::Identity::generate();
        let epoch_pub = epoch.to_public();
        let labels: Vec<Label> = labels.iter().map(|l| Label::new(l).unwrap()).collect();
        let mut recipients: Vec<&dyn age::Recipient> = vec![&epoch_pub];
        recipients.extend(labels.iter().map(|l| l as &dyn age::Recipient));
        let ciphertext = encrypt(&header_with(Recipients::new()), b"body", &recipients).unwrap();
        (ciphertext, epoch)
    }

    #[test]
    fn label_is_readable_without_a_key_and_the_epoch_alone_decrypts() {
        let (ciphertext, epoch) = encrypt_labelled(&["production"]);
        assert_eq!(label_of("p.env.amaga", &ciphertext).unwrap(), "production");
        let (_, body) = decrypt::<Header>(&ciphertext, &[&epoch as &dyn age::Identity]).unwrap();
        assert_eq!(body, b"body");
    }

    #[test]
    fn label_of_rejects_zero_two_and_non_age_input() {
        let (none, _) = encrypt_labelled(&[]);
        let (two, _) = encrypt_labelled(&["a", "b"]);
        // A forged label outside the name rule: `Label::new` would refuse to write it.
        let (mut forged, _) = encrypt_labelled(&["prod"]);
        let at = forged.windows(4).position(|w| w == b"prod").unwrap();
        forged[at] = b'P';
        for input in [
            &none[..],
            &two[..],
            &forged[..],
            b"not an age file".as_slice(),
        ] {
            assert!(matches!(
                label_of("p.env.amaga", input),
                Err(Error::PartitionLabelInvalid(_))
            ));
        }
    }

    #[test]
    fn label_outside_the_name_rule_is_rejected() {
        for name in ["", "Prod", "a b", "-a"] {
            assert!(matches!(
                Label::new(name),
                Err(Error::PartitionLabelInvalid(_))
            ));
        }
    }

    #[test]
    fn a_changed_label_fails_authentication() {
        let (mut ciphertext, epoch) = encrypt_labelled(&["production"]);
        let at = ciphertext
            .windows(10)
            .position(|w| w == b"production")
            .unwrap();
        ciphertext[at + 9] = b'x';
        assert_eq!(label_of("p.env.amaga", &ciphertext).unwrap(), "productiox");
        assert!(matches!(
            decrypt::<Header>(&ciphertext, &[&epoch as &dyn age::Identity]),
            Err(Error::Decrypt(age::DecryptError::InvalidMac))
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

    #[test]
    fn load_base_skips_non_ascii_and_non_utf8_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("amaga-base");
        // 64 bytes, but the 2-byte slices of the old parser split a character.
        let non_ascii = format!("a{}a", "\u{e9}".repeat(31));
        let mut contents = format!("{non_ascii} secrets/a.env\n").into_bytes();
        contents.extend_from_slice(b"\xff\xfe secrets/b.env\n");
        contents
            .extend_from_slice(format!("{} secrets/c.env\n", hash_to_hex(&hash(b"c"))).as_bytes());
        std::fs::write(&path, contents).unwrap();

        let loaded = load_base(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded["secrets/c.env"], hash(b"c"));
    }
}
