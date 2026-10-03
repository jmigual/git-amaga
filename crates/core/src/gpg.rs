//! OpenPGP (`.asc`) key parsing, validation, encryption-subkey selection (plan 5.1), the `pgp`
//! age stanza (plan 5.2.1) and gpg subprocess decryption (plan 7.3).

use std::collections::HashSet;
use std::io::{self, Write};
use std::process::{Command, Stdio};

use age::secrecy::ExposeSecret;
use age_core::format::{FileKey, Stanza};
use pgp::composed::{Deserializable, MessageBuilder, SignedPublicKey, SignedPublicSubKey};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{Signature, SignatureType};
use pgp::types::{KeyDetails, Timestamp};
use thiserror::Error;

use crate::error::Error as CrateError;

const TAG: &str = "pgp";

/// A validated armored OpenPGP key with its chosen encryption subkey; `fpr` is that subkey's
/// uppercase-hex fingerprint (plan 5.1).
#[derive(Clone, Debug)]
pub struct AscKey {
    pub key: SignedPublicKey,
    pub fpr: String,
    pub subkey: SignedPublicSubKey,
}

impl AscKey {
    /// Every subkey fingerprint, so secrets written before a subkey change still match.
    pub fn subkey_fprs(&self) -> Vec<String> {
        self.key
            .public_subkeys
            .iter()
            .map(|sk| format!("{:X}", sk.key.fingerprint()))
            .collect()
    }

    /// Uppercase-hex primary key fingerprint, as gpg prints it.
    pub fn primary_fpr(&self) -> String {
        format!("{:X}", self.key.primary_key.fingerprint())
    }

    /// The first user ID in the key, or empty if it has none.
    pub fn first_user_id(&self) -> String {
        self.key
            .details
            .users
            .first()
            .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
            .unwrap_or_default()
    }
}

/// Does not check expiry; see [`check_not_expired`].
pub fn validate(armored: &str) -> Result<AscKey, CrateError> {
    reject_concatenated_armor(armored)?;

    let (mut keys, _headers) = SignedPublicKey::from_string_many(armored)
        .map_err(|e| CrateError::GpgKeyParse(e.to_string()))?;
    let first = keys
        .next()
        .ok_or_else(|| CrateError::GpgKeyParse("no OpenPGP key found".to_string()))?
        .map_err(|e| CrateError::GpgKeyParse(e.to_string()))?;
    if keys.next().is_some() {
        return Err(CrateError::GpgKeyMultiple);
    }
    let key = first;

    key.verify_bindings()
        .map_err(|e| CrateError::GpgKeyBindings(e.to_string()))?;

    let revoked = key
        .details
        .revocation_signatures
        .iter()
        .any(|s| s.typ() == Some(SignatureType::KeyRevocation));
    if revoked {
        return Err(CrateError::GpgKeyRevoked);
    }

    let subkey = select_encryption_subkey(&key).ok_or(CrateError::GpgKeyNoEncryptionSubkey)?;
    let fpr = format!("{:X}", subkey.key.fingerprint());
    Ok(AscKey { key, fpr, subkey })
}

// rPGP's dearmorer stops at the first END line, so trailing content (a second key block or garbage)
// would be silently ignored; reject it (plan 5.1).
fn reject_concatenated_armor(armored: &str) -> Result<(), CrateError> {
    if let Some(end_offset) = armored.find("-----END PGP") {
        let after_end_marker = &armored[end_offset..];
        let trailing = after_end_marker
            .find('\n')
            .map(|i| &after_end_marker[i + 1..])
            .unwrap_or("");
        if !trailing.trim().is_empty() {
            return Err(CrateError::GpgKeyParse(
                "armored input has trailing content after the key".to_string(),
            ));
        }
    }
    Ok(())
}

// Newest non-revoked encryption-capable subkey (plan 5.1); expiry is not considered.
fn select_encryption_subkey(key: &SignedPublicKey) -> Option<SignedPublicSubKey> {
    key.public_subkeys
        .iter()
        .filter(|sk| {
            let revoked = sk
                .signatures
                .iter()
                .any(|s| s.typ() == Some(SignatureType::SubkeyRevocation));
            if revoked {
                return false;
            }
            let Some(binding) = newest_binding(&sk.signatures) else {
                return false;
            };
            let flags = binding.key_flags();
            (flags.encrypt_comms() || flags.encrypt_storage()) && sk.key.algorithm().can_encrypt()
        })
        .max_by_key(|sk| sk.key.created_at().as_secs())
        .cloned()
}

fn newest_binding(signatures: &[Signature]) -> Option<&Signature> {
    signatures
        .iter()
        .filter(|s| s.typ() == Some(SignatureType::SubkeyBinding))
        .max_by_key(|s| s.created().map(|t| t.as_secs()).unwrap_or(0))
}

/// Add-time check (plan 7): neither the primary key nor the selected subkey may be expired.
pub fn check_not_expired(asc: &AscKey) -> Result<(), CrateError> {
    let now = Timestamp::now().as_secs();

    let newest_primary_sig = asc
        .key
        .details
        .users
        .iter()
        .flat_map(|u| u.signatures.iter())
        .chain(asc.key.details.direct_signatures.iter())
        .max_by_key(|s| s.created().map(|t| t.as_secs()).unwrap_or(0));
    if newest_primary_sig.is_some_and(|sig| is_expired(asc.key.primary_key.created_at(), sig, now))
    {
        return Err(CrateError::GpgKeyExpired);
    }

    if newest_binding(&asc.subkey.signatures)
        .is_some_and(|sig| is_expired(asc.subkey.key.created_at(), sig, now))
    {
        return Err(CrateError::GpgKeyExpired);
    }

    Ok(())
}

fn is_expired(created: Timestamp, sig: &Signature, now: u32) -> bool {
    match sig.key_expiration_time() {
        Some(d) if d.as_secs() > 0 => created.as_secs() as u64 + d.as_secs() as u64 <= now as u64,
        _ => false,
    }
}

/// Wraps a file key to an OpenPGP encryption subkey as a `pgp` stanza (plan 5.2.1).
pub struct PgpRecipient {
    fpr: String,
    subkey: SignedPublicSubKey,
}

impl PgpRecipient {
    pub fn new(asc: &AscKey) -> Self {
        Self {
            fpr: asc.fpr.clone(),
            subkey: asc.subkey.clone(),
        }
    }
}

impl age::Recipient for PgpRecipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        let mut rng = rand::thread_rng();
        let mut builder = MessageBuilder::from_bytes("", file_key.expose_secret().to_vec())
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        builder
            .encrypt_to_key(&mut rng, &self.subkey)
            .map_err(|e| age::EncryptError::Io(io::Error::other(e.to_string())))?;
        let body = builder
            .to_vec(&mut rng)
            .map_err(|e| age::EncryptError::Io(io::Error::other(e.to_string())))?;
        Ok((
            vec![Stanza {
                tag: TAG.to_string(),
                args: vec![self.fpr.clone()],
                body,
            }],
            HashSet::new(),
        ))
    }
}

/// gpg failed for `fpr`; carries gpg's stderr and a card/PIN hint (plan 7.3).
#[derive(Debug, Error)]
#[error(
    "gpg decryption failed for {fpr}: {stderr}\nis the card inserted, and can gpg-agent show a PIN prompt (`export GPG_TTY=$(tty)`)?"
)]
pub struct GpgError {
    pub fpr: String,
    pub stderr: String,
}

/// Unwraps `pgp` stanzas for any of `fprs` via `gpg --decrypt` (plan 5.2.1, 7.3); ignores other
/// stanzas.
pub struct GpgIdentity {
    fprs: Vec<String>,
    // Test-only GNUPGHOME override, set on the child only, never via `set_var` (plan 11).
    gnupghome: Option<std::path::PathBuf>,
}

impl GpgIdentity {
    pub fn new(fprs: Vec<String>) -> Self {
        Self {
            fprs,
            gnupghome: None,
        }
    }

    #[cfg(test)]
    fn with_gnupghome(fprs: Vec<String>, gnupghome: std::path::PathBuf) -> Self {
        Self {
            fprs,
            gnupghome: Some(gnupghome),
        }
    }
}

impl age::Identity for GpgIdentity {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        if stanza.tag != TAG || stanza.args.len() != 1 {
            return None;
        }
        let fpr = &stanza.args[0];
        if !self.fprs.contains(fpr) {
            return None;
        }
        Some(
            decrypt_with_gpg(fpr, &stanza.body, self.gnupghome.as_deref())
                .map_err(age::DecryptError::Io),
        )
    }

    // Tries every matching stanza, not just the first: first `Ok`, else first `Err` (ADR-0004).
    fn unwrap_stanzas(&self, stanzas: &[Stanza]) -> Option<Result<FileKey, age::DecryptError>> {
        let mut first_err = None;
        for stanza in stanzas {
            match self.unwrap_stanza(stanza) {
                Some(Ok(key)) => return Some(Ok(key)),
                Some(Err(e)) => {
                    first_err.get_or_insert(e);
                }
                None => {}
            }
        }
        first_err.map(Err)
    }
}

// Oversized stanza bodies are rejected before spawning gpg, to avoid a pipe deadlock (ADR-0004).
const MAX_STANZA_BODY_LEN: usize = 8 * 1024;

fn decrypt_with_gpg(
    fpr: &str,
    body: &[u8],
    gnupghome: Option<&std::path::Path>,
) -> io::Result<FileKey> {
    if body.len() > MAX_STANZA_BODY_LEN {
        // Not a GpgError: gpg never ran, so its card/PIN hint would be misleading.
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "pgp stanza body too large ({} bytes, max {MAX_STANZA_BODY_LEN})",
                body.len()
            ),
        ));
    }

    let gpg_error = |stderr: String| GpgError {
        fpr: fpr.to_string(),
        stderr,
    };
    let mut command = Command::new("gpg");
    command.args(["--quiet", "--max-output", "16", "--decrypt"]);
    if let Some(home) = gnupghome {
        command.env("GNUPGHOME", home);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let write_result = child.stdin.take().expect("stdin was piped").write_all(body);
    // Always wait for the child (and collect its stderr) even if the write failed, so a short
    // write doesn't leak the process and the error still carries gpg's own context.
    let output = child.wait_with_output()?;
    if let Err(e) = write_result {
        return Err(io::Error::other(gpg_error(format!(
            "{e} (gpg stderr: {})",
            String::from_utf8_lossy(&output.stderr)
        ))));
    }
    if !output.status.success() {
        return Err(io::Error::other(gpg_error(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )));
    }
    let key: [u8; 16] = output.stdout.as_slice().try_into().map_err(|_| {
        io::Error::other(gpg_error(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ))
    })?;
    Ok(FileKey::new(Box::new(key)))
}

/// `Ok(true)` when gpg reports a secret key for `primary_fpr` (plan 5.5). `Err` means gpg could
/// not be spawned (callers treat `NotFound` as "gpg absent") or failed for a reason other than
/// the key being missing, e.g. gpg-agent could not start; the error carries gpg's stderr.
pub fn is_held(primary_fpr: &str) -> io::Result<bool> {
    let output = Command::new("gpg")
        // The classification below matches gpg's English message; gettext lets LANGUAGE override
        // LC_ALL, so set both.
        .env("LC_ALL", "C")
        .env("LANGUAGE", "C")
        .args(["--list-secret-keys", "--with-colons", primary_fpr])
        .stdout(Stdio::null())
        .output()?;
    classify_secret_key_probe(
        output.status.code(),
        &String::from_utf8_lossy(&output.stderr),
    )
    .map_err(|stderr| {
        io::Error::other(format!(
            "gpg --list-secret-keys {primary_fpr} failed: {stderr}"
        ))
    })
}

/// Maps the exit code and stderr of `gpg --list-secret-keys <fpr>` to held / not held; any other
/// outcome is `Err` with gpg's stderr.
fn classify_secret_key_probe(code: Option<i32>, stderr: &str) -> Result<bool, String> {
    match code {
        Some(0) => Ok(true),
        Some(2) if stderr.contains("No secret key") => Ok(false),
        _ => Err(stderr.trim().to_string()),
    }
}

// Fixture recipes: tests/fixtures/README.md (plan 11).
#[cfg(test)]
mod tests {
    use std::io::Read;
    #[cfg(unix)]
    use std::process::Command as StdCommand;

    use age::{Identity, Recipient};
    use pgp::composed::{Message, SignedSecretKey};
    use pgp::types::Password;

    use super::*;

    fn fixture(name: &str) -> &'static str {
        match name {
            "valid_cv25519" => include_str!("../tests/fixtures/valid_cv25519.asc"),
            "valid_cv25519_secret" => include_str!("../tests/fixtures/valid_cv25519.secret.asc"),
            "valid_cv25519_crlf" => include_str!("../tests/fixtures/valid_cv25519_crlf.asc"),
            "valid_rsa" => include_str!("../tests/fixtures/valid_rsa.asc"),
            "sign_only" => include_str!("../tests/fixtures/sign_only.asc"),
            "revoked" => include_str!("../tests/fixtures/revoked.asc"),
            "third_party" => include_str!("../tests/fixtures/third_party.asc"),
            "two_keys" => include_str!("../tests/fixtures/two_keys.asc"),
            "garbage" => include_str!("../tests/fixtures/garbage.asc"),
            "expired" => include_str!("../tests/fixtures/expired.asc"),
            "subkey_expired" => include_str!("../tests/fixtures/subkey_expired.asc"),
            "two_subkeys" => include_str!("../tests/fixtures/two_subkeys.asc"),
            other => panic!("unknown fixture {other}"),
        }
    }

    /// Returns `true` if `gpg` is on PATH; otherwise prints a skip notice and returns `false`.
    #[cfg(unix)]
    fn gpg_available(test_name: &str) -> bool {
        if StdCommand::new("gpg").arg("--version").output().is_ok() {
            true
        } else {
            println!("skipping {test_name}: gpg not on PATH");
            false
        }
    }

    #[test]
    fn secret_key_probe_exit_zero_is_held() {
        assert_eq!(classify_secret_key_probe(Some(0), ""), Ok(true));
    }

    #[test]
    fn secret_key_probe_no_secret_key_is_not_held() {
        let stderr = "gpg: error reading key: No secret key\n";
        assert_eq!(classify_secret_key_probe(Some(2), stderr), Ok(false));
    }

    #[test]
    fn secret_key_probe_other_failures_carry_stderr() {
        let stderr = "gpg: can't connect to the gpg-agent: IPC connect call failed\n\
                      gpg: error reading key: No agent running\n";
        let err = classify_secret_key_probe(Some(2), stderr).unwrap_err();
        assert!(err.contains("No agent running"));
        // Killed by a signal, or any exit code other than gpg's "not found".
        assert!(classify_secret_key_probe(None, "").is_err());
        assert!(classify_secret_key_probe(Some(1), "No secret key").is_err());
    }

    #[test]
    fn validates_cv25519_key() {
        let asc = validate(fixture("valid_cv25519")).unwrap();
        assert_eq!(asc.fpr, "29D48A1B3BFEFD598681BCBAFA5E1250AC77C728");
    }

    #[test]
    fn validates_cv25519_key_with_crlf_line_endings() {
        let asc = validate(fixture("valid_cv25519_crlf")).unwrap();
        assert_eq!(asc.fpr, "29D48A1B3BFEFD598681BCBAFA5E1250AC77C728");
    }

    #[test]
    fn validates_rsa_key() {
        let asc = validate(fixture("valid_rsa")).unwrap();
        assert_eq!(asc.fpr, "0C65BC91B2C337DA71087984D10F62D0C4CF3D22");
    }

    #[test]
    fn rejects_sign_only_key() {
        assert!(matches!(
            validate(fixture("sign_only")),
            Err(CrateError::GpgKeyNoEncryptionSubkey)
        ));
    }

    #[test]
    fn rejects_revoked_key() {
        assert!(matches!(
            validate(fixture("revoked")),
            Err(CrateError::GpgKeyRevoked)
        ));
    }

    #[test]
    fn rejects_third_party_certification() {
        assert!(matches!(
            validate(fixture("third_party")),
            Err(CrateError::GpgKeyBindings(_))
        ));
    }

    #[test]
    fn rejects_multiple_keys_in_one_file() {
        assert!(matches!(
            validate(fixture("two_keys")),
            Err(CrateError::GpgKeyMultiple)
        ));
    }

    #[test]
    fn rejects_two_separately_armored_keys_concatenated() {
        // rPGP's dearmorer stops at the first `-----END PGP...-----` line, so naively
        // concatenating two full `-----BEGIN/END-----` blocks (e.g. `cat a.asc b.asc`) must
        // not silently validate as the first key alone.
        let concatenated = format!("{}{}", fixture("valid_cv25519"), fixture("valid_rsa"));
        assert!(matches!(
            validate(&concatenated),
            Err(CrateError::GpgKeyParse(_))
        ));
    }

    #[test]
    fn rejects_trailing_garbage_after_key() {
        // Not a second key, just corrupt trailing bytes after an otherwise valid key: must
        // still be rejected rather than silently validating the key alone.
        let with_garbage = format!("{}not a pgp key\n", fixture("valid_cv25519"));
        assert!(matches!(
            validate(&with_garbage),
            Err(CrateError::GpgKeyParse(_))
        ));
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(
            validate(fixture("garbage")),
            Err(CrateError::GpgKeyParse(_))
        ));
    }

    #[test]
    fn expired_key_loads_but_fails_add_time_check() {
        let asc = validate(fixture("expired")).unwrap();
        assert!(matches!(
            check_not_expired(&asc),
            Err(CrateError::GpgKeyExpired)
        ));
    }

    #[test]
    fn valid_key_passes_add_time_check() {
        let asc = validate(fixture("valid_cv25519")).unwrap();
        assert!(check_not_expired(&asc).is_ok());
    }

    #[test]
    fn expired_subkey_with_valid_primary_fails_add_time_check() {
        // The primary never expires; only the (newest, selected) encryption subkey does. This
        // exercises the subkey branch of check_not_expired independently of the primary branch.
        let asc = validate(fixture("subkey_expired")).unwrap();
        assert!(matches!(
            check_not_expired(&asc),
            Err(CrateError::GpgKeyExpired)
        ));
    }

    #[test]
    fn selects_newest_non_revoked_encryption_subkey() {
        // Fixture has three subkeys: an older encryption subkey (expected), a newer encryption
        // subkey that is revoked, and an even newer sign-only subkey. Selecting either of the
        // latter two would mean the revocation filter or the key-flags check is not applied.
        let asc = validate(fixture("two_subkeys")).unwrap();
        assert_eq!(asc.fpr, "ABCC4D8204EDED2D94FEAB8178AB623E697737B4");
    }

    #[test]
    fn stanza_round_trip_without_gpg() {
        let asc = validate(fixture("valid_cv25519")).unwrap();
        let recipient = PgpRecipient::new(&asc);
        let file_key = FileKey::new(Box::new([7u8; 16]));
        let (stanzas, labels) = recipient.wrap_file_key(&file_key).unwrap();
        assert!(labels.is_empty());
        assert_eq!(stanzas.len(), 1);
        assert_eq!(stanzas[0].tag, TAG);
        assert_eq!(stanzas[0].args, vec![asc.fpr.clone()]);

        let (secret_key, _headers) =
            SignedSecretKey::from_string(fixture("valid_cv25519_secret")).unwrap();
        let mut message = Message::from_bytes(stanzas[0].body.as_slice())
            .unwrap()
            .decrypt(&Password::from(""), &secret_key)
            .unwrap();
        let plaintext = message.as_data_vec().unwrap();
        assert_eq!(plaintext, file_key.expose_secret().to_vec());
    }

    #[test]
    fn mixed_age_and_pgp_file_decrypts_with_x25519_alone() {
        let asc = validate(fixture("valid_cv25519")).unwrap();
        let pgp_recipient = PgpRecipient::new(&asc);
        let x25519_identity = age::x25519::Identity::generate();
        let x25519_recipient = x25519_identity.to_public();
        let recipients: Vec<&dyn age::Recipient> = vec![&x25519_recipient, &pgp_recipient];
        let encryptor = age::Encryptor::with_recipients(recipients.into_iter()).unwrap();
        let mut ciphertext = vec![];
        let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
        writer.write_all(b"mixed body").unwrap();
        writer.finish().unwrap();

        let decryptor = age::Decryptor::new_buffered(&ciphertext[..]).unwrap();
        let mut plaintext = vec![];
        decryptor
            .decrypt(std::iter::once(&x25519_identity as &dyn age::Identity))
            .unwrap()
            .read_to_end(&mut plaintext)
            .unwrap();
        assert_eq!(plaintext, b"mixed body");
    }

    #[test]
    fn gpg_identity_ignores_other_tags_and_unknown_fingerprints() {
        // A nonexistent GNUPGHOME makes any regressed gpg spawn fail loudly, not reach ~/.gnupg.
        let identity = GpgIdentity::with_gnupghome(vec!["AAAA".to_string()], "/nonexistent".into());
        let other_tag = Stanza {
            tag: "x25519".to_string(),
            args: vec!["AAAA".to_string()],
            body: vec![],
        };
        assert!(identity.unwrap_stanza(&other_tag).is_none());

        let unknown_fpr = Stanza {
            tag: TAG.to_string(),
            args: vec!["BBBB".to_string()],
            body: vec![],
        };
        assert!(identity.unwrap_stanza(&unknown_fpr).is_none());

        let zero_args = Stanza {
            tag: TAG.to_string(),
            args: vec![],
            body: vec![],
        };
        assert!(identity.unwrap_stanza(&zero_args).is_none());

        let two_args = Stanza {
            tag: TAG.to_string(),
            args: vec!["AAAA".to_string(), "BBBB".to_string()],
            body: vec![],
        };
        assert!(identity.unwrap_stanza(&two_args).is_none());
    }

    #[test]
    fn gpg_identity_rejects_oversized_stanza_body_without_spawning_gpg() {
        // An oversized stanza body must be rejected before gpg is spawned; the nonexistent
        // GNUPGHOME proves gpg never ran if the cap regresses.
        let identity = GpgIdentity::with_gnupghome(vec!["AAAA".to_string()], "/nonexistent".into());
        let oversized = Stanza {
            tag: TAG.to_string(),
            args: vec!["AAAA".to_string()],
            body: vec![0u8; MAX_STANZA_BODY_LEN + 1],
        };
        let Some(Err(age::DecryptError::Io(e))) = identity.unwrap_stanza(&oversized) else {
            panic!("expected an io error without spawning gpg");
        };
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    #[cfg(unix)]
    fn unwrap_stanzas_tries_all_matches_before_giving_up() {
        // Two held GPG keys, only one usable (e.g. a card not inserted): the default
        // `unwrap_stanzas` would stop at the first stanza's `Err` and never try the second.
        if !gpg_available("unwrap_stanzas_tries_all_matches_before_giving_up") {
            return;
        }
        let gnupghome = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
        let _guard = GpgAgentGuard(gnupghome.path().to_path_buf());
        std::fs::set_permissions(
            gnupghome.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        import_secret_key(gnupghome.path(), fixture("valid_cv25519_secret"));

        // rsa_asc's secret key is never imported into this GNUPGHOME, so gpg will fail to
        // decrypt its stanza ("No secret key"); cv25519's secret key is imported and succeeds.
        let rsa_asc = validate(fixture("valid_rsa")).unwrap();
        let cv25519_asc = validate(fixture("valid_cv25519")).unwrap();
        let file_key = FileKey::new(Box::new([5u8; 16]));
        let (mut rsa_stanzas, _) = PgpRecipient::new(&rsa_asc)
            .wrap_file_key(&file_key)
            .unwrap();
        let (mut cv25519_stanzas, _) = PgpRecipient::new(&cv25519_asc)
            .wrap_file_key(&file_key)
            .unwrap();

        let identity = GpgIdentity::with_gnupghome(
            vec![rsa_asc.fpr.clone(), cv25519_asc.fpr.clone()],
            gnupghome.path().to_path_buf(),
        );

        // Failing stanza first: must still find the later, succeeding one.
        let stanzas = [rsa_stanzas.remove(0), cv25519_stanzas.remove(0)];
        let result = identity.unwrap_stanzas(&stanzas).unwrap().unwrap();
        assert_eq!(result.expose_secret(), file_key.expose_secret());
    }

    #[test]
    #[cfg(unix)]
    fn gpg_identity_unwraps_stanza_via_gpg() {
        if !gpg_available("gpg_identity_unwraps_stanza_via_gpg") {
            return;
        }
        let gnupghome = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
        let _guard = GpgAgentGuard(gnupghome.path().to_path_buf());
        std::fs::set_permissions(
            gnupghome.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        import_secret_key(gnupghome.path(), fixture("valid_cv25519_secret"));

        let asc = validate(fixture("valid_cv25519")).unwrap();
        let recipient = PgpRecipient::new(&asc);
        let file_key = FileKey::new(Box::new([9u8; 16]));
        let (stanzas, _labels) = recipient.wrap_file_key(&file_key).unwrap();

        let identity =
            GpgIdentity::with_gnupghome(vec![asc.fpr.clone()], gnupghome.path().to_path_buf());
        let result = identity.unwrap_stanza(&stanzas[0]).unwrap().unwrap();
        assert_eq!(result.expose_secret(), file_key.expose_secret());
    }

    #[cfg(unix)]
    fn import_secret_key(gnupghome: &std::path::Path, armored_secret: &str) {
        let key_path = gnupghome.join("import.asc");
        std::fs::write(&key_path, armored_secret).unwrap();
        let status = StdCommand::new("gpg")
            .env("GNUPGHOME", gnupghome)
            .args(["--batch", "--import"])
            .arg(&key_path)
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[cfg(unix)]
    struct GpgAgentGuard(std::path::PathBuf);
    #[cfg(unix)]
    impl Drop for GpgAgentGuard {
        fn drop(&mut self) {
            let _ = StdCommand::new("gpgconf")
                .env("GNUPGHOME", &self.0)
                .args(["--kill", "gpg-agent"])
                .status();
        }
    }
}
