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

/// The age stanza tag for OpenPGP-wrapped file keys (plan 5.2.1).
const TAG: &str = "pgp";

/// An armored OpenPGP public key that has passed structural validation (plan 5.1), together
/// with its chosen encryption subkey and that subkey's fingerprint as uppercase hex (the `<FPR>`
/// used in key strings and `pgp` stanzas, plan 5.1/5.2.1).
pub struct AscKey {
    pub key: SignedPublicKey,
    pub fpr: String,
    pub subkey: SignedPublicSubKey,
}

/// Parses and validates an armored OpenPGP public key (plan 5.1). Does not check expiry; see
/// [`check_not_expired`] for the separate add-time check (plan change 18).
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

/// Rejects armored input with non-whitespace content after the first `-----END PGP...-----`
/// line (plan 5.1: "exactly one armored transferable public key"). rPGP's dearmorer only reads
/// up to that line, so a second concatenated key block, or plain trailing garbage, would
/// otherwise be silently ignored instead of rejected. Not specifically "multiple keys": trailing
/// content might not even be a second key, so [`CrateError::GpgKeyParse`] fits both cases.
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

/// Picks the newest, non-revoked subkey flagged for encryption with an encryption-capable
/// algorithm (plan 5.1). Expiry is not considered here.
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

/// The add-time expiry check (plan section 7): neither the primary key nor the selected
/// encryption subkey may be expired, judged from the `key_expiration_time()` of the newest
/// self-signature plus the key's `created_at()`.
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

/// An `age::Recipient` that wraps a file key to an OpenPGP encryption subkey as a `pgp` stanza
/// (plan 5.2.1).
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

/// gpg's stderr and the member fingerprint it was decrypting for (plan 7.3). Reported per
/// secret, with the fixed hint to check the card/PIN prompt.
#[derive(Debug, Error)]
#[error(
    "gpg decryption failed for {fpr}: {stderr}\nis the card inserted, and can gpg-agent show a PIN prompt (`export GPG_TTY=$(tty)`)?"
)]
pub struct GpgError {
    pub fpr: String,
    pub stderr: String,
}

/// An `age::Identity` that unwraps `pgp` stanzas addressed to any of `fprs` by running
/// `gpg --decrypt` (plan 5.2.1, 7.3). Ignores every other stanza tag, and unknown fingerprints,
/// so it can be mixed with age identities and age's own grease stanzas.
pub struct GpgIdentity {
    fprs: Vec<String>,
    /// Test-only `GNUPGHOME` override, passed to the gpg child process via `Command::env` so
    /// tests never mutate this process's own environment (plan section 11).
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

    /// Tries every `pgp` stanza addressed to a held fingerprint, not just the first one.
    ///
    /// The default `unwrap_stanzas` (`stanzas.iter().find_map(unwrap_stanza)`) stops at the
    /// first stanza for which `unwrap_stanza` returns `Some`, including `Some(Err(_))`. With
    /// two held GPG keys where only one card is inserted, that would let one key's gpg failure
    /// mask another key's success. Instead: return the first `Ok`, or else the first `Err` if
    /// every matching stanza failed, or else `None` if none matched at all.
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

/// Largest `pgp` stanza body accepted before spawning gpg. A real body (PKESK v3 + SEIPD v1
/// wrapping a 16-byte age file key) is a few hundred bytes; this is a generous margin, not a
/// protocol limit. Rejecting an oversized body up front avoids a subprocess pipe deadlock: gpg
/// can block writing its own stdout/stderr while this process is still blocked writing a large
/// stdin, and neither side is reading the other.
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

/// Returns whether gpg reports a secret key for `primary_fpr` as held (plan 5.5): `Ok(true)` on
/// exit 0, `Ok(false)` on any other exit. An `Err` means gpg could not be spawned; the caller
/// treats [`io::ErrorKind::NotFound`] as "gpg is absent" and skips every GPG member silently.
pub fn is_held(primary_fpr: &str) -> io::Result<bool> {
    let status = Command::new("gpg")
        .args(["--list-secret-keys", "--with-colons", primary_fpr])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    Ok(status.success())
}

// Fixture generation commands (plan section 11), run with a short-lived `GNUPGHOME` (never
// `~/.gnupg`), e.g. `GNUPGHOME=$(mktemp -d /tmp/g.XXXX)`:
//
//   valid_cv25519.asc / valid_cv25519.secret.asc:
//     gpg --batch --passphrase '' --quick-gen-key 'Valid <valid@example.invalid>' \
//       default default never
//     gpg --armor --export-options export-minimal --export <fpr> > valid_cv25519.asc
//     gpg --batch --passphrase '' --armor --export-secret-keys <fpr> \
//       > valid_cv25519.secret.asc
//   valid_cv25519_crlf.asc: `sed 's/$/\r/' valid_cv25519.asc`
//   valid_rsa.asc:
//     gpg --batch --passphrase '' --quick-gen-key 'Rsa <rsa@example.invalid>' rsa2048 default \
//       never
//     gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key <fpr> rsa2048 encr \
//       never
//     gpg --armor --export-options export-minimal --export <fpr> > valid_rsa.asc
//   sign_only.asc: like valid_cv25519.asc but
//     gpg --batch --passphrase '' --quick-gen-key 'SignOnly <signonly@example.invalid>' \
//       default sign never   (no subkey is created)
//   revoked.asc: like valid_cv25519.asc, then
//     gpg --no-tty --yes --pinentry-mode loopback --command-fd 0 --gen-revoke <fpr> \
//       > revoke.asc   (feed "y\n0\n\ny\n" on stdin)
//     gpg --batch --yes --import revoke.asc
//     gpg --armor --export-options export-minimal --export <fpr> > revoked.asc
//   third_party.asc: two keys (Signee, Signer), then
//     gpg --batch --yes --pinentry-mode loopback --passphrase '' --local-user <signer-fpr> \
//       --quick-sign-key <signee-fpr>
//     gpg --armor --export <signee-fpr> > third_party.asc   (no export-minimal, so the
//       third-party certification survives)
//   two_keys.asc: two keys imported into one keyring, then
//     gpg --armor --export-options export-minimal --export <fpr1> <fpr2> > two_keys.asc
//     (one armor block containing both keys' packets; see also the
//     `rejects_two_separately_armored_keys_concatenated` test below for the *separately*
//     armored case, built in-test by string concatenation)
//   garbage.asc: `printf 'this is not an openpgp key\n' > garbage.asc`
//   expired.asc: like valid_cv25519.asc, generated under
//     `--faked-system-time 20240101T000000` with a `1d` expiry, then exported with a plain
//     `gpg --armor --export <fpr>` (**not** `--export-options export-minimal`, which drops an
//     already-expired subkey at export time)
//   subkey_expired.asc: primary + first encryption subkey generated under
//     `--faked-system-time 20240101T000000` with `never` expiry, then a second, newer
//     encryption subkey added under `--faked-system-time 20240102T000000` with a `1d` expiry
//     (`gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key <fpr> default encr
//     1d`), exported with a plain `gpg --armor --export <fpr>` (same export-minimal caveat)
//   two_subkeys.asc: primary + first encryption subkey (kept, expected to be selected), then
//     a second, newer encryption subkey added under a future `--faked-system-time` and revoked
//     specifically (`gpg --command-fd 0 --edit-key <fpr>`, feed "key 2\nrevkey\ny\n0\n\ny\nsave\n"
//     on stdin), then a third, even newer sign-only RSA subkey added
//     (`gpg --quick-add-key <fpr> rsa2048 sign never`, under a later faked time), exported with
//     `--export-options export-minimal`
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
        // A nonexistent GNUPGHOME means that if any of these checks regressed and gpg actually
        // got spawned, it would fail loudly instead of silently reaching this process's real
        // `~/.gnupg`.
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
        // A crafted stanza body far larger than any real PKESK+SEIPD wrapping a 16-byte file
        // key must be rejected before gpg is even spawned (a nonexistent GNUPGHOME, rather than
        // this process's real `~/.gnupg`, proves gpg never ran if the cap regresses: an
        // oversized body that reached a real `gpg --decrypt` risked a stdin/stdout pipe
        // deadlock instead of a clean, prompt error).
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
