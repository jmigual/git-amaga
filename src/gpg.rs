//! OpenPGP (`.asc`) key parsing, validation and encryption-subkey selection (plan 5.1).

use pgp::composed::{Deserializable, SignedPublicKey, SignedPublicSubKey};
use pgp::packet::{Signature, SignatureType};
use pgp::types::{KeyDetails, Timestamp};

use crate::error::Error;

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
pub fn validate(armored: &str) -> Result<AscKey, Error> {
    reject_concatenated_armor(armored)?;

    let (mut keys, _headers) = SignedPublicKey::from_string_many(armored)
        .map_err(|e| Error::GpgKeyParse(e.to_string()))?;
    let first = keys
        .next()
        .ok_or_else(|| Error::GpgKeyParse("no OpenPGP key found".to_string()))?
        .map_err(|e| Error::GpgKeyParse(e.to_string()))?;
    if keys.next().is_some() {
        return Err(Error::GpgKeyMultiple);
    }
    let key = first;

    key.verify_bindings()
        .map_err(|e| Error::GpgKeyBindings(e.to_string()))?;

    let revoked = key
        .details
        .revocation_signatures
        .iter()
        .any(|s| s.typ() == Some(SignatureType::KeyRevocation));
    if revoked {
        return Err(Error::GpgKeyRevoked);
    }

    let subkey = select_encryption_subkey(&key).ok_or(Error::GpgKeyNoEncryptionSubkey)?;
    let fpr = format!("{:X}", subkey.key.fingerprint());
    Ok(AscKey { key, fpr, subkey })
}

/// Rejects armored input with non-whitespace content after the first `-----END PGP...-----`
/// line (plan 5.1: "exactly one armored transferable public key"). rPGP's dearmorer only reads
/// up to that line, so a second concatenated key block, or plain trailing garbage, would
/// otherwise be silently ignored instead of rejected. Not specifically "multiple keys": trailing
/// content might not even be a second key, so [`Error::GpgKeyParse`] fits both cases.
fn reject_concatenated_armor(armored: &str) -> Result<(), Error> {
    if let Some(end_offset) = armored.find("-----END PGP") {
        let after_end_marker = &armored[end_offset..];
        let trailing = after_end_marker
            .find('\n')
            .map(|i| &after_end_marker[i + 1..])
            .unwrap_or("");
        if !trailing.trim().is_empty() {
            return Err(Error::GpgKeyParse(
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
pub fn check_not_expired(asc: &AscKey) -> Result<(), Error> {
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
        return Err(Error::GpgKeyExpired);
    }

    if newest_binding(&asc.subkey.signatures)
        .is_some_and(|sig| is_expired(asc.subkey.key.created_at(), sig, now))
    {
        return Err(Error::GpgKeyExpired);
    }

    Ok(())
}

fn is_expired(created: Timestamp, sig: &Signature, now: u32) -> bool {
    match sig.key_expiration_time() {
        Some(d) if d.as_secs() > 0 => created.as_secs() as u64 + d.as_secs() as u64 <= now as u64,
        _ => false,
    }
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
    use super::*;

    fn fixture(name: &str) -> &'static str {
        match name {
            "valid_cv25519" => include_str!("../tests/fixtures/valid_cv25519.asc"),
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
            Err(Error::GpgKeyNoEncryptionSubkey)
        ));
    }

    #[test]
    fn rejects_revoked_key() {
        assert!(matches!(
            validate(fixture("revoked")),
            Err(Error::GpgKeyRevoked)
        ));
    }

    #[test]
    fn rejects_third_party_certification() {
        assert!(matches!(
            validate(fixture("third_party")),
            Err(Error::GpgKeyBindings(_))
        ));
    }

    #[test]
    fn rejects_multiple_keys_in_one_file() {
        assert!(matches!(
            validate(fixture("two_keys")),
            Err(Error::GpgKeyMultiple)
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
            Err(Error::GpgKeyParse(_))
        ));
    }

    #[test]
    fn rejects_trailing_garbage_after_key() {
        // Not a second key, just corrupt trailing bytes after an otherwise valid key: must
        // still be rejected rather than silently validating the key alone.
        let with_garbage = format!("{}not a pgp key\n", fixture("valid_cv25519"));
        assert!(matches!(
            validate(&with_garbage),
            Err(Error::GpgKeyParse(_))
        ));
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(
            validate(fixture("garbage")),
            Err(Error::GpgKeyParse(_))
        ));
    }

    #[test]
    fn expired_key_loads_but_fails_add_time_check() {
        let asc = validate(fixture("expired")).unwrap();
        assert!(matches!(check_not_expired(&asc), Err(Error::GpgKeyExpired)));
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
        assert!(matches!(check_not_expired(&asc), Err(Error::GpgKeyExpired)));
    }

    #[test]
    fn selects_newest_non_revoked_encryption_subkey() {
        // Fixture has three subkeys: an older encryption subkey (expected), a newer encryption
        // subkey that is revoked, and an even newer sign-only subkey. Selecting either of the
        // latter two would mean the revocation filter or the key-flags check is not applied.
        let asc = validate(fixture("two_subkeys")).unwrap();
        assert_eq!(asc.fpr, "ABCC4D8204EDED2D94FEAB8178AB623E697737B4");
    }
}
