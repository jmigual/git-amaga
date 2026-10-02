//! `KEY` argument resolution for `init` and `user add` (plan 7, 7.4, ADR-0013): age recipients,
//! `.asc` key files, and keys exported from the local gpg keyring.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;
use std::process::Output;

use crate::{Error, gpg};

#[derive(Debug, PartialEq, Eq)]
pub enum KeyKind {
    Age,
    AscFile,
    GpgSpec,
}

/// Plan 7 rules 1-3: `age1…`, then an existing `.asc` file, else a gpg key spec.
pub fn classify(key: &str) -> KeyKind {
    let path = Path::new(key);
    if key.starts_with("age1") {
        KeyKind::Age
    } else if path.extension().is_some_and(|e| e == "asc") && path.is_file() {
        KeyKind::AscFile
    } else {
        KeyKind::GpgSpec
    }
}

/// A validated OpenPGP key ready to be stored as `<name>.asc`.
pub struct GpgKey {
    pub armored: String,
    pub asc: gpg::AscKey,
    pub fpr: String,
    pub uid: String,
}

impl GpgKey {
    /// The line printed for each OpenPGP key (plan 7).
    pub fn summary(&self, name: &str) -> String {
        format!("{name}: GPG key {} \"{}\"", self.fpr, self.uid)
    }
}

pub struct ResolvedKeys {
    pub age_keys: Vec<age::x25519::Recipient>,
    pub gpg: Option<GpgKey>,
}

/// Resolves every `KEY`; at most one OpenPGP key (file or lookup) is allowed (plan 5.1, 7).
/// OpenPGP keys are validated and checked for expiry before anything is written.
pub fn resolve(keys: &[String]) -> Result<ResolvedKeys, Error> {
    let mut age_keys = Vec::new();
    let mut seen_age = BTreeSet::new();
    let mut gpg_key = None;
    for key in keys {
        let kind = classify(key);
        if kind == KeyKind::Age {
            let recipient: age::x25519::Recipient = key
                .parse()
                .map_err(|_| Error::AgeRecipientParse(key.clone()))?;
            if seen_age.insert(recipient.to_string()) {
                age_keys.push(recipient);
            }
            continue;
        }
        if gpg_key.is_some() {
            return Err(Error::MultipleGpgKeys);
        }
        let armored = if kind == KeyKind::AscFile {
            fs::read_to_string(key).map_err(|source| Error::IoPath {
                path: key.clone(),
                source,
            })?
        } else {
            lookup(key).map_err(|e| match e {
                Error::GpgKeyNotFound { .. } if looks_like_path(key) => {
                    Error::KeyFileNotFound(key.clone())
                }
                e => e,
            })?
        };
        let asc = gpg::validate(&armored)?;
        gpg::check_not_expired(&asc)?;
        gpg_key = Some(GpgKey {
            fpr: asc.primary_fpr(),
            uid: asc.first_user_id(),
            armored,
            asc,
        });
    }
    Ok(ResolvedKeys {
        age_keys,
        gpg: gpg_key,
    })
}

/// Exports the one key matching `spec` from the local keyring, export-minimal (plan 7.4).
pub fn lookup(spec: &str) -> Result<String, Error> {
    let listing = run_gpg(&["--list-keys", "--with-colons", "--", &wrap_email(spec)])?;
    let stderr = String::from_utf8_lossy(&listing.stderr);
    let keys = if listing.status.success() {
        parse_listing(&String::from_utf8_lossy(&listing.stdout))
    } else {
        Vec::new()
    };
    let key = single_key(spec, keys, &stderr)?;

    let export = run_gpg(&[
        "--export",
        "--armor",
        "--export-options",
        "export-minimal",
        "--",
        &key.fpr,
    ])?;
    if !export.status.success() || export.stdout.is_empty() {
        return Err(not_found(spec, &String::from_utf8_lossy(&export.stderr)));
    }
    String::from_utf8(export.stdout).map_err(|e| Error::GpgKeyParse(e.to_string()))
}

fn run_gpg(args: &[&str]) -> Result<Output, Error> {
    std::process::Command::new("gpg")
        .args(args)
        .output()
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => Error::GpgNotFound,
            _ => Error::Io(e),
        })
}

// A spec that was probably meant as a key file (so a typo says the file is missing).
fn looks_like_path(spec: &str) -> bool {
    spec.ends_with(".asc") || spec.contains(['/', '\\'])
}

// A bare email would match as a substring (`alice@x` also finds `malice@x`); `<…>` is exact.
// gpg's own prefix forms (`=exact`, `@substring`, `*word`, ...) are left alone.
fn wrap_email(spec: &str) -> String {
    let is_email = spec.contains('@')
        && !spec.starts_with(['=', '@', '*', '+', '#', '&', '<'])
        && !spec.contains('>')
        && !spec.chars().any(char::is_whitespace);
    if is_email {
        format!("<{spec}>")
    } else {
        spec.to_string()
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ListedKey {
    fpr: String,
    uid: String,
    // Revoked, expired or disabled: it can never be added, so it must not count as a match.
    unusable: bool,
}

// Each `pub` record starts a key (validity `r`/`e` in field 2, `D` in the capabilities in field
// 12 mark it unusable); only the first `fpr` after it is the primary's (later ones follow `sub`
// records); the first `uid` is kept.
fn parse_listing(colons: &str) -> Vec<ListedKey> {
    let mut keys: Vec<ListedKey> = Vec::new();
    let mut awaiting_fpr = false;
    for line in colons.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        let field9 = fields.get(9).copied().unwrap_or_default();
        if fields[0] == "pub" {
            keys.push(ListedKey {
                unusable: matches!(fields.get(1).copied(), Some("r" | "e"))
                    || fields.get(11).is_some_and(|caps| caps.contains('D')),
                ..ListedKey::default()
            });
            awaiting_fpr = true;
            continue;
        }
        let Some(key) = keys.last_mut() else { continue };
        match fields[0] {
            "fpr" if awaiting_fpr => {
                key.fpr = field9.to_string();
                awaiting_fpr = false;
            }
            "uid" if key.uid.is_empty() => key.uid = field9.to_string(),
            _ => {}
        }
    }
    keys
}

fn single_key(spec: &str, keys: Vec<ListedKey>, stderr: &str) -> Result<ListedKey, Error> {
    let total = keys.len();
    let mut keys: Vec<ListedKey> = keys.into_iter().filter(|k| !k.unusable).collect();
    match keys.len() {
        0 if total > 0 => Err(not_found(
            spec,
            "only revoked, expired or disabled keys match",
        )),
        0 => Err(not_found(spec, stderr)),
        1 => Ok(keys.remove(0)),
        _ => Err(Error::GpgKeyAmbiguous {
            spec: spec.to_string(),
            keys: keys
                .iter()
                .map(|k| format!("  {} {}", k.fpr, k.uid))
                .collect::<Vec<_>>()
                .join("\n"),
        }),
    }
}

fn not_found(spec: &str, stderr: &str) -> Error {
    Error::GpgKeyNotFound {
        spec: spec.to_string(),
        stderr: stderr.trim().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE_KEY: &str = "tru::1:1700000000:0:3:1:5\n\
pub:u:255:22:AAAA111122223333:1700000000:::u:::scESC:::::ed25519:::0:\n\
fpr:::::::::1111111111111111111111111111111111111111:\n\
grp:::::::::GRIP1:\n\
uid:u::::1700000000::HASH1::Alice <alice@example.invalid>::::::::::0:\n\
sub:u:255:18:BBBB111122223333:1700000000::::::e:::::cv25519::\n\
fpr:::::::::2222222222222222222222222222222222222222:\n";

    const TWO_KEYS: &str = "pub:u:255:22:AAAA:1700000000:::u:::scESC:::::ed25519:::0:\n\
fpr:::::::::1111111111111111111111111111111111111111:\n\
uid:u::::1700000000::H1::Alice One <dup@example.invalid>:::::::::0:\n\
sub:u:255:18:BBBB:1700000000::::::e:::::cv25519::\n\
fpr:::::::::2222222222222222222222222222222222222222:\n\
pub:u:255:22:CCCC:1700000001:::u:::scESC:::::ed25519:::0:\n\
fpr:::::::::3333333333333333333333333333333333333333:\n\
uid:u::::1700000001::H2::Alice Two <dup@example.invalid>:::::::::0:\n\
uid:u::::1700000001::H3::Second uid <other@example.invalid>:::::::::0:\n\
sub:u:255:18:DDDD:1700000001::::::e:::::cv25519::\n\
fpr:::::::::4444444444444444444444444444444444444444:\n";

    #[test]
    fn classify_age_recipient() {
        assert_eq!(classify("age1abc"), KeyKind::Age);
    }

    #[test]
    fn classify_existing_asc_file_only() {
        let dir = tempfile::tempdir().unwrap();
        let asc = dir.path().join("alice.asc");
        let txt = dir.path().join("alice.txt");
        fs::write(&asc, "").unwrap();
        fs::write(&txt, "").unwrap();

        assert_eq!(classify(asc.to_str().unwrap()), KeyKind::AscFile);
        assert_eq!(classify(txt.to_str().unwrap()), KeyKind::GpgSpec);
        let missing = dir.path().join("missing.asc");
        assert_eq!(classify(missing.to_str().unwrap()), KeyKind::GpgSpec);
    }

    #[test]
    fn classify_ids_and_emails_as_gpg_specs() {
        for spec in ["alice@example.org", "0xDEADBEEF", "Alice Example"] {
            assert_eq!(classify(spec), KeyKind::GpgSpec, "{spec}");
        }
    }

    #[test]
    fn wrap_email_wraps_only_bare_addresses() {
        assert_eq!(wrap_email("alice@example.org"), "<alice@example.org>");
        assert_eq!(wrap_email("<alice@example.org>"), "<alice@example.org>");
        assert_eq!(
            wrap_email("Alice <alice@example.org>"),
            "Alice <alice@example.org>"
        );
        assert_eq!(wrap_email("0xDEADBEEF"), "0xDEADBEEF");
    }

    #[test]
    fn wrap_email_leaves_gpg_prefix_forms_alone() {
        for spec in [
            "@example.invalid",
            "=Alice <a@x>",
            "*alice@x",
            "+a@x",
            "#a@x",
            "&a@x",
        ] {
            assert_eq!(wrap_email(spec), spec);
        }
    }

    #[test]
    fn looks_like_path_matches_asc_names_and_separators() {
        assert!(looks_like_path("alice.asc"));
        assert!(looks_like_path("keys/alice"));
        assert!(looks_like_path("keys\\alice"));
        assert!(!looks_like_path("alice@example.org"));
    }

    #[test]
    fn parse_listing_marks_revoked_expired_and_disabled_keys_unusable() {
        let line = |validity: &str, caps: &str| {
            format!("pub:{validity}:255:22:AAAA:1700000000:::u:::{caps}:::::ed25519:::0:\n")
        };
        let usable = |validity, caps| !parse_listing(&line(validity, caps))[0].unusable;

        assert!(usable("u", "scESC"));
        assert!(usable("-", "scESC"));
        assert!(!usable("r", "scESC"));
        assert!(!usable("e", "scESC"));
        assert!(!usable("u", "scESCD"));
    }

    #[test]
    fn single_key_skips_unusable_keys() {
        let key = |fpr: &str, unusable| ListedKey {
            fpr: fpr.to_string(),
            uid: "x".to_string(),
            unusable,
        };

        let picked = single_key("s", vec![key("OLD", true), key("NEW", false)], "").unwrap();
        assert_eq!(picked.fpr, "NEW");

        match single_key("s", vec![key("OLD", true)], "gpg said no") {
            Err(Error::GpgKeyNotFound { stderr, .. }) => assert!(stderr.contains("revoked")),
            other => panic!("expected GpgKeyNotFound, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn parse_listing_takes_the_primary_fpr_not_the_subkey_fpr() {
        let keys = parse_listing(ONE_KEY);
        assert_eq!(
            keys,
            [ListedKey {
                fpr: "1".repeat(40),
                uid: "Alice <alice@example.invalid>".to_string(),
                unusable: false,
            }]
        );
    }

    #[test]
    fn parse_listing_separates_two_keys_and_keeps_the_first_uid() {
        let keys = parse_listing(TWO_KEYS);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].fpr, "1".repeat(40));
        assert_eq!(keys[1].fpr, "3".repeat(40));
        assert_eq!(keys[1].uid, "Alice Two <dup@example.invalid>");
    }

    #[test]
    fn parse_listing_of_nothing_is_empty() {
        assert!(parse_listing("").is_empty());
    }

    #[test]
    fn single_key_rejects_none_and_many() {
        assert!(matches!(
            single_key("x", Vec::new(), ""),
            Err(Error::GpgKeyNotFound { .. })
        ));
        match single_key("dup@example.invalid", parse_listing(TWO_KEYS), "") {
            Err(Error::GpgKeyAmbiguous { keys, .. }) => {
                assert!(keys.contains(&"1".repeat(40)));
                assert!(keys.contains(&"3".repeat(40)));
            }
            other => panic!("expected GpgKeyAmbiguous, got {:?}", other.map(|_| ())),
        }
        assert!(single_key("x", parse_listing(ONE_KEY), "").is_ok());
    }

    #[test]
    fn resolve_deduplicates_age_keys_and_reads_an_asc_file() {
        let dir = tempfile::tempdir().unwrap();
        let asc = dir.path().join("alice.asc");
        let armored = include_str!("../tests/fixtures/valid_cv25519.asc");
        fs::write(&asc, armored).unwrap();
        let age = age::x25519::Identity::generate().to_public().to_string();

        let resolved =
            resolve(&[age.clone(), asc.to_str().unwrap().to_string(), age.clone()]).unwrap();

        let age_keys: Vec<String> = resolved.age_keys.iter().map(|k| k.to_string()).collect();
        assert_eq!(age_keys, [age]);
        let gpg = resolved.gpg.unwrap();
        assert_eq!(gpg.armored, armored);
        assert_eq!(gpg.fpr.len(), 40);
        assert!(gpg.uid.contains("valid@example.invalid"));
    }

    #[test]
    fn resolve_rejects_a_second_openpgp_key_before_looking_it_up() {
        let dir = tempfile::tempdir().unwrap();
        let asc = dir.path().join("alice.asc");
        fs::write(&asc, include_str!("../tests/fixtures/valid_cv25519.asc")).unwrap();
        let path = asc.to_str().unwrap().to_string();

        let result = resolve(&[path.clone(), path]);

        assert!(matches!(result, Err(Error::MultipleGpgKeys)));
    }
}
