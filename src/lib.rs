pub mod audit;
pub mod error;
pub mod git;
pub mod gpg;
pub mod identity;
pub mod paths;
pub mod secret;
pub mod users;

pub use error::Error;

use std::fs;
use std::path::Path;

/// `.gitattributes` lines `init` ensures are present (plan 5).
const GITATTRIBUTES_LINES: [&str; 3] = [
    "*.amaga binary",
    ".amaga/audit.jsonl merge=union",
    ".gitignore merge=union",
];

/// `git-amaga keygen [PATH]` (plan: `keygen`): generates an age identity and prints its public
/// key.
pub fn cmd_keygen(path: Option<&Path>) -> Result<(), Error> {
    let (_path, public) = identity::keygen(path)?;
    println!("{public}");
    Ok(())
}

/// `git-amaga init <name> [KEY…]` (plan: `init`): creates `.amaga/`, the first member, the
/// `.gitattributes`/`.gitignore` lines, and the `init` audit event.
pub fn cmd_init(name: &str, keys: &[String]) -> Result<(), Error> {
    if !users::valid_name(name) {
        return Err(Error::InvalidMemberName(name.to_string()));
    }

    let root = git::toplevel()?;
    let amaga_dir = root.join(".amaga");
    if amaga_dir.exists() {
        return Err(Error::AlreadyInitialized);
    }

    let (age_lines, asc_content) = if keys.is_empty() {
        let identity_path = identity::configured_identity_path()?.ok_or(Error::NoIdentity)?;
        let identities = identity::load_identity_file(&identity_path)?;
        if identities.is_empty() {
            return Err(Error::NoIdentity);
        }
        let age_lines = identities
            .iter()
            .map(|i| i.to_public().to_string())
            .collect();
        (age_lines, None)
    } else {
        collect_keys(keys)?
    };

    // .gitattributes/.gitignore first, and .amaga/ only once they have succeeded: both are
    // idempotent, so a retry after a failure here (for example an unreadable .gitignore) can
    // simply run `init` again, instead of leaving a half-initialized `.amaga/` that a retry
    // would then refuse with AlreadyInitialized.
    paths::ensure_lines_present(&root.join(".gitattributes"), &GITATTRIBUTES_LINES)?;
    paths::ensure_gitignore_line(&root.join(".gitignore"), "*.amaga-tmp")?;

    let users_dir = amaga_dir.join("users");
    fs::create_dir_all(&users_dir)?;
    if !age_lines.is_empty() {
        let contents = format!("{}\n", age_lines.join("\n"));
        paths::atomic_write(
            &users_dir.join(format!("{name}.txt")),
            contents.as_bytes(),
            None,
        )?;
    }
    if let Some(asc) = &asc_content {
        paths::atomic_write(&users_dir.join(format!("{name}.asc")), asc.as_bytes(), None)?;
    }

    audit::append(&amaga_dir.join("audit.jsonl"), name, "init")?;

    Ok(())
}

/// Classifies each `KEY` argument (plan section 7): `age1…` is an age recipient, anything else
/// is a path to an armored OpenPGP public key file (at most one per member), validated and
/// checked for add-time expiry (plan 5.1, section 7).
fn collect_keys(keys: &[String]) -> Result<(Vec<String>, Option<String>), Error> {
    let mut age_lines = Vec::new();
    let mut seen_age: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut asc_content: Option<String> = None;
    for key in keys {
        if key.starts_with("age1") {
            let recipient: age::x25519::Recipient = key
                .parse()
                .map_err(|_| Error::AgeRecipientParse(key.clone()))?;
            let canonical = recipient.to_string();
            if seen_age.insert(canonical.clone()) {
                age_lines.push(canonical);
            }
        } else {
            if asc_content.is_some() {
                return Err(Error::MultipleGpgKeys);
            }
            let contents = fs::read_to_string(key).map_err(|source| Error::IoPath {
                path: key.clone(),
                source,
            })?;
            let asc = gpg::validate(&contents)?;
            gpg::check_not_expired(&asc)?;
            asc_content = Some(contents);
        }
    }
    Ok((age_lines, asc_content))
}
