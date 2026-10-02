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
use std::path::{Path, PathBuf};

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

    audit::append(&amaga_dir.join("audit.jsonl"), name, "init", None)?;

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

/// Per-command state: repository, membership, the actor's identities (plan 5.5) and the
/// per-worktree base hashes.
struct Context {
    root: PathBuf,
    prefix: String,
    actor: String,
    members: users::Members,
    age_identities: Vec<age::x25519::Identity>,
    gpg_fprs: Vec<String>,
    base_path: PathBuf,
    base: secret::BaseMap,
}

impl Context {
    /// Refuses while any `*.amaga` is unmerged (plan section 7), then loads everything.
    fn load() -> Result<Self, Error> {
        let root = git::toplevel()?;
        let unmerged = git::unmerged_secrets(&root)?;
        if !unmerged.is_empty() {
            return Err(Error::UnmergedAmagaFiles(unmerged.join(", ")));
        }
        let members = users::load(&root.join(".amaga/users"))?;
        let age_identities = match identity::configured_identity_path()? {
            Some(path) => identity::load_identity_file(&path)?,
            None => Vec::new(),
        };
        let (actor, gpg_fprs) = identity::find_actor(&members, &age_identities, gpg::is_held)?;
        let base_path = git::git_path("amaga-base")?;
        Ok(Self {
            prefix: git::show_prefix()?,
            base: secret::load_base(&base_path)?,
            base_path,
            root,
            actor,
            members,
            age_identities,
            gpg_fprs,
        })
    }

    /// Decrypts with the age identities first, then one `GpgIdentity` (plan 5.5). Errors name
    /// `path`.
    fn decrypt(&self, path: &str, ciphertext: &[u8]) -> Result<(secret::Header, Vec<u8>), Error> {
        let gpg_identity = gpg::GpgIdentity::new(self.gpg_fprs.clone());
        let mut identities: Vec<&dyn age::Identity> = self
            .age_identities
            .iter()
            .map(|i| i as &dyn age::Identity)
            .collect();
        identities.push(&gpg_identity);
        secret::decrypt(ciphertext, &identities).map_err(|source| Error::SecretUndecryptable {
            path: path.to_string(),
            member: self.failing_member(&source),
            source: Box::new(source),
        })
    }

    /// The member whose gpg key a gpg decryption failure was about.
    fn failing_member(&self, err: &Error) -> Option<String> {
        let Error::Decrypt(age::DecryptError::Io(io)) = err else {
            return None;
        };
        let fpr = &io.get_ref()?.downcast_ref::<gpg::GpgError>()?.fpr;
        self.members
            .iter()
            .find(|(_, m)| {
                m.asc
                    .as_ref()
                    .is_some_and(|a| a.subkey_fprs().contains(fpr))
            })
            .map(|(name, _)| name.clone())
    }

    /// Encrypts to every member key, age and OpenPGP.
    fn encrypt(&self, header: &secret::Header, body: &[u8]) -> Result<Vec<u8>, Error> {
        let pgp: Vec<gpg::PgpRecipient> = self
            .members
            .values()
            .filter_map(|m| m.asc.as_ref())
            .map(gpg::PgpRecipient::new)
            .collect();
        let recipients: Vec<&dyn age::Recipient> = self
            .members
            .values()
            .flat_map(|m| &m.age_keys)
            .map(|k| k as &dyn age::Recipient)
            .chain(pgp.iter().map(|r| r as &dyn age::Recipient))
            .collect();
        secret::encrypt(header, body, &recipients)
    }

    /// Records `body` as the base of `path`; the file is rewritten only when that changes it.
    fn set_base(&mut self, path: &str, body: &[u8]) -> Result<(), Error> {
        let hash = secret::hash(body);
        if self.base.insert(path.to_string(), hash) != Some(hash) {
            secret::save_base(&self.base_path, &self.base)?;
        }
        Ok(())
    }

    fn audit(&self, event: &str, path: &str) -> Result<(), Error> {
        audit::append(
            &self.root.join(".amaga/audit.jsonl"),
            &self.actor,
            event,
            Some(path),
        )
    }
}

/// Existing managed secrets for the given arguments, or all of them when `args` is empty
/// (only those with local plaintext when `existing_plaintext_only`). Listed paths get the same
/// validation as arguments; invalid ones are skipped with a warning.
fn secret_paths_for(
    ctx: &Context,
    args: &[String],
    existing_plaintext_only: bool,
) -> Result<Vec<paths::SecretPath>, Error> {
    if !args.is_empty() {
        return args
            .iter()
            .map(|a| paths::resolve_arg(&ctx.prefix, a))
            .collect();
    }
    let mut found = Vec::new();
    for ciphertext in git::managed_secrets(&ctx.root)? {
        if !ctx.root.join(&ciphertext).exists() {
            continue;
        }
        match paths::resolve_arg("", &ciphertext) {
            Ok(sp) if !existing_plaintext_only || ctx.root.join(&sp.plaintext).exists() => {
                found.push(sp)
            }
            Ok(_) => {}
            Err(e) => eprintln!("warning: skipping '{ciphertext}': {e}"),
        }
    }
    Ok(found)
}

fn read_repo_file(root: &Path, path: &str) -> Result<Vec<u8>, Error> {
    fs::read(root.join(path)).map_err(|source| Error::IoPath {
        path: path.to_string(),
        source,
    })
}

/// `None` only when the plaintext does not exist; other read errors must not look like `Closed`.
fn read_plaintext(root: &Path, path: &str) -> Result<Option<Vec<u8>>, Error> {
    match read_repo_file(root, path) {
        Err(Error::IoPath { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            Ok(None)
        }
        other => other.map(Some),
    }
}

fn write_repo_file(
    root: &Path,
    path: &str,
    contents: &[u8],
    mode: Option<u32>,
) -> Result<(), Error> {
    paths::atomic_write(&root.join(path), contents, mode).map_err(|source| Error::IoPath {
        path: path.to_string(),
        source,
    })
}

/// The ensure-ignored step (plan 5.4).
fn ensure_ignored(root: &Path, path: &str) -> Result<(), Error> {
    if git::is_ignored(root, path)? {
        return Ok(());
    }
    paths::ensure_gitignore_line(&root.join(".gitignore"), &paths::gitignore_escape(path))?;
    if !git::is_ignored(root, path)? {
        return Err(Error::PlaintextNotIgnored(path.to_string()));
    }
    Ok(())
}

/// `git-amaga add [--force] <path>…` (plan 7).
pub fn cmd_add(force: bool, args: &[String]) -> Result<(), Error> {
    let mut ctx = Context::load()?;
    let current = users::recipients(&ctx.members);

    for arg in args {
        let sp = paths::resolve_arg(&ctx.prefix, arg)?;
        let meta =
            fs::symlink_metadata(ctx.root.join(&sp.plaintext)).map_err(|source| Error::IoPath {
                path: sp.plaintext.clone(),
                source,
            })?;
        if !meta.is_file() {
            return Err(Error::NotARegularFile(sp.plaintext));
        }
        if git::is_tracked(&ctx.root, &sp.plaintext)? {
            return Err(Error::PlaintextTracked(sp.plaintext));
        }
        if ctx.root.join(&sp.ciphertext).exists() {
            return Err(Error::CiphertextExists(sp.ciphertext));
        }
        if git::path_in_history(&ctx.root, &sp.plaintext)? {
            eprintln!("warning: '{}' already appears in git history", sp.plaintext);
        }
        if git::path_in_history(&ctx.root, &sp.ciphertext)? {
            if !force {
                return Err(Error::CiphertextInHistory(sp.ciphertext));
            }
            eprintln!(
                "warning: '{}' appears in git history; its exposure history is dropped",
                sp.ciphertext
            );
        }

        ensure_ignored(&ctx.root, &sp.plaintext)?;
        let body = read_repo_file(&ctx.root, &sp.plaintext)?;
        let header = secret::next_header(None, false, &current);
        let ciphertext = ctx.encrypt(&header, &body)?;
        write_repo_file(&ctx.root, &sp.ciphertext, &ciphertext, None)?;
        ctx.set_base(&sp.plaintext, &body)?;
        ctx.audit("secret.added", &sp.plaintext)?;
        println!("added {}", sp.ciphertext);
    }
    Ok(())
}

/// `git-amaga seal [--force] [<path>…]` (plan 7).
pub fn cmd_seal(force: bool, args: &[String]) -> Result<(), Error> {
    let mut ctx = Context::load()?;
    let current = users::recipients(&ctx.members);

    for sp in secret_paths_for(&ctx, args, true)? {
        let ciphertext = read_repo_file(&ctx.root, &sp.ciphertext)?;
        let (old_header, old_body) = ctx.decrypt(&sp.ciphertext, &ciphertext)?;
        ensure_ignored(&ctx.root, &sp.plaintext)?;
        let Some(local) = read_plaintext(&ctx.root, &sp.plaintext)? else {
            continue;
        };

        let state = secret::plaintext_state(
            Some(&local),
            &old_body,
            ctx.base.get(&sp.plaintext).copied(),
        );
        if state == secret::PlaintextState::InSync {
            ctx.set_base(&sp.plaintext, &old_body)?;
            continue;
        }
        if matches!(
            state,
            secret::PlaintextState::Outdated | secret::PlaintextState::Conflict
        ) {
            if !force {
                return Err(Error::SealRefused(sp.plaintext, state));
            }
            if !old_header.exposed_to.is_empty() {
                eprintln!(
                    "warning: sealing '{}' with --force clears NEEDS ROTATION for {} member(s); the local copy may still hold an old value",
                    sp.plaintext,
                    old_header.exposed_to.len()
                );
            }
        }

        let new_header = secret::next_header(Some(&old_header), true, &current);
        let new_ciphertext = ctx.encrypt(&new_header, &local)?;
        write_repo_file(&ctx.root, &sp.ciphertext, &new_ciphertext, None)?;
        ctx.set_base(&sp.plaintext, &local)?;
        ctx.audit("secret.updated", &sp.plaintext)?;
        println!("sealed {}", sp.ciphertext);
    }
    Ok(())
}
