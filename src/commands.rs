use std::fs;
use std::path::Path;

use crate::context::{
    Context, ensure_ignored, read_plaintext, read_repo_file, secret_paths_for, write_repo_file,
};
use crate::{Error, audit, git, gpg, identity, paths, secret, users};

const GITATTRIBUTES_LINES: [&str; 3] = [
    "*.amaga binary",
    ".amaga/audit.jsonl merge=union",
    ".gitignore merge=union",
];

/// `git-amaga keygen [PATH]` (plan 7).
pub fn cmd_keygen(path: Option<&Path>) -> Result<(), Error> {
    let (_path, public) = identity::keygen(path)?;
    println!("{public}");
    Ok(())
}

/// `git-amaga init <name> [KEY…]` (plan 7).
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

    // Idempotent steps first: a failure here must not leave a half-initialized `.amaga/` that a
    // retry would refuse with AlreadyInitialized.
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

// `age1…` is an age recipient; anything else is an armored OpenPGP key file, at most one
// per member (plan 5.1, 7).
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

/// `git-amaga open [--force] [<path>…]` (plan 7).
pub fn cmd_open(force: bool, args: &[String]) -> Result<(), Error> {
    let mut ctx = Context::load()?;

    for sp in secret_paths_for(&ctx, args, false)? {
        let ciphertext = read_repo_file(&ctx.root, &sp.ciphertext)?;
        let (_header, body) = ctx.decrypt(&sp.ciphertext, &ciphertext)?;
        if git::is_tracked(&ctx.root, &sp.plaintext)? {
            return Err(Error::PlaintextTracked(sp.plaintext));
        }
        ensure_ignored(&ctx.root, &sp.plaintext)?;

        let local = read_plaintext(&ctx.root, &sp.plaintext)?;
        let state = secret::plaintext_state(
            local.as_deref(),
            &body,
            ctx.base.get(&sp.plaintext).copied(),
        );
        match state {
            secret::PlaintextState::InSync => {
                ctx.set_base(&sp.plaintext, &body)?;
                continue;
            }
            secret::PlaintextState::Modified | secret::PlaintextState::Conflict if !force => {
                return Err(Error::OpenRefused(sp.plaintext, state));
            }
            _ => {}
        }

        write_repo_file(&ctx.root, &sp.plaintext, &body, Some(0o600))?;
        ctx.set_base(&sp.plaintext, &body)?;
        println!("opened {}", sp.plaintext);
    }
    Ok(())
}

/// `git-amaga close [<path>…]` (plan 7).
pub fn cmd_close(args: &[String]) -> Result<(), Error> {
    let mut ctx = Context::load()?;

    for sp in secret_paths_for(&ctx, args, true)? {
        let Some(local) = read_plaintext(&ctx.root, &sp.plaintext)? else {
            continue;
        };
        let ciphertext = read_repo_file(&ctx.root, &sp.ciphertext)?;
        let (_header, body) = ctx.decrypt(&sp.ciphertext, &ciphertext)?;

        let state =
            secret::plaintext_state(Some(&local), &body, ctx.base.get(&sp.plaintext).copied());
        if state != secret::PlaintextState::InSync {
            return Err(Error::CloseRefused(sp.plaintext, state));
        }
        fs::remove_file(ctx.root.join(&sp.plaintext)).map_err(|source| Error::IoPath {
            path: sp.plaintext.clone(),
            source,
        })?;
        ctx.drop_base(&sp.plaintext)?;
        println!("closed {}", sp.plaintext);
    }
    Ok(())
}
