use std::fs;
use std::path::Path;

use crate::context::{
    Context, ensure_ignored, read_plaintext, read_repo_file, secret_paths_for, write_repo_file,
};
use crate::keyring::{GpgKey, ResolvedKeys};
use crate::outcome::{Outcome, Warning};
use crate::{Error, audit, git, identity, keyring, paths, secret, users};

const GITATTRIBUTES_LINES: [&str; 3] = [
    "*.amaga binary",
    ".amaga/audit.jsonl merge=union",
    ".gitignore merge=union",
];

/// `git-amaga keygen [PATH]` (plan 7).
pub fn cmd_keygen(dir: &Path, path: Option<&Path>) -> Result<age::x25519::Recipient, Error> {
    let (_path, public) = identity::keygen(dir, path)?;
    Ok(public)
}

/// `git-amaga init <name> [KEY…]` (plan 7): returns the member's GPG key, if any.
pub fn cmd_init(dir: &Path, name: &str, keys: &[String]) -> Result<Option<GpgKey>, Error> {
    if !users::valid_name(name) {
        return Err(Error::InvalidMemberName(name.to_string()));
    }

    let root = git::toplevel(dir)?;
    let amaga_dir = root.join(".amaga");
    if amaga_dir.exists() {
        return Err(Error::AlreadyInitialized);
    }

    let resolved = if keys.is_empty() {
        let identity_path = identity::configured_identity_path(dir)?.ok_or(Error::NoIdentity)?;
        let identities = identity::load_identity_file(&identity_path)?;
        if identities.is_empty() {
            return Err(Error::NoIdentity);
        }
        ResolvedKeys {
            age_keys: identities.iter().map(|i| i.to_public()).collect(),
            gpg: None,
        }
    } else {
        keyring::resolve(dir, keys)?
    };

    // Idempotent steps first: a failure here must not leave a half-initialized `.amaga/` that a
    // retry would refuse with AlreadyInitialized.
    paths::ensure_lines_present(&root.join(".gitattributes"), &GITATTRIBUTES_LINES)?;
    paths::ensure_gitignore_line(&root.join(".gitignore"), "*.amaga-tmp")?;

    let users_dir = amaga_dir.join("users");
    fs::create_dir_all(&users_dir)?;
    users::write_member(&users_dir, name, &resolved)?;

    let gpg_info = resolved
        .gpg
        .as_ref()
        .map(|k| (k.fpr.as_str(), k.uid.as_str()));
    audit::append(
        &amaga_dir.join("audit.jsonl"),
        name,
        "init",
        None,
        None,
        gpg_info,
    )?;

    Ok(resolved.gpg)
}

/// `git-amaga add [--force] <path>…` (plan 7).
pub fn cmd_add(dir: &Path, force: bool, args: &[String]) -> Result<Outcome, Error> {
    let mut ctx = Context::load(dir)?;
    let current = users::recipients(&ctx.members);
    let mut outcome = Outcome::default();

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
            outcome
                .warnings
                .push(Warning::PlaintextInHistory(sp.plaintext.clone()));
        }
        if git::path_in_history(&ctx.root, &sp.ciphertext)? {
            if !force {
                return Err(Error::CiphertextInHistory(sp.ciphertext));
            }
            outcome
                .warnings
                .push(Warning::ExposureHistoryDropped(sp.ciphertext.clone()));
        }

        ensure_ignored(&ctx.root, &sp.plaintext)?;
        let body = read_repo_file(&ctx.root, &sp.plaintext)?;
        let header = secret::next_header(None, false, &current);
        let ciphertext = ctx.encrypt(&header, &body)?;
        write_repo_file(&ctx.root, &sp.ciphertext, &ciphertext, None)?;
        ctx.set_base(&sp.plaintext, &body)?;
        ctx.audit("secret.added", &sp.plaintext)?;
        outcome.changed.push(sp.ciphertext);
    }
    Ok(outcome)
}

/// `git-amaga seal [--force] [<path>…]` (plan 7).
pub fn cmd_seal(dir: &Path, force: bool, args: &[String]) -> Result<Outcome, Error> {
    let mut ctx = Context::load(dir)?;
    let current = users::recipients(&ctx.members);
    let mut outcome = Outcome::default();

    for sp in secret_paths_for(&ctx, args, true, &mut outcome.warnings)? {
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
                outcome.warnings.push(Warning::ExposureCleared {
                    plaintext: sp.plaintext.clone(),
                    members: old_header.exposed_to.len(),
                });
            }
        }

        let new_header = secret::next_header(Some(&old_header), true, &current);
        let new_ciphertext = ctx.encrypt(&new_header, &local)?;
        write_repo_file(&ctx.root, &sp.ciphertext, &new_ciphertext, None)?;
        ctx.set_base(&sp.plaintext, &local)?;
        ctx.audit("secret.updated", &sp.plaintext)?;
        outcome.changed.push(sp.ciphertext);
    }
    Ok(outcome)
}

/// `git-amaga open [--force] [<path>…]` (plan 7).
pub fn cmd_open(dir: &Path, force: bool, args: &[String]) -> Result<Outcome, Error> {
    let mut ctx = Context::load(dir)?;
    let mut outcome = Outcome::default();

    for sp in secret_paths_for(&ctx, args, false, &mut outcome.warnings)? {
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
        outcome.changed.push(sp.plaintext);
    }
    Ok(outcome)
}

/// `git-amaga close [<path>…]` (plan 7).
pub fn cmd_close(dir: &Path, args: &[String]) -> Result<Outcome, Error> {
    let mut ctx = Context::load(dir)?;
    let mut outcome = Outcome::default();

    for sp in secret_paths_for(&ctx, args, true, &mut outcome.warnings)? {
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
        outcome.changed.push(sp.plaintext);
    }
    Ok(outcome)
}
