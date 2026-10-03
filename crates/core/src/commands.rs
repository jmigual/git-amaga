use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::context::{
    Context, ensure_ignored, read_plaintext, read_repo_file, secret_paths_for, write_repo_file,
};
use crate::keyring::{GpgKey, ResolvedKeys};
use crate::outcome::{Level, Outcome, SecretStatus, StatusReport, Warning};
use crate::{Error, audit, git, identity, keyring, paths, secret, users};

const GITATTRIBUTES_LINES: [&str; 3] = [
    "*.amaga binary",
    ".amaga/audit.jsonl merge=union",
    ".gitignore merge=union",
];

/// `git-amaga keygen [PATH]` (plan 7).
pub fn cmd_keygen(path: Option<&Path>) -> Result<age::x25519::Recipient, Error> {
    let (_path, public) = identity::keygen(path)?;
    Ok(public)
}

/// `git-amaga init <name> [KEY…]` (plan 7): returns the member's GPG key, if any.
pub fn cmd_init(name: &str, keys: &[String]) -> Result<Option<GpgKey>, Error> {
    if !users::valid_name(name) {
        return Err(Error::InvalidMemberName(name.to_string()));
    }

    let root = git::toplevel()?;
    let amaga_dir = root.join(".amaga");
    if amaga_dir.exists() {
        return Err(Error::AlreadyInitialized);
    }

    let resolved = if keys.is_empty() {
        let identity_path = identity::configured_identity_path()?.ok_or(Error::NoIdentity)?;
        let identities = identity::load_identity_file(&identity_path)?;
        if identities.is_empty() {
            return Err(Error::NoIdentity);
        }
        ResolvedKeys {
            age_keys: identities.iter().map(|i| i.to_public()).collect(),
            gpg: None,
        }
    } else {
        keyring::resolve(keys)?
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
pub fn cmd_add(force: bool, args: &[String]) -> Result<Outcome, Error> {
    let mut ctx = Context::load()?;
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
pub fn cmd_seal(force: bool, args: &[String]) -> Result<Outcome, Error> {
    let mut ctx = Context::load()?;
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
pub fn cmd_open(force: bool, args: &[String]) -> Result<Outcome, Error> {
    let mut ctx = Context::load()?;
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
pub fn cmd_close(args: &[String]) -> Result<Outcome, Error> {
    let mut ctx = Context::load()?;
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

const UNMERGED: &str = "unmerged; resolve the conflict and `git add` the file";

/// `git-amaga status` (plan 7.2): problems first; the caller exits 1 if `error_count` > 0.
pub fn cmd_status() -> Result<StatusReport, Error> {
    let ctx = Context::load_allowing_unmerged()?;
    let unmerged = git::unmerged_secrets(&ctx.root)?;
    let current = users::recipients(&ctx.members);

    let mut warnings = Vec::new();
    let mut statuses = Vec::new();
    let secrets = secret_paths_for(&ctx, &[], false, &mut warnings)?;
    for sp in &secrets {
        statuses.push(secret_status(&ctx, sp, &unmerged, &current)?);
    }
    // Unmerged files that are not listed above (deleted from the worktree, or invalid paths).
    for path in unmerged
        .iter()
        .filter(|p| !secrets.iter().any(|s| &s.ciphertext == *p))
    {
        statuses.push(SecretStatus {
            level: Level::Error,
            path: path.clone(),
            messages: vec![UNMERGED.into()],
        });
    }
    statuses.sort_by_key(|status| status.level);
    Ok(StatusReport {
        members: identity::member_summary(&ctx.members, false),
        secrets: statuses,
        warnings,
    })
}

// The messages of one secret. Undecryptable secrets report no state.
fn secret_status(
    ctx: &Context,
    sp: &paths::SecretPath,
    unmerged: &[String],
    current: &secret::Recipients,
) -> Result<SecretStatus, Error> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut ok = "in sync";
    let plaintext = &sp.plaintext;

    if !git::text_is_unset(&ctx.root, &sp.ciphertext)? {
        errors.push("`text` attribute is not unset; add `*.amaga binary` to .gitattributes".into());
    }
    if git::is_tracked(&ctx.root, plaintext)? {
        let fix = format!("run `git rm --cached -- {plaintext}`");
        errors.push(format!(
            "CRITICAL plaintext '{plaintext}' is tracked; {fix}"
        ));
    }
    if !git::is_ignored(&ctx.root, plaintext)? {
        let fix = "run `git-amaga seal` or `open`, or add it to .gitignore";
        errors.push(format!(
            "CRITICAL plaintext '{plaintext}' is not ignored; {fix}"
        ));
    }

    if unmerged.contains(&sp.ciphertext) {
        errors.push(UNMERGED.into());
    } else {
        let decrypted = read_repo_file(&ctx.root, &sp.ciphertext)
            .and_then(|ciphertext| ctx.decrypt(&sp.ciphertext, &ciphertext));
        match decrypted {
            Err(e) => errors.push(without_path(e)),
            Ok((header, body)) => {
                if key_set(&header.recipients) != key_set(current) {
                    errors.push("stale recipients; run git-amaga rotate".into());
                }
                if !header.exposed_to.is_empty() {
                    let names: Vec<&str> = header.exposed_to.keys().map(String::as_str).collect();
                    warnings.push(format!("NEEDS ROTATION: exposed to {}", names.join(", ")));
                }
                match read_plaintext(&ctx.root, plaintext) {
                    Err(e) => errors.push(e.to_string()),
                    Ok(local) => {
                        let base = ctx.base.get(plaintext).copied();
                        let state = secret::plaintext_state(local.as_deref(), &body, base);
                        if state == secret::PlaintextState::Closed {
                            ok = "closed";
                        }
                        errors.extend(state_problem(plaintext, state));
                    }
                }
            }
        }
    }

    let level = match (errors.is_empty(), warnings.is_empty()) {
        (false, _) => Level::Error,
        (true, false) => Level::Warn,
        (true, true) => Level::Ok,
    };
    errors.extend(warnings);
    if errors.is_empty() {
        errors.push(ok.into());
    }
    Ok(SecretStatus {
        level,
        path: sp.ciphertext.clone(),
        messages: errors,
    })
}

// The status line already starts with the secret's path; drop the copy inside the error.
fn without_path(e: Error) -> String {
    match e {
        Error::SecretUndecryptable {
            member: Some(member),
            source,
            ..
        } => format!("member {member}: {source}"),
        Error::SecretUndecryptable { source, .. } => source.to_string(),
        Error::IoPath { source, .. } => source.to_string(),
        Error::NotARegularFile(_) => "not a regular file".into(),
        e => e.to_string(),
    }
}

fn state_problem(plaintext: &str, state: secret::PlaintextState) -> Option<String> {
    let (what, fix) = match state {
        secret::PlaintextState::Closed | secret::PlaintextState::InSync => return None,
        secret::PlaintextState::Modified => ("has local edits", "run `git-amaga seal`"),
        secret::PlaintextState::Outdated => (
            "is outdated",
            "`git-amaga open` replaces it, `seal --force` keeps it",
        ),
        secret::PlaintextState::Conflict => (
            "conflicts with the repository",
            "`seal --force` keeps yours, `open --force` takes theirs",
        ),
    };
    Some(format!("'{plaintext}' {what}; {fix}"))
}

// Stale means a different set of keys; member names are only labels (plan 5.2).
fn key_set(recipients: &secret::Recipients) -> BTreeSet<&str> {
    recipients.values().flatten().map(String::as_str).collect()
}
