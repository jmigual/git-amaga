//! `git-amaga status` (plan 7.2).

use std::path::Path;

use crate::context::{Context, read_plaintext, read_repo_file, secret_paths_for};
use crate::outcome::{Level, SecretStatus, StatusReport};
use crate::{Error, git, identity, paths, secret};

const UNMERGED: &str = "unmerged; resolve the conflict and `git add` the file";

/// `git-amaga status` (plan 7.2): problems first; the caller exits 1 if `error_count` > 0.
pub fn cmd_status(dir: &Path) -> Result<StatusReport, Error> {
    let ctx = Context::load_allowing_unmerged(dir)?;
    let unmerged = git::unmerged_secrets(&ctx.root)?;
    let up_to_date = ctx.epoch_up_to_date()?;

    let mut warnings = Vec::new();
    let mut statuses = Vec::new();
    let secrets = secret_paths_for(&ctx, &[], false, &mut warnings)?;
    for sp in &secrets {
        statuses.push(secret_status(&ctx, sp, &unmerged, up_to_date)?);
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
    up_to_date: bool,
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
            Ok((header, body, epoch)) => {
                if !up_to_date || epoch.id() != ctx.current_epoch()?.id() {
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
