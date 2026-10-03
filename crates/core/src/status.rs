//! `git-amaga status` (plan 7.2).

use std::path::Path;

use crate::context::{Context, Decrypted};
use crate::files::{read_plaintext, read_repo_file};
use crate::outcome::{Level, SecretStatus, StatusReport, Warning};
use crate::partition::DEFAULT;
use crate::selection::all_secret_paths;
use crate::{Error, git, identity, paths, secret, users};

const UNMERGED: &str = "unmerged; resolve the conflict and `git add` the file";

/// `git-amaga status` (plan 7.2): problems first; the caller exits 1 if `error_count` > 0.
pub fn cmd_status(dir: &Path) -> Result<StatusReport, Error> {
    let ctx = Context::load_allowing_unmerged(dir)?;
    let unmerged = git::unmerged_paths(&ctx.root, &["*.amaga"])?;

    let mut warnings = Vec::new();
    let mut partitions = Vec::new();
    for (p, partition) in &ctx.partitions {
        partitions.push((p.clone(), partition.members.iter().cloned().collect()));
        for name in users::select(&ctx.members, &partition.members).1 {
            warnings.push(Warning::UnknownMember {
                partition: p.clone(),
                name,
            });
        }
    }
    let mut statuses = Vec::new();
    let secrets = all_secret_paths(&ctx, false, &mut warnings)?;
    for sp in &secrets {
        statuses.push(secret_status(&ctx, sp, &unmerged)?);
    }
    // Unmerged files that are not listed above (deleted from the worktree, or invalid paths).
    for path in unmerged
        .iter()
        .filter(|p| !secrets.iter().any(|s| &s.ciphertext == *p))
    {
        statuses.push(SecretStatus {
            level: Level::Error,
            path: path.clone(),
            partition: String::new(),
            messages: vec![UNMERGED.into()],
        });
    }
    statuses.sort_by_key(|status| status.level);
    Ok(StatusReport {
        members: identity::member_summary(&ctx.members, false),
        partitions,
        secrets: statuses,
        warnings,
    })
}

// The messages of one secret. Undecryptable secrets report no state, and a secret of a partition
// that does not list the actor only gets the checks that need no key.
fn secret_status(
    ctx: &Context,
    sp: &paths::SecretPath,
    unmerged: &[String],
) -> Result<SecretStatus, Error> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut ok = "in sync";
    let mut partition = String::new();
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
        let read = read_repo_file(&ctx.root, &sp.ciphertext).and_then(|ciphertext| {
            let label = secret::label_of(&sp.ciphertext, &ciphertext)?;
            Ok((ciphertext, label))
        });
        match read {
            Err(e) => errors.push(without_path(e)),
            Ok((ciphertext, label)) => {
                partition = label;
                match ctx.in_partition(&partition) {
                    Err(e) => errors.push(e.to_string()),
                    Ok(false) => ok = "not a member",
                    Ok(true) => {
                        ok = decrypted_messages(ctx, sp, &ciphertext, &mut errors, &mut warnings);
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
        partition,
        messages: errors,
    })
}

// The checks that need the secret decrypted; returns the plain state when nothing is wrong.
fn decrypted_messages(
    ctx: &Context,
    sp: &paths::SecretPath,
    ciphertext: &[u8],
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> &'static str {
    let plaintext = &sp.plaintext;
    let mut ok = "in sync";
    match ctx.decrypt(&sp.ciphertext, ciphertext) {
        Err(e) => errors.push(without_path(e)),
        Ok(Decrypted {
            header,
            body,
            epoch,
            partition,
        }) => {
            match stale(ctx, &partition, &epoch.id()) {
                Ok(true) => {
                    let flag = match partition.as_str() {
                        DEFAULT => String::new(),
                        p => format!(" --partition {p}"),
                    };
                    errors.push(format!("stale recipients; run git-amaga rotate{flag}"));
                }
                Ok(false) => {}
                Err(e) => errors.push(e.to_string()),
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
    ok
}

// Whether the secret is under an older epoch, or its partition is not up to date (plan 5.7).
fn stale(ctx: &Context, partition: &str, epoch_id: &str) -> Result<bool, Error> {
    Ok(!ctx.epoch_up_to_date(partition)? || ctx.current_epoch(partition)?.id() != epoch_id)
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
