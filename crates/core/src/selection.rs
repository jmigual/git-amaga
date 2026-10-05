//! Which managed secrets a command acts on (plan 7).

use crate::context::Context;
use crate::files::read_repo_file;
use crate::outcome::Warning;
use crate::{Error, git, paths, secret};

// Explicit args must have a `.amaga`. No args: every existing managed secret in a partition that
// lists the actor, skipping invalid listed paths with a `Skipped` warning.
pub(crate) fn secret_paths_for(
    ctx: &Context,
    args: &[String],
    existing_plaintext_only: bool,
    warnings: &mut Vec<Warning>,
) -> Result<Vec<paths::SecretPath>, Error> {
    if !args.is_empty() {
        return args
            .iter()
            .map(|a| {
                let sp = paths::resolve_arg(&ctx.prefix, a)?;
                if !ctx.root.join(&sp.ciphertext).exists() {
                    return Err(Error::NotManagedSecret(sp.plaintext));
                }
                Ok(sp)
            })
            .collect();
    }
    let mut found = all_secret_paths(ctx, existing_plaintext_only, warnings)?;
    found.retain(|sp| !in_other_partition(ctx, sp));
    Ok(found)
}

// Every existing managed secret, whichever partition it is in (`status` lists them all).
pub(crate) fn all_secret_paths(
    ctx: &Context,
    existing_plaintext_only: bool,
    warnings: &mut Vec<Warning>,
) -> Result<Vec<paths::SecretPath>, Error> {
    let mut found = Vec::new();
    for entry in git::managed_secrets(&ctx.root)? {
        let ciphertext = match entry {
            Ok(path) => path,
            Err(path) => {
                let error = Error::PathNotUtf8(path.clone());
                warnings.push(Warning::Skipped { path, error });
                continue;
            }
        };
        if !ctx.root.join(&ciphertext).exists() {
            continue;
        }
        match paths::resolve_arg("", &ciphertext) {
            Ok(sp) if !existing_plaintext_only || ctx.root.join(&sp.plaintext).exists() => {
                found.push(sp)
            }
            Ok(_) => {}
            Err(error) => warnings.push(Warning::Skipped {
                path: ciphertext,
                error,
            }),
        }
    }
    Ok(found)
}

// A secret whose label names an existing partition that does not list the actor. An unreadable
// or unknown label is not left out, so the command reports it.
fn in_other_partition(ctx: &Context, sp: &paths::SecretPath) -> bool {
    read_repo_file(&ctx.root, &sp.ciphertext)
        .and_then(|bytes| secret::label_of(&sp.ciphertext, &bytes))
        .and_then(|label| ctx.in_partition(&label))
        .is_ok_and(|member| !member)
}
