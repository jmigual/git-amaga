//! `git-amaga remove` (plan 7).

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::context::Context;
use crate::files::{read_plaintext, read_repo_file};
use crate::outcome::Outcome;
use crate::selection::secret_paths_for;
use crate::{Error, secret};

/// `git-amaga remove <path>…` (plan 7): deletes the `.amaga` file only. The plaintext and its
/// ignore entry stay (ADR-0011), so the plaintext must be open and in sync: it is then the copy
/// the user keeps, even if the `.amaga` was never committed.
pub fn cmd_remove(dir: &Path, args: &[String]) -> Result<Outcome, Error> {
    // `secret_paths_for` treats no paths as "every secret".
    if args.is_empty() {
        return Err(Error::NoPaths);
    }
    let mut ctx = Context::load(dir)?;
    let mut outcome = Outcome::default();

    // Everything is checked up front, so one bad path removes nothing.
    let mut seen = BTreeSet::new();
    let mut targets = secret_paths_for(&ctx, args, false, &mut outcome.warnings)?;
    targets.retain(|sp| seen.insert(sp.ciphertext.clone()));
    for sp in &targets {
        let body = read_repo_file(&ctx.root, &sp.ciphertext)
            .and_then(|ciphertext| ctx.decrypt(&sp.ciphertext, &ciphertext))
            .map(|decrypted| decrypted.body)
            .map_err(|source| Error::RemoveUnreadable {
                path: sp.ciphertext.clone(),
                source: Box::new(source),
            })?;
        let local = read_plaintext(&ctx.root, &sp.plaintext)?;
        let base = ctx.base.get(&sp.plaintext).copied();
        let state = secret::plaintext_state(local.as_deref(), &body, base);
        if state != secret::PlaintextState::InSync {
            return Err(Error::RemoveRefused(sp.plaintext.clone(), state));
        }
    }

    for sp in targets {
        fs::remove_file(ctx.root.join(&sp.ciphertext)).map_err(|source| Error::IoPath {
            path: sp.ciphertext.clone(),
            source,
        })?;
        ctx.drop_base(&sp.plaintext)?;
        ctx.audit("secret.removed", &sp.plaintext)?;
        outcome.changed.push(sp.ciphertext);
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_paths_is_refused_before_anything_is_loaded() {
        assert!(matches!(
            cmd_remove(Path::new("."), &[]),
            Err(Error::NoPaths)
        ));
    }
}
