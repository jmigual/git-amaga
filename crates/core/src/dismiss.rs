//! `git-amaga dismiss` (plan 7, ADR-0016).

use std::collections::BTreeSet;
use std::path::Path;

use crate::context::{Context, read_repo_file, secret_paths_for, write_repo_file};
use crate::outcome::Outcome;
use crate::secret::{self, Header, Recipients};
use crate::{Error, audit};

/// `git-amaga dismiss [--user <name>]… [<path>…]` (plan 7): clears `exposed_to` for `users` (all
/// members if empty) in the named secrets (all if none), without a plaintext change.
pub fn cmd_dismiss(dir: &Path, users: &[String], args: &[String]) -> Result<Outcome, Error> {
    if users.is_empty() && args.is_empty() {
        return Err(Error::DismissNoTarget);
    }
    let ctx = Context::load(dir)?;
    ctx.require_up_to_date()?;
    let mut outcome = Outcome::default();

    let mut seen = BTreeSet::new();
    let mut targets = secret_paths_for(&ctx, args, false, &mut outcome.warnings)?;
    targets.retain(|sp| seen.insert(sp.ciphertext.clone()));
    let mut decrypted = Vec::new();
    for sp in targets {
        let ciphertext = read_repo_file(&ctx.root, &sp.ciphertext)?;
        let (header, body, epoch) = ctx.decrypt(&sp.ciphertext, &ciphertext)?;
        decrypted.push((sp, header, body, epoch));
    }

    if let Some(unknown) = users.iter().find(|user| {
        !decrypted
            .iter()
            .any(|(_, header, ..)| header.exposed_to.contains_key(*user))
    }) {
        return Err(Error::NotExposed(unknown.clone()));
    }

    let current = ctx.current_epoch()?;
    for (sp, old_header, body, old_epoch) in decrypted {
        let names = selected(&old_header.exposed_to, users);
        if names.is_empty() {
            continue;
        }
        let header = dismissed_header(&old_header, &old_epoch.members, &current.members, &names);
        let ciphertext = ctx.encrypt(&header, &body)?;
        write_repo_file(&ctx.root, &sp.ciphertext, &ciphertext, None)?;
        for name in &names {
            audit::append(
                &ctx.root.join(".amaga/audit.jsonl"),
                &ctx.actor,
                "exposure.dismissed",
                Some(&sp.plaintext),
                Some(name),
                None,
            )?;
        }
        outcome.changed.push(sp.ciphertext);
    }
    Ok(outcome)
}

// The members of `exposed_to` to dismiss: `users` that are present, or all of them if none named.
fn selected(exposed_to: &Recipients, users: &[String]) -> Vec<String> {
    exposed_to
        .keys()
        .filter(|name| users.is_empty() || users.contains(name))
        .cloned()
        .collect()
}

// The exposure rule (plan 6.1) first, so an epoch change still adds its members; then the
// dismissed names go.
fn dismissed_header(
    old: &Header,
    old_members: &Recipients,
    new_members: &Recipients,
    names: &[String],
) -> Header {
    let mut header = secret::next_header(Some((old, old_members)), false, new_members);
    for name in names {
        header.exposed_to.remove(name);
    }
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipients(pairs: &[(&str, &str)]) -> Recipients {
        pairs
            .iter()
            .map(|(name, key)| (name.to_string(), BTreeSet::from([key.to_string()])))
            .collect()
    }

    #[test]
    fn no_target_is_refused_before_anything_is_loaded() {
        assert!(matches!(
            cmd_dismiss(Path::new("."), &[], &[]),
            Err(Error::DismissNoTarget)
        ));
    }

    #[test]
    fn no_user_selects_every_exposed_name() {
        let exposed = recipients(&[("bob", "k1"), ("carol", "k2")]);
        assert_eq!(selected(&exposed, &[]), ["bob", "carol"]);
    }

    #[test]
    fn named_users_are_selected_only_where_present() {
        let exposed = recipients(&[("bob", "k1"), ("carol", "k2")]);
        let users = ["bob".to_string(), "dave".to_string()];
        assert_eq!(selected(&exposed, &users), ["bob"]);
    }

    #[test]
    fn a_secret_under_an_older_epoch_keeps_the_exposure_its_epoch_change_adds() {
        let old = Header {
            v: secret::VERSION,
            exposed_to: recipients(&[("bob", "kb")]),
        };
        let old_members = recipients(&[("alice", "ka"), ("bob", "kb"), ("carol", "kc")]);
        let new_members = recipients(&[("alice", "ka")]);
        let header = dismissed_header(&old, &old_members, &new_members, &["bob".to_string()]);
        assert_eq!(header.exposed_to, recipients(&[("carol", "kc")]));
    }
}
