//! Re-encrypting partitions (plan 7.1): `rotate` here, and the membership commands.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::context::{Context, Decrypted};
use crate::epoch::Epoch;
use crate::files::{read_repo_file, write_repo_file};
use crate::keyring::GpgKey;
use crate::outcome::Reencrypted;
use crate::{Error, git, keyring, partition, secret, users};

/// Plan 7.1 for the partitions `selected`: decrypts every secret labelled with one of them first
/// and writes nothing if any fails, then runs `change` (the membership change and its audit
/// event, for `user remove`; it may update `ctx.members` and `ctx.partitions`), then writes a new
/// epoch per partition, rewrites each secret under its partition's epoch, in order, and moves the
/// pointers last.
pub(crate) fn reencrypt(
    ctx: &mut Context,
    selected: &BTreeSet<String>,
    change: impl FnOnce(&mut Context) -> Result<(), Error>,
) -> Result<Vec<Reencrypted>, Error> {
    let mut failures = Vec::new();
    let mut targets = Vec::new();
    for path in git::managed_secrets(&ctx.root)? {
        if !ctx.root.join(&path).exists() {
            continue;
        }
        let read = read_repo_file(&ctx.root, &path).and_then(|bytes| {
            let label = secret::label_of(&path, &bytes)?;
            Ok((bytes, label))
        });
        match read {
            Ok((bytes, label)) if selected.contains(&label) => targets.push((path, bytes, label)),
            Ok(_) => {}
            Err(e) => failures.push(e.to_string()),
        }
    }
    // A current epoch that cannot be unwrapped aborts instead of failing every secret.
    let used: BTreeSet<&str> = targets.iter().map(|(.., label)| label.as_str()).collect();
    for p in used {
        ctx.current_epoch(p)?;
    }
    let mut decrypted = Vec::new();
    for (path, bytes, _) in targets {
        match ctx.decrypt(&path, &bytes) {
            Ok(found) => decrypted.push((path, found)),
            Err(e) => failures.push(e.to_string()),
        }
    }
    if !failures.is_empty() {
        return Err(Error::ReencryptAborted(failures.join("\n")));
    }

    change(ctx)?;

    let mut epochs = BTreeMap::new();
    for p in selected {
        let epoch = Epoch::generate(users::recipients(&ctx.partition_members(p)?));
        ctx.write_epoch(p, &epoch)?;
        epochs.insert(p.as_str(), epoch);
    }
    let mut written = Vec::new();
    for (
        path,
        Decrypted {
            header: old_header,
            body,
            epoch: old_epoch,
            partition: p,
        },
    ) in decrypted
    {
        let epoch = &epochs[p.as_str()];
        let header = secret::next_header(
            Some((&old_header, &old_epoch.members)),
            false,
            &epoch.members,
        );
        let (recipient, label) = (epoch.recipient(), secret::Label::new(&p)?);
        let ciphertext = secret::encrypt(
            &header,
            &body,
            &[
                &recipient as &dyn age::Recipient,
                &label as &dyn age::Recipient,
            ],
        )?;
        write_repo_file(&ctx.root, &path, &ciphertext, None)?;
        written.push(Reencrypted {
            path,
            exposed_to: header.exposed_to.keys().cloned().collect(),
        });
    }
    for (p, epoch) in &epochs {
        partition::write_pointer(&ctx.root, p, &epoch.id())?;
    }
    Ok(written)
}

/// `git-amaga rotate` (plan 7): re-encrypts everything; also finishes an interrupted run.
pub fn cmd_rotate(dir: &Path) -> Result<Vec<Reencrypted>, Error> {
    let mut ctx = Context::load(dir)?;
    let all = ctx.partitions.keys().cloned().collect();
    let written = reencrypt(&mut ctx, &all, |_| Ok(()))?;
    ctx.audit_event("rotated", None, None)?;
    Ok(written)
}

/// `git-amaga user add <name> <KEY>…` (plan 7): validates the keys, then re-wraps the current epoch
/// to the members including the newcomer. No secret is rewritten (ADR-0015). Returns the new
/// member's GPG key, if any.
pub fn cmd_user_add(dir: &Path, name: &str, keys: &[String]) -> Result<Option<GpgKey>, Error> {
    if !users::valid_name(name) {
        return Err(Error::InvalidMemberName(name.to_string()));
    }
    let mut ctx = Context::load(dir)?;
    let users_dir = ctx.root.join(".amaga/users");
    if member_files(&users_dir, name).next().is_some() {
        return Err(Error::UserExists(name.to_string()));
    }
    ctx.require_up_to_date(partition::DEFAULT)?;
    let resolved = keyring::resolve(dir, keys)?;
    ctx.members
        .insert(name.to_string(), users::member_from_keys(&resolved));
    users::check(&ctx.members, None)?;

    users::write_member(&users_dir, name, &resolved)?;
    let gpg = resolved
        .gpg
        .as_ref()
        .map(|k| (k.fpr.as_str(), k.uid.as_str()));
    ctx.audit_event("user.added", Some(name), gpg)?;
    let listed = &mut ctx
        .partitions
        .get_mut(partition::DEFAULT)
        .expect("`default` is checked on load")
        .members;
    listed.insert(name.to_string());
    partition::write_members(&ctx.root, partition::DEFAULT, listed)?;
    let epoch = ctx
        .current_epoch(partition::DEFAULT)?
        .with_members(users::recipients(
            &ctx.partition_members(partition::DEFAULT)?,
        ));
    ctx.write_epoch(partition::DEFAULT, &epoch)?;
    Ok(resolved.gpg)
}

/// `git-amaga user remove <name>` (plan 7): the member's own files need not be valid.
pub fn cmd_user_remove(dir: &Path, name: &str) -> Result<Vec<Reencrypted>, Error> {
    if !users::valid_name(name) {
        return Err(Error::InvalidMemberName(name.to_string()));
    }
    let mut ctx = Context::load_for_removal(dir, name)?;
    let files: Vec<PathBuf> = member_files(&ctx.root.join(".amaga/users"), name).collect();
    if files.is_empty() && !ctx.partitions.values().any(|p| p.members.contains(name)) {
        return Err(Error::UserNotFound(name.to_string()));
    }
    for (p, partition) in &ctx.partitions {
        let only_member = partition.members.contains(name)
            && !partition
                .members
                .iter()
                .any(|m| m != name && ctx.members.contains_key(m));
        if only_member {
            return Err(Error::LastMember {
                user: name.to_string(),
                partition: p.clone(),
            });
        }
    }

    let all = ctx.partitions.keys().cloned().collect();
    reencrypt(&mut ctx, &all, |ctx| {
        for (p, partition) in &mut ctx.partitions {
            if partition.members.remove(name) {
                partition::write_members(&ctx.root, p, &partition.members)?;
            }
        }
        for file in &files {
            fs::remove_file(file)?;
        }
        ctx.members.remove(name);
        ctx.audit_event("user.removed", Some(name), None)
    })
}

// The existing user files of member `name`: `<name>.txt` and `<name>.asc`.
fn member_files(users_dir: &Path, name: &str) -> impl Iterator<Item = PathBuf> {
    ["txt", "asc"]
        .map(|ext| users_dir.join(format!("{name}.{ext}")))
        .into_iter()
        .filter(|path| path.exists())
}
