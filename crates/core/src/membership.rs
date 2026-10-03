//! Re-encrypting partitions (plan 7.1): `rotate` here, and the membership commands.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::context::{Context, Decrypted, write_epoch};
use crate::epoch::Epoch;
use crate::files::{read_repo_file, write_repo_file};
use crate::keyring::GpgKey;
use crate::outcome::{Reencrypted, Rotation, Warning};
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

/// `git-amaga rotate [--partition <p>]…` (plan 7): re-encrypts the named partitions, or every
/// partition that lists the actor; also finishes an interrupted run.
pub fn cmd_rotate(dir: &Path, partitions: &[String]) -> Result<Rotation, Error> {
    let mut ctx = Context::load(dir)?;
    let mut warnings = Vec::new();
    let selected: BTreeSet<String> = if partitions.is_empty() {
        let (mine, others) = actor_partitions(&ctx, |_| true);
        warnings.extend(others.into_iter().map(Warning::PartitionNotRotated));
        mine
    } else {
        for p in partitions {
            ctx.require_member(p)?;
        }
        partitions.iter().cloned().collect()
    };
    let written = reencrypt(&mut ctx, &selected, |_| Ok(()))?;
    for p in &selected {
        ctx.audit_partition("rotated", p, None)?;
    }
    Ok(Rotation { written, warnings })
}

// The partitions accepted by `wanted` that list the actor, and those that do not.
fn actor_partitions(
    ctx: &Context,
    wanted: impl Fn(&partition::Partition) -> bool,
) -> (BTreeSet<String>, Vec<String>) {
    let (mut mine, mut others) = (BTreeSet::new(), Vec::new());
    for (p, partition) in ctx.partitions.iter().filter(|(_, p)| wanted(p)) {
        match partition.members.contains(&ctx.actor) {
            true => mine.insert(p.clone()),
            false => {
                others.push(p.clone());
                false
            }
        };
    }
    (mine, others)
}

/// `git-amaga partition create <p> <member>…` (plan 7): a new partition with a new epoch wrapped
/// to the members. The actor need not be listed.
pub fn cmd_partition_create(dir: &Path, name: &str, members: &[String]) -> Result<(), Error> {
    if !users::valid_name(name) {
        return Err(Error::InvalidPartitionName(name.to_string()));
    }
    let ctx = Context::load(dir)?;
    if ctx.partitions.contains_key(name) {
        return Err(Error::PartitionExists(name.to_string()));
    }
    let listed: BTreeSet<String> = members.iter().cloned().collect();
    if listed.is_empty() {
        return Err(Error::PartitionInvalid(format!(
            "{name}: needs at least one member"
        )));
    }
    if let Some(unknown) = listed.iter().find(|m| !ctx.members.contains_key(*m)) {
        return Err(Error::UserNotFound(unknown.clone()));
    }
    let (wrapped_to, _) = users::select(&ctx.members, &listed);
    let epoch = Epoch::generate(users::recipients(&wrapped_to));
    write_epoch(&ctx.root, &wrapped_to, &epoch)?;
    partition::write_members(&ctx.root, name, &listed)?;
    partition::write_pointer(&ctx.root, name, &epoch.id())?;
    ctx.audit_partition("partition.created", name, None)?;
    for member in &listed {
        ctx.audit_partition("partition.member_added", name, Some(member))?;
    }
    Ok(())
}

// The grant sequence (plan 7): list `names`, who must be users, in partition `p`, audit each, then
// re-wrap `p`'s current epoch (same key) to its members. No secret is rewritten.
fn grant(ctx: &mut Context, p: &str, names: &[String]) -> Result<(), Error> {
    let partition = ctx
        .partitions
        .get_mut(p)
        .ok_or_else(|| Error::UnknownPartition(p.to_string()))?;
    partition.members.extend(names.iter().cloned());
    partition::write_members(&ctx.root, p, &partition.members)?;
    for name in names {
        ctx.audit_partition("partition.member_added", p, Some(name))?;
    }
    let members = users::recipients(&ctx.partition_members(p)?);
    let epoch = ctx.current_epoch(p)?.with_members(members);
    ctx.write_epoch(p, &epoch)
}

/// `git-amaga partition add <p> <member>…` (plan 7): re-wraps `p`'s current epoch to the new
/// members. No secret is rewritten.
pub fn cmd_partition_add(dir: &Path, name: &str, members: &[String]) -> Result<(), Error> {
    let mut ctx = Context::load(dir)?;
    ctx.require_member(name)?;
    let listed = &ctx.partition(name)?.members;
    let mut added = Vec::new();
    for member in members {
        if !ctx.members.contains_key(member) {
            return Err(Error::UserNotFound(member.clone()));
        }
        if listed.contains(member) {
            return Err(Error::AlreadyInPartition {
                user: member.clone(),
                partition: name.to_string(),
            });
        }
        if !added.contains(member) {
            added.push(member.clone());
        }
    }
    ctx.require_up_to_date(name)?;
    grant(&mut ctx, name, &added)
}

/// `git-amaga partition remove <p> <member>…` (plan 7): re-encrypts `p`'s secrets under a new
/// epoch without them. Removing oneself is allowed; the last member cannot be removed.
pub fn cmd_partition_remove(dir: &Path, name: &str, members: &[String]) -> Result<Rotation, Error> {
    let mut ctx = Context::load(dir)?;
    ctx.require_member(name)?;
    let listed = &ctx.partition(name)?.members;
    if let Some(unlisted) = members.iter().find(|m| !listed.contains(*m)) {
        return Err(Error::NotAPartitionMember {
            user: unlisted.clone(),
            partition: name.to_string(),
        });
    }
    let stays = listed
        .iter()
        .any(|m| !members.contains(m) && ctx.members.contains_key(m));
    if !stays {
        return Err(Error::LastMember {
            user: members.join(", "),
            partition: name.to_string(),
        });
    }

    let selected = BTreeSet::from([name.to_string()]);
    let written = reencrypt(&mut ctx, &selected, |ctx| {
        let partition = ctx
            .partitions
            .get_mut(name)
            .ok_or_else(|| Error::UnknownPartition(name.to_string()))?;
        for member in members {
            partition.members.remove(member);
        }
        partition::write_members(&ctx.root, name, &partition.members)?;
        for member in members {
            ctx.audit_partition("partition.member_removed", name, Some(member))?;
        }
        Ok(())
    })?;
    Ok(Rotation {
        written,
        warnings: Vec::new(),
    })
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
    grant(&mut ctx, partition::DEFAULT, &[name.to_string()])?;
    Ok(resolved.gpg)
}

/// `git-amaga user remove <name>` (plan 7): the member's own files need not be valid.
pub fn cmd_user_remove(dir: &Path, name: &str) -> Result<Rotation, Error> {
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

    let (selected, others) = actor_partitions(&ctx, |p| p.members.contains(name));
    let warnings = others
        .into_iter()
        .map(Warning::PartitionNotRotated)
        .collect();
    let written = reencrypt(&mut ctx, &selected, |ctx| {
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
    })?;
    Ok(Rotation { written, warnings })
}

// The existing user files of member `name`: `<name>.txt` and `<name>.asc`.
fn member_files(users_dir: &Path, name: &str) -> impl Iterator<Item = PathBuf> {
    ["txt", "asc"]
        .map(|ext| users_dir.join(format!("{name}.{ext}")))
        .into_iter()
        .filter(|path| path.exists())
}
