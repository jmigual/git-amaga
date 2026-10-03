//! The `partition` commands (plan 7, ADR-0017).

use std::collections::BTreeSet;
use std::path::Path;

use crate::context::{Context, write_epoch};
use crate::epoch::Epoch;
use crate::files::{read_repo_file, write_repo_file};
use crate::membership::reencrypt;
use crate::outcome::{Outcome, Rotation};
use crate::partition::{self, Partition};
use crate::selection::secret_paths_for;
use crate::{Error, audit, secret, users};

/// `git-amaga partition create <p> <member>…` (plan 7): a new partition with a new epoch wrapped
/// to the members. The actor need not be listed.
pub fn cmd_partition_create(dir: &Path, name: &str, members: &[String]) -> Result<(), Error> {
    if !users::valid_name(name) {
        return Err(Error::InvalidPartitionName(name.to_string()));
    }
    let mut ctx = Context::load(dir)?;
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
    create_partition(&mut ctx, name, &listed)
}

// The create sequence (plan 7): a new epoch wrapped to `listed`, who must be users, then `members`,
// then `current-epoch` last, and the audit events.
pub(crate) fn create_partition(
    ctx: &mut Context,
    name: &str,
    listed: &BTreeSet<String>,
) -> Result<(), Error> {
    let (wrapped_to, _) = users::select(&ctx.members, listed);
    let epoch = Epoch::generate(users::recipients(&wrapped_to));
    write_epoch(&ctx.root, &wrapped_to, &epoch)?;
    partition::write_members(&ctx.root, name, listed)?;
    partition::write_pointer(&ctx.root, name, &epoch.id())?;
    ctx.partitions.insert(
        name.to_string(),
        Partition {
            members: listed.clone(),
            current: epoch.recipient(),
        },
    );
    ctx.audit_partition("partition.created", name, None)?;
    for member in listed {
        ctx.audit_partition("partition.member_added", name, Some(member))?;
    }
    Ok(())
}

// The grant sequence (plan 7): list `names`, who must be users, in partition `p`, audit each, then
// re-wrap `p`'s current epoch (same key) to its members. No secret is rewritten.
pub(crate) fn grant(ctx: &mut Context, p: &str, names: &[String]) -> Result<(), Error> {
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

/// `git-amaga partition move <p> <path>…` (plan 7): re-encrypts the secrets into `p`, flagging the
/// members of their old epoch that `p` lacks. Plaintext and base are never touched.
pub fn cmd_partition_move(dir: &Path, name: &str, args: &[String]) -> Result<Outcome, Error> {
    if args.is_empty() {
        return Err(Error::NoPaths);
    }
    let ctx = Context::load(dir)?;
    ctx.require_member(name)?;
    ctx.require_up_to_date(name)?;
    let mut outcome = Outcome::default();

    let mut seen = BTreeSet::new();
    let mut targets = secret_paths_for(&ctx, args, false, &mut outcome.warnings)?;
    targets.retain(|sp| seen.insert(sp.ciphertext.clone()));
    let mut moving = Vec::new();
    for sp in targets {
        let ciphertext = read_repo_file(&ctx.root, &sp.ciphertext)?;
        let found = ctx.decrypt(&sp.ciphertext, &ciphertext)?;
        if found.partition != name {
            moving.push((sp, found));
        }
    }

    for (sp, old) in moving {
        let current = ctx.current_epoch(name)?;
        let old_epoch = Some((&old.header, &old.epoch.members));
        let header = secret::next_header(old_epoch, false, &current.members);
        let ciphertext = ctx.encrypt(name, &header, &old.body)?;
        write_repo_file(&ctx.root, &sp.ciphertext, &ciphertext, None)?;
        audit::append(
            &ctx.root.join(".amaga/audit.jsonl"),
            &ctx.actor,
            "secret.moved",
            Some(&sp.plaintext),
            None,
            Some(name),
            None,
        )?;
        outcome.changed.push(sp.ciphertext);
    }
    Ok(outcome)
}
