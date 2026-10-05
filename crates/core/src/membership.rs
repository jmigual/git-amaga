//! Re-encrypting partitions (plan 7.1): `rotate` here, and `user add`/`user remove`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::context::{Context, Decrypted};
use crate::epoch::Epoch;
use crate::files::{read_repo_file, write_repo_file};
use crate::keyring::GpgKey;
use crate::outcome::{Reencrypted, Rotation, Warning};
use crate::partition_commands::grant;
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
    for entry in git::managed_secrets(&ctx.root)? {
        // Its partition is unknown, so it might be one of `selected`'s.
        let path = match entry {
            Ok(path) => path,
            Err(path) => {
                failures.push(Error::PathNotUtf8(path).to_string());
                continue;
            }
        };
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

/// `git-amaga user add [--partition <p>]… <name> <KEY>…` (plan 7): validates the keys, then
/// re-wraps the current epoch of each partition (default: `default`) to the members including the
/// newcomer. No secret is rewritten (ADR-0015). Returns the new member's GPG key, if any.
pub fn cmd_user_add(
    dir: &Path,
    name: &str,
    keys: &[String],
    partitions: &[String],
) -> Result<Option<GpgKey>, Error> {
    if !users::valid_name(name) {
        return Err(Error::InvalidMemberName(name.to_string()));
    }
    let mut ctx = Context::load(dir)?;
    let users_dir = ctx.root.join(".amaga/users");
    if member_files(&users_dir, name).next().is_some() {
        return Err(Error::UserExists(name.to_string()));
    }
    if let Some(partition) = ctx.listing_partition(name) {
        return Err(Error::UserStillListed {
            user: name.to_string(),
            partition: partition.clone(),
        });
    }
    let selected: BTreeSet<String> = match partitions.is_empty() {
        true => BTreeSet::from([partition::DEFAULT.to_string()]),
        false => partitions.iter().cloned().collect(),
    };
    for p in &selected {
        ctx.require_member(p)?;
        ctx.require_up_to_date(p)?;
    }
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
    for p in &selected {
        grant(&mut ctx, p, &[name.to_string()])?;
    }
    Ok(resolved.gpg)
}

/// `git-amaga user remove <name>` (plan 7): the member's own files need not be valid.
pub fn cmd_user_remove(dir: &Path, name: &str) -> Result<Rotation, Error> {
    if !users::valid_name(name) {
        return Err(Error::InvalidMemberName(name.to_string()));
    }
    let mut ctx = Context::load_for_removal(dir, name)?;
    let files: Vec<PathBuf> = member_files(&ctx.root.join(".amaga/users"), name).collect();
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

    let (selected, others) = removal_partitions(&ctx, name)?;
    // An interrupted run leaves no file and no listing, only a current epoch still wrapped to them.
    if files.is_empty() && selected.is_empty() && others.is_empty() {
        return Err(Error::UserNotFound(name.to_string()));
    }
    let written = reencrypt(&mut ctx, &selected, |ctx| {
        for (p, partition) in &mut ctx.partitions {
            if partition.members.remove(name) && !others.contains(p) {
                partition::write_members(&ctx.root, p, &partition.members)?;
            }
        }
        for file in &files {
            fs::remove_file(file).map_err(|source| Error::IoPath {
                path: file.display().to_string(),
                source,
            })?;
        }
        ctx.members.remove(name);
        ctx.audit_event("user.removed", Some(name), None)
    })?;
    // Unlisted last, so an interrupted run leaves them for the rerun to report (plan 7.1).
    for p in &others {
        partition::write_members(&ctx.root, p, &ctx.partitions[p].members)?;
    }
    let warnings = others
        .into_iter()
        .map(Warning::PartitionNotRotated)
        .collect();
    Ok(Rotation { written, warnings })
}

// The partitions `user remove` re-encrypts, and those it can only report. A partition that
// lists the actor is re-encrypted when it lists `name` or when its current epoch was wrapped to
// `name` (or any of their keys), so a rerun after an interruption or a hand edit of `members`
// still locks them out. Others are reported when they list `name`.
fn removal_partitions(ctx: &Context, name: &str) -> Result<(BTreeSet<String>, Vec<String>), Error> {
    let keys = users::recipients(&ctx.members)
        .remove(name)
        .unwrap_or_default();
    let (mut selected, mut others) = (BTreeSet::new(), Vec::new());
    for (p, partition) in &ctx.partitions {
        let listed = partition.members.contains(name);
        if !partition.members.contains(&ctx.actor) {
            if listed {
                others.push(p.clone());
            }
            continue;
        }
        let wrapped = || {
            let epoch = ctx.current_epoch(p)?;
            let found = epoch
                .members
                .iter()
                .any(|(n, ks)| n == name || ks.iter().any(|k| keys.contains(k)));
            Ok::<_, Error>(found)
        };
        if listed || wrapped()? {
            selected.insert(p.clone());
        }
    }
    Ok((selected, others))
}

// The existing user files of member `name`: `<name>.txt` and `<name>.asc`.
fn member_files(users_dir: &Path, name: &str) -> impl Iterator<Item = PathBuf> {
    ["txt", "asc"]
        .map(|ext| users_dir.join(format!("{name}.{ext}")))
        .into_iter()
        .filter(|path| path.exists())
}
