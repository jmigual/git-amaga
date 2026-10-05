//! `git-amaga import-git-crypt` (plan 7.5, ADR-0018). The pure helpers are in `gitcrypt.rs`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::context::Context;
use crate::files::{ensure_ignored, read_plaintext, read_repo_file, write_repo_file};
use crate::gitcrypt::{derive_name, filter_key, holders, strip_git_crypt};
use crate::keyring::{self, ResolvedKeys};
use crate::outcome::{Imported, Warning};
use crate::partition::DEFAULT;
use crate::partition_commands::{create_partition, grant};
use crate::secret::{self, Recipients};
use crate::users::{self, Members};
use crate::{Error, git, paths};

// The first bytes of a file that git-crypt has not decrypted.
const LOCKED: &[u8] = b"\0GITCRYPT\0";

struct ImportFile {
    sp: paths::SecretPath,
    bytes: Vec<u8>,
    key: String,
    tracked: bool,
}

// The new members, and the member names holding each git-crypt key.
struct MemberPlan {
    new_users: Vec<(String, ResolvedKeys)>,
    holders: BTreeMap<String, BTreeSet<String>>,
}

/// `git-amaga import-git-crypt [--name <FPR>=<name>]…` (plan 7.5): turns the files of an unlocked
/// git-crypt repository into secrets, and its key holders into members of partitions.
pub fn cmd_import_git_crypt(dir: &Path, names: &[String]) -> Result<Imported, Error> {
    let mut ctx = Context::load(dir)?;
    ctx.require_member(DEFAULT)?;
    ctx.require_up_to_date(DEFAULT)?;
    // A name that is not UTF-8 cannot be checked, so it counts as a secret.
    let has_secrets = git::managed_secrets(&ctx.root)?
        .iter()
        .any(|entry| match entry {
            Ok(path) => ctx.root.join(path).exists(),
            Err(_) => true,
        });
    if has_secrets {
        return Err(Error::ImportNotFresh);
    }
    let files = read_files(&ctx)?;
    let keys: BTreeSet<String> = files.iter().map(|f| f.key.clone()).collect();
    let partitions = partition_names(&ctx, &keys)?;
    let mut warnings = Vec::new();
    let plan = plan_members(&ctx, &keys, names, &mut warnings)?;

    for file in &files {
        ensure_ignored(&ctx.root, &file.sp.plaintext)?;
    }
    let members = write_members(&mut ctx, plan.new_users)?;
    let created = write_partitions(&mut ctx, &plan.holders, &partitions)?;
    let mut changed = Vec::new();
    for file in &files {
        let partition = &partitions[&file.key];
        let header = secret::next_header(None, false, &Recipients::new());
        let ciphertext = ctx.encrypt(partition, &header, &file.bytes)?;
        write_repo_file(&ctx.root, &file.sp.ciphertext, &ciphertext, None)?;
        ctx.set_base(&file.sp.plaintext, &file.bytes)?;
        ctx.audit("secret.added", &file.sp.plaintext)?;
        changed.push(file.sp.ciphertext.clone());
    }
    let tracked = files.iter().filter(|f| f.tracked);
    let plaintexts: Vec<&str> = tracked.map(|f| f.sp.plaintext.as_str()).collect();
    git::rm_cached(&ctx.root, &plaintexts)?;
    strip_attributes(&ctx)?;
    check_filters_gone(&ctx, &files)?;
    match fs::remove_dir_all(ctx.root.join(".git-crypt")) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(Error::IoPath {
                path: ".git-crypt".into(),
                source: e,
            });
        }
        _ => {}
    }
    warnings.push(Warning::GitCryptHistory);
    Ok(Imported {
        members,
        created,
        changed,
        warnings,
    })
}

// Checks 3 to 5 (plan 7.5): the tracked and untracked unignored files with a git-crypt filter,
// read from the working tree. An untracked one would otherwise be added in clear once the filter
// is gone.
fn read_files(ctx: &Context) -> Result<Vec<ImportFile>, Error> {
    let tracked = git::tracked_files(&ctx.root)?;
    let untracked = git::untracked_files(&ctx.root)?;
    let candidates: Vec<&str> = tracked
        .iter()
        .chain(&untracked)
        .map(String::as_str)
        .collect();
    let (mut files, mut locked) = (Vec::new(), Vec::new());
    for (path, _, value) in git::check_attr(&ctx.root, &["filter"], &candidates)? {
        let Some(key) = filter_key(&value) else {
            continue;
        };
        let sp = paths::resolve_arg("", &path)?;
        let bytes = read_repo_file(&ctx.root, &sp.plaintext)?;
        if ctx.root.join(&sp.ciphertext).exists() {
            return Err(Error::CiphertextExists(sp.ciphertext));
        }
        match bytes.starts_with(LOCKED) {
            true => locked.push(path),
            false => files.push(ImportFile {
                tracked: tracked.contains(&path),
                sp,
                bytes,
                key: key.to_string(),
            }),
        }
    }
    if files.is_empty() && locked.is_empty() {
        return Err(Error::NothingToImport);
    }
    if !locked.is_empty() {
        return Err(Error::GitCryptLocked(locked.join(", ")));
    }
    let changed = |listed: Vec<String>| {
        (files.iter())
            .map(|f| f.sp.plaintext.as_str())
            .filter(|path| listed.iter().any(|s| s == path))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let staged = changed(git::staged_paths(&ctx.root)?);
    if !staged.is_empty() {
        return Err(Error::ImportStagedChanges(staged));
    }
    let unstaged = changed(git::unstaged_paths(&ctx.root)?);
    if !unstaged.is_empty() {
        return Err(Error::ImportUnstagedChanges(unstaged));
    }
    Ok(files)
}

// Check 6: git-crypt key -> partition name (the lowercased key).
fn partition_names(
    ctx: &Context,
    keys: &BTreeSet<String>,
) -> Result<BTreeMap<String, String>, Error> {
    let mut key_of_name: BTreeMap<String, &String> = BTreeMap::new();
    for key in keys {
        let name = key.to_lowercase();
        if !users::valid_name(&name) {
            return Err(Error::InvalidPartitionName(name));
        }
        if let Some(other) = key_of_name.insert(name.clone(), key) {
            let both = format!("{name} (git-crypt keys {other} and {key})");
            return Err(Error::InvalidPartitionName(both));
        }
        if name != DEFAULT && ctx.partitions.contains_key(&name) {
            return Err(Error::PartitionExists(name));
        }
    }
    Ok(key_of_name
        .into_iter()
        .map(|(name, key)| (key.clone(), name))
        .collect())
}

// Checks 7 and 8: who holds each key, which holders become new members, under what names.
fn plan_members(
    ctx: &Context,
    keys: &BTreeSet<String>,
    names: &[String],
    warnings: &mut Vec<Warning>,
) -> Result<MemberPlan, Error> {
    let keys_dir = ctx.root.join(".git-crypt/keys");
    let mut fprs_of = BTreeMap::new();
    let mut all = BTreeSet::new();
    for key in keys {
        let (fprs, skipped) = holders(&keys_dir, key)?;
        for name in skipped {
            warnings.push(Warning::KeySkipped {
                fpr: name.clone(),
                error: Error::ImportBadHolderName(name),
            });
        }
        all.extend(fprs.iter().cloned());
        fprs_of.insert(key, fprs);
    }
    let chosen = parse_names(ctx, names, &all)?;

    // A name a partition still lists would give the new member that partition's access.
    let listed = ctx.partitions.values().flat_map(|p| &p.members);
    let mut taken: BTreeSet<String> = (ctx.members.keys().chain(chosen.values()).chain(listed))
        .cloned()
        .collect();
    let mut members = ctx.members.clone();
    let (mut member_of, mut new_users) = (BTreeMap::new(), Vec::new());
    for fpr in &all {
        if let Some(name) = member_with_key(&members, fpr) {
            member_of.insert(fpr, name);
            continue;
        }
        let resolved = match keyring::resolve(&ctx.root, std::slice::from_ref(fpr)) {
            Ok(resolved) => resolved,
            Err(error) => {
                warnings.push(Warning::KeySkipped {
                    fpr: fpr.clone(),
                    error,
                });
                continue;
            }
        };
        let gpg = resolved
            .gpg
            .as_ref()
            .expect("a fingerprint resolves to a gpg key");
        if let Some(name) = member_with_key(&members, &gpg.fpr) {
            member_of.insert(fpr, name);
            continue;
        }
        let name = chosen.get(fpr).cloned().unwrap_or_else(|| {
            let name = derive_name(&gpg.uid, fpr, &taken);
            taken.insert(name.clone());
            name
        });
        members.insert(name.clone(), users::member_from_keys(&resolved));
        member_of.insert(fpr, name.clone());
        new_users.push((name, resolved));
    }
    users::check(&members, None)?;

    let holders = fprs_of
        .into_iter()
        .map(|(key, fprs)| {
            let names = fprs.iter().filter_map(|f| member_of.get(f).cloned());
            (key.clone(), names.collect())
        })
        .collect();
    Ok(MemberPlan { new_users, holders })
}

// The `--name <FPR>=<name>` arguments: fingerprint -> name.
fn parse_names(
    ctx: &Context,
    args: &[String],
    holders: &BTreeSet<String>,
) -> Result<BTreeMap<String, String>, Error> {
    let mut chosen: BTreeMap<String, String> = BTreeMap::new();
    for arg in args {
        let (fpr, name) = arg
            .split_once('=')
            .ok_or_else(|| Error::ImportUnknownFingerprint(arg.clone()))?;
        let fpr = fpr.to_ascii_uppercase();
        if !holders.contains(&fpr) {
            return Err(Error::ImportUnknownFingerprint(fpr));
        }
        if !users::valid_name(name) {
            return Err(Error::InvalidMemberName(name.to_string()));
        }
        if ctx.members.contains_key(name) || chosen.values().any(|n| n == name) {
            return Err(Error::UserExists(name.to_string()));
        }
        if let Some(partition) = ctx.listing_partition(name) {
            return Err(Error::UserStillListed {
                user: name.to_string(),
                partition: partition.clone(),
            });
        }
        chosen.insert(fpr, name.to_string());
    }
    Ok(chosen)
}

// The member whose `.asc` has `fpr` as its primary key or one of its subkeys.
fn member_with_key(members: &Members, fpr: &str) -> Option<String> {
    members
        .iter()
        .find(|(_, member)| {
            member
                .asc
                .as_ref()
                .is_some_and(|a| a.primary_fpr() == fpr || a.subkey_fprs().iter().any(|s| s == fpr))
        })
        .map(|(name, _)| name.clone())
}

// Write step 2: the member files and `user.added` events; returns the new members' keys.
fn write_members(
    ctx: &mut Context,
    new_users: Vec<(String, ResolvedKeys)>,
) -> Result<Vec<(String, crate::GpgKey)>, Error> {
    let users_dir = ctx.root.join(".amaga/users");
    let mut written = Vec::new();
    for (name, mut resolved) in new_users {
        users::write_member(&users_dir, &name, &resolved)?;
        ctx.members
            .insert(name.clone(), users::member_from_keys(&resolved));
        let gpg = resolved
            .gpg
            .as_ref()
            .map(|k| (k.fpr.as_str(), k.uid.as_str()));
        ctx.audit_event("user.added", Some(&name), gpg)?;
        if let Some(key) = resolved.gpg.take() {
            written.push((name, key));
        }
    }
    Ok(written)
}

// Write step 3: `default` gains its new names, every other partition is created; returns those.
fn write_partitions(
    ctx: &mut Context,
    holders: &BTreeMap<String, BTreeSet<String>>,
    partitions: &BTreeMap<String, String>,
) -> Result<Vec<String>, Error> {
    let mut created = Vec::new();
    for (key, names) in holders {
        let name = &partitions[key];
        let mut listed = names.clone();
        listed.insert(ctx.actor.clone());
        if name == DEFAULT {
            let current = &ctx.partition(DEFAULT)?.members;
            let added: Vec<String> = listed.difference(current).cloned().collect();
            if !added.is_empty() {
                grant(ctx, DEFAULT, &added)?;
            }
        } else {
            create_partition(ctx, name, &listed)?;
            created.push(name.clone());
        }
    }
    Ok(created)
}

// Write step 6: drop the git-crypt tokens from every tracked `.gitattributes` outside
// `.git-crypt/`.
fn strip_attributes(ctx: &Context) -> Result<(), Error> {
    let tracked = git::tracked_matching(&ctx.root, &[".gitattributes", "*/.gitattributes"])?;
    for path in tracked.iter().filter(|p| !p.starts_with(".git-crypt/")) {
        let Some(bytes) = read_plaintext(&ctx.root, path)? else {
            continue;
        };
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        let stripped = strip_git_crypt(&text);
        if stripped != text {
            write_repo_file(&ctx.root, path, stripped.as_bytes(), None)?;
        }
    }
    Ok(())
}

// Write step 7: no imported path may still have a git-crypt filter or diff driver.
fn check_filters_gone(ctx: &Context, files: &[ImportFile]) -> Result<(), Error> {
    let paths: Vec<&str> = files
        .iter()
        .flat_map(|f| [f.sp.plaintext.as_str(), f.sp.ciphertext.as_str()])
        .collect();
    let attrs = git::check_attr(&ctx.root, &["filter", "diff"], &paths)?;
    let remaining: BTreeSet<&str> = attrs
        .iter()
        .filter(|(_, _, value)| value.starts_with("git-crypt"))
        .map(|(path, ..)| path.as_str())
        .collect();
    match remaining.is_empty() {
        true => Ok(()),
        false => Err(Error::GitCryptAttributeRemains(
            remaining.into_iter().collect::<Vec<_>>().join(", "),
        )),
    }
}
