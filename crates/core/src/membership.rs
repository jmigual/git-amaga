//! Re-encrypting every secret (plan 7.1): `rotate` here, and the membership commands.

use std::fs;
use std::path::{Path, PathBuf};

use crate::context::{Context, read_repo_file, write_repo_file};
use crate::keyring::GpgKey;
use crate::outcome::Reencrypted;
use crate::{Error, git, keyring, secret, users};

/// Plan 7.1: decrypts every secret first and writes nothing if any fails, then runs `change` (the
/// membership change and its audit event, for `user add`/`user remove`; it may update
/// `ctx.members`), then rewrites each secret for the current members, in order.
pub(crate) fn reencrypt_all(
    ctx: &mut Context,
    change: impl FnOnce(&mut Context) -> Result<(), Error>,
) -> Result<Vec<Reencrypted>, Error> {
    let mut decrypted = Vec::new();
    let mut failures = Vec::new();
    for path in git::managed_secrets(&ctx.root)? {
        if !ctx.root.join(&path).exists() {
            continue;
        }
        match read_repo_file(&ctx.root, &path).and_then(|bytes| ctx.decrypt(&path, &bytes)) {
            Ok((header, body)) => decrypted.push((path, header, body)),
            Err(e) => failures.push(e.to_string()),
        }
    }
    if !failures.is_empty() {
        return Err(Error::ReencryptAborted(failures.join("\n")));
    }

    change(ctx)?;

    let current = users::recipients(&ctx.members);
    let mut written = Vec::new();
    for (path, old_header, body) in decrypted {
        let header = secret::next_header(Some(&old_header), false, &current);
        let ciphertext = ctx.encrypt(&header, &body)?;
        write_repo_file(&ctx.root, &path, &ciphertext, None)?;
        written.push(Reencrypted {
            path,
            exposed_to: header.exposed_to.keys().cloned().collect(),
        });
    }
    Ok(written)
}

/// `git-amaga rotate` (plan 7): re-encrypts everything; also finishes an interrupted run.
pub fn cmd_rotate() -> Result<Vec<Reencrypted>, Error> {
    let mut ctx = Context::load()?;
    let written = reencrypt_all(&mut ctx, |_| Ok(()))?;
    ctx.audit_event("rotated", None, None)?;
    Ok(written)
}

/// `git-amaga user add <name> <KEY>…` (plan 7): validates the keys, then re-encrypts everything.
/// Returns the new member's GPG key, if any, and the rewritten secrets.
pub fn cmd_user_add(
    name: &str,
    keys: &[String],
) -> Result<(Option<GpgKey>, Vec<Reencrypted>), Error> {
    if !users::valid_name(name) {
        return Err(Error::InvalidMemberName(name.to_string()));
    }
    let mut ctx = Context::load()?;
    let users_dir = ctx.root.join(".amaga/users");
    if member_files(&users_dir, name).next().is_some() {
        return Err(Error::UserExists(name.to_string()));
    }
    let resolved = keyring::resolve(keys)?;
    // Checked before anything is written; decrypting does not depend on the member list.
    ctx.members
        .insert(name.to_string(), users::member_from_keys(&resolved));
    users::check(&ctx.members, None)?;

    let written = reencrypt_all(&mut ctx, |ctx| {
        users::write_member(&users_dir, name, &resolved)?;
        let gpg = resolved
            .gpg
            .as_ref()
            .map(|k| (k.fpr.as_str(), k.uid.as_str()));
        ctx.audit_event("user.added", Some(name), gpg)
    })?;
    Ok((resolved.gpg, written))
}

/// `git-amaga user remove <name>` (plan 7): the member's own files need not be valid.
pub fn cmd_user_remove(name: &str) -> Result<Vec<Reencrypted>, Error> {
    if !users::valid_name(name) {
        return Err(Error::InvalidMemberName(name.to_string()));
    }
    let mut ctx = Context::load_for_removal(name)?;
    let files: Vec<PathBuf> = member_files(&ctx.root.join(".amaga/users"), name).collect();
    if files.is_empty() {
        return Err(Error::UserNotFound(name.to_string()));
    }
    if ctx.members.keys().all(|member| member == name) {
        return Err(Error::LastMember(name.to_string()));
    }

    reencrypt_all(&mut ctx, |ctx| {
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
