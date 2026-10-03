use std::fs;
use std::path::{Path, PathBuf};

use crate::outcome::Warning;
use crate::{Error, audit, git, gpg, identity, paths, secret, users};

// Per-command state: repo, membership, actor identities and base hashes (plan 5.5).
pub(crate) struct Context {
    pub(crate) root: PathBuf,
    pub(crate) prefix: String,
    pub(crate) actor: String,
    pub(crate) members: users::Members,
    pub(crate) age_identities: Vec<age::x25519::Identity>,
    pub(crate) gpg_fprs: Vec<String>,
    pub(crate) base_path: PathBuf,
    pub(crate) base: secret::BaseMap,
}

impl Context {
    // Refuses while any `*.amaga` is unmerged (plan 7).
    pub(crate) fn load(dir: &Path) -> Result<Self, Error> {
        Self::load_refusing_unmerged(dir, None)
    }

    // Like `load`, but member `name`'s own files may be invalid (`user remove`, plan 7).
    pub(crate) fn load_for_removal(dir: &Path, name: &str) -> Result<Self, Error> {
        Self::load_refusing_unmerged(dir, Some(name))
    }

    fn load_refusing_unmerged(dir: &Path, tolerated: Option<&str>) -> Result<Self, Error> {
        let root = git::toplevel(dir)?;
        let unmerged = git::unmerged_secrets(&root)?;
        if !unmerged.is_empty() {
            return Err(Error::UnmergedAmagaFiles(unmerged.join(", ")));
        }
        Self::load_in(dir, root, tolerated)
    }

    // For `status`, which lists the unmerged files instead of refusing.
    pub(crate) fn load_allowing_unmerged(dir: &Path) -> Result<Self, Error> {
        Self::load_in(dir, git::toplevel(dir)?, None)
    }

    fn load_in(dir: &Path, root: PathBuf, tolerated: Option<&str>) -> Result<Self, Error> {
        let members = users::load_tolerating(&root.join(".amaga/users"), tolerated)?;
        let age_identities = match identity::configured_identity_path(dir)? {
            Some(path) => identity::load_identity_file(&path)?,
            None => Vec::new(),
        };
        let (actor, gpg_fprs) = identity::find_actor(&members, &age_identities, gpg::is_held)?;
        let base_path = git::git_path(dir, "amaga-base")?;
        Ok(Self {
            prefix: git::show_prefix(dir)?,
            base: secret::load_base(&base_path)?,
            base_path,
            root,
            actor,
            members,
            age_identities,
            gpg_fprs,
        })
    }

    // Age identities first, then gpg (plan 5.5).
    pub(crate) fn decrypt(
        &self,
        path: &str,
        ciphertext: &[u8],
    ) -> Result<(secret::Header, Vec<u8>), Error> {
        let gpg_identity = gpg::GpgIdentity::new(self.gpg_fprs.clone());
        let mut identities: Vec<&dyn age::Identity> = self
            .age_identities
            .iter()
            .map(|i| i as &dyn age::Identity)
            .collect();
        identities.push(&gpg_identity);
        secret::decrypt(ciphertext, &identities).map_err(|source| Error::SecretUndecryptable {
            path: path.to_string(),
            member: self.failing_member(&source),
            source: Box::new(source),
        })
    }

    pub(crate) fn failing_member(&self, err: &Error) -> Option<String> {
        let Error::Decrypt(age::DecryptError::Io(io)) = err else {
            return None;
        };
        let fpr = &io.get_ref()?.downcast_ref::<gpg::GpgError>()?.fpr;
        self.members
            .iter()
            .find(|(_, m)| {
                m.asc
                    .as_ref()
                    .is_some_and(|a| a.subkey_fprs().contains(fpr))
            })
            .map(|(name, _)| name.clone())
    }

    pub(crate) fn encrypt(&self, header: &secret::Header, body: &[u8]) -> Result<Vec<u8>, Error> {
        let pgp: Vec<gpg::PgpRecipient> = self
            .members
            .values()
            .filter_map(|m| m.asc.as_ref())
            .map(gpg::PgpRecipient::new)
            .collect();
        let recipients: Vec<&dyn age::Recipient> = self
            .members
            .values()
            .flat_map(|m| &m.age_keys)
            .map(|k| k as &dyn age::Recipient)
            .chain(pgp.iter().map(|r| r as &dyn age::Recipient))
            .collect();
        secret::encrypt(header, body, &recipients)
    }

    // Rewrites the base file only when the hash changes.
    pub(crate) fn set_base(&mut self, path: &str, body: &[u8]) -> Result<(), Error> {
        let hash = secret::hash(body);
        if self.base.insert(path.to_string(), hash) != Some(hash) {
            secret::save_base(&self.base_path, &self.base)?;
        }
        Ok(())
    }

    pub(crate) fn drop_base(&mut self, path: &str) -> Result<(), Error> {
        if self.base.remove(path).is_some() {
            secret::save_base(&self.base_path, &self.base)?;
        }
        Ok(())
    }

    pub(crate) fn audit(&self, event: &str, path: &str) -> Result<(), Error> {
        audit::append(
            &self.root.join(".amaga/audit.jsonl"),
            &self.actor,
            event,
            Some(path),
            None,
            None,
        )
    }

    // An event without a secret path: `rotated`, or `user.*` about `user` (plan 5.3).
    pub(crate) fn audit_event(
        &self,
        event: &str,
        user: Option<&str>,
        gpg: Option<(&str, &str)>,
    ) -> Result<(), Error> {
        audit::append(
            &self.root.join(".amaga/audit.jsonl"),
            &self.actor,
            event,
            None,
            user,
            gpg,
        )
    }
}

// Explicit args must have a `.amaga`. No args: every existing managed secret, skipping invalid
// listed paths with a `Skipped` warning.
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
    let mut found = Vec::new();
    for ciphertext in git::managed_secrets(&ctx.root)? {
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

// Regular files only: following a symlinked secret could decrypt, then re-encrypt, a file from
// another repository (plan 3).
pub(crate) fn read_repo_file(root: &Path, path: &str) -> Result<Vec<u8>, Error> {
    let full = root.join(path);
    let io_error = |source| Error::IoPath {
        path: path.to_string(),
        source,
    };
    if !fs::symlink_metadata(&full)
        .map_err(io_error)?
        .file_type()
        .is_file()
    {
        return Err(Error::NotARegularFile(path.to_string()));
    }
    fs::read(&full).map_err(io_error)
}

// `None` only when the plaintext does not exist; other read errors must not look like `Closed`.
pub(crate) fn read_plaintext(root: &Path, path: &str) -> Result<Option<Vec<u8>>, Error> {
    match read_repo_file(root, path) {
        Err(Error::IoPath { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            Ok(None)
        }
        other => other.map(Some),
    }
}

pub(crate) fn write_repo_file(
    root: &Path,
    path: &str,
    contents: &[u8],
    mode: Option<u32>,
) -> Result<(), Error> {
    paths::atomic_write(&root.join(path), contents, mode).map_err(|source| Error::IoPath {
        path: path.to_string(),
        source,
    })
}

pub(crate) fn ensure_ignored(root: &Path, path: &str) -> Result<(), Error> {
    if git::is_ignored(root, path)? {
        return Ok(());
    }
    paths::ensure_gitignore_line(&root.join(".gitignore"), &paths::gitignore_escape(path))?;
    if !git::is_ignored(root, path)? {
        return Err(Error::PlaintextNotIgnored(path.to_string()));
    }
    Ok(())
}
