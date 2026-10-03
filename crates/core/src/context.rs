use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::epoch::{self, Epoch};
use crate::outcome::Warning;
use crate::{Error, audit, git, gpg, identity, paths, secret, users};

// Per-command state: repo, membership, actor identities and base hashes (plan 5.5), and the
// epochs unwrapped so far (plan 5.6).
pub(crate) struct Context {
    pub(crate) root: PathBuf,
    pub(crate) prefix: String,
    pub(crate) actor: String,
    pub(crate) members: users::Members,
    pub(crate) age_identities: Vec<age::x25519::Identity>,
    pub(crate) gpg_fprs: Vec<String>,
    pub(crate) base_path: PathBuf,
    pub(crate) base: secret::BaseMap,
    current: age::x25519::Recipient,
    epochs: RefCell<BTreeMap<String, Rc<Epoch>>>,
    unreadable: RefCell<BTreeMap<String, Option<String>>>,
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
        let unmerged = git::unmerged_paths(&root, &["*.amaga"])?;
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
        let unmerged_epoch =
            git::unmerged_paths(&root, &[".amaga/current-epoch", ".amaga/epochs"])?;
        if !unmerged_epoch.is_empty() {
            return Err(Error::UnmergedEpoch(unmerged_epoch.join(", ")));
        }
        let members = users::load_tolerating(&root.join(".amaga/users"), tolerated)?;
        let current = epoch::read_pointer(&root)?;
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
            current,
            epochs: RefCell::default(),
            unreadable: RefCell::default(),
        })
    }

    // Unwraps epoch `id` once per command, success or failure (plan 5.6). `unreadable` keeps the
    // message of a real failure, and `None` for an epoch that is simply not wrapped to us.
    fn epoch(&self, id: &str) -> Result<Rc<Epoch>, Error> {
        if let Some(epoch) = self.epochs.borrow().get(id) {
            return Ok(Rc::clone(epoch));
        }
        let path = epoch::file_path(id);
        if let Some(failure) = self.unreadable.borrow().get(id) {
            return Err(match failure {
                Some(message) => Error::Io(io::Error::other(message.clone())),
                None => Error::EpochUndecryptable {
                    path,
                    member: None,
                    source: Box::new(Error::Decrypt(age::DecryptError::NoMatchingKeys)),
                },
            });
        }
        let gpg_identity = gpg::GpgIdentity::new(self.gpg_fprs.clone());
        // Age identities first, then gpg (plan 5.5).
        let mut identities: Vec<&dyn age::Identity> = self
            .age_identities
            .iter()
            .map(|i| i as &dyn age::Identity)
            .collect();
        identities.push(&gpg_identity);
        let unwrapped = read_repo_file(&self.root, &path)
            .and_then(|bytes| epoch::unwrap(id, &bytes, &identities))
            .map_err(|source| match source {
                Error::EpochInvalid(_) | Error::IoPath { .. } => source,
                source => Error::EpochUndecryptable {
                    path,
                    member: self.failing_member(&source),
                    source: Box::new(source),
                },
            });
        match unwrapped {
            Ok(epoch) => {
                let epoch = Rc::new(epoch);
                self.epochs
                    .borrow_mut()
                    .insert(id.to_string(), Rc::clone(&epoch));
                Ok(epoch)
            }
            Err(e) => {
                let message = (!is_not_a_recipient(&e)).then(|| e.to_string());
                self.unreadable.borrow_mut().insert(id.to_string(), message);
                Err(e)
            }
        }
    }

    /// Whether the current epoch is wrapped to exactly the keys in `.amaga/users` (plan 5.6).
    pub(crate) fn epoch_up_to_date(&self) -> Result<bool, Error> {
        let epoch = self.current_epoch()?;
        Ok(key_set(&epoch.members) == key_set(&users::recipients(&self.members)))
    }

    /// The guard of `add`, `seal`, `user add` and `dismiss`: [`Error::EpochStale`] unless up to date (plan 7).
    pub(crate) fn require_up_to_date(&self) -> Result<(), Error> {
        match self.epoch_up_to_date()? {
            true => Ok(()),
            false => Err(Error::EpochStale),
        }
    }

    /// The current epoch. A failure aborts the command (plan 5.6).
    pub(crate) fn current_epoch(&self) -> Result<Rc<Epoch>, Error> {
        self.epoch(&self.current.to_string())
    }

    // The current epoch first, then the others in name order (plan 5.6). Returns the header, the
    // body and the epoch that decrypted them.
    pub(crate) fn decrypt(
        &self,
        path: &str,
        ciphertext: &[u8],
    ) -> Result<(secret::Header, Vec<u8>, Rc<Epoch>), Error> {
        self.current_epoch()?;
        let current_id = self.current.to_string();
        let others = epoch::list(&self.root)?
            .into_iter()
            .filter(|id| *id != current_id);
        let undecryptable = |source| Error::SecretUndecryptable {
            path: path.to_string(),
            source: Box::new(source),
        };
        // The first reason an epoch could not be unwrapped, other than "not wrapped to us".
        let mut unwrap_failure = None;
        for id in std::iter::once(current_id.clone()).chain(others) {
            let epoch = match self.epoch(&id) {
                Ok(epoch) => epoch,
                Err(e) => {
                    if !is_not_a_recipient(&e) {
                        unwrap_failure.get_or_insert(e);
                    }
                    continue;
                }
            };
            match open_with(ciphertext, &epoch) {
                Ok(Some((header, body))) => return Ok((header, body, epoch)),
                Ok(None) => {}
                Err(e) => return Err(undecryptable(e)),
            }
        }
        Err(unwrap_failure
            .unwrap_or_else(|| undecryptable(Error::Decrypt(age::DecryptError::NoMatchingKeys))))
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

    /// Encrypts to the current epoch's public key; needs no unwrap (plan 7).
    pub(crate) fn encrypt(&self, header: &secret::Header, body: &[u8]) -> Result<Vec<u8>, Error> {
        secret::encrypt(header, body, &[&self.current as &dyn age::Recipient])
    }

    /// Wraps `epoch` to every member key and writes its file (plan 5.6).
    pub(crate) fn write_epoch(&self, epoch: &Epoch) -> Result<(), Error> {
        write_epoch(&self.root, &self.members, epoch)
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

// Stale means a different set of keys; member names are only labels (plan 5.2).
fn key_set(recipients: &secret::Recipients) -> BTreeSet<&str> {
    recipients.values().flatten().map(String::as_str).collect()
}

// An epoch file with no stanza for our keys (no gpg was run), as opposed to a failure to unwrap.
fn is_not_a_recipient(err: &Error) -> bool {
    matches!(
        err,
        Error::EpochUndecryptable { source, .. }
            if matches!(**source, Error::Decrypt(age::DecryptError::NoMatchingKeys))
    )
}

// `None`: the epoch's key does not open the file.
fn open_with(ciphertext: &[u8], epoch: &Epoch) -> Result<Option<(secret::Header, Vec<u8>)>, Error> {
    match secret::decrypt(ciphertext, &[epoch.identity() as &dyn age::Identity]) {
        Ok(found) => Ok(Some(found)),
        Err(Error::Decrypt(age::DecryptError::NoMatchingKeys)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Wraps `epoch` to every key of `members`, X25519 and `pgp` stanzas, and writes its file.
pub(crate) fn write_epoch(
    root: &Path,
    members: &users::Members,
    epoch: &Epoch,
) -> Result<(), Error> {
    let pgp: Vec<gpg::PgpRecipient> = members
        .values()
        .filter_map(|m| m.asc.as_ref())
        .map(gpg::PgpRecipient::new)
        .collect();
    let recipients: Vec<&dyn age::Recipient> = members
        .values()
        .flat_map(|m| &m.age_keys)
        .map(|k| k as &dyn age::Recipient)
        .chain(pgp.iter().map(|r| r as &dyn age::Recipient))
        .collect();
    epoch::write(root, epoch, &recipients)
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
