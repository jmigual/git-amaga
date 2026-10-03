use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::epoch::{self, Epoch};
use crate::failure::{EpochFailure, is_not_a_recipient};
use crate::files::read_repo_file;
use crate::partition::{self, Partition, Partitions};
use crate::{Error, audit, git, gpg, identity, paths, secret, users};

// Per-command state: repo, membership, partitions, actor identities and base hashes (plan 5.5),
// and the epochs unwrapped so far (plan 5.6).
pub(crate) struct Context {
    pub(crate) root: PathBuf,
    pub(crate) prefix: String,
    pub(crate) actor: String,
    pub(crate) members: users::Members,
    pub(crate) partitions: Partitions,
    pub(crate) age_identities: Vec<age::x25519::Identity>,
    pub(crate) gpg_fprs: Vec<String>,
    pub(crate) base_path: PathBuf,
    pub(crate) base: secret::BaseMap,
    epochs: RefCell<BTreeMap<String, Rc<Epoch>>>,
    failures: RefCell<BTreeMap<String, EpochFailure>>,
}

/// A decrypted secret: its header and body, the epoch that opened it and its partition.
pub(crate) struct Decrypted {
    pub(crate) header: secret::Header,
    pub(crate) body: Vec<u8>,
    pub(crate) epoch: Rc<Epoch>,
    pub(crate) partition: String,
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
        let unmerged_epoch = git::unmerged_paths(&root, &[".amaga/partitions", ".amaga/epochs"])?;
        if !unmerged_epoch.is_empty() {
            return Err(Error::UnmergedEpoch(unmerged_epoch.join(", ")));
        }
        let members = users::load_tolerating(&root.join(".amaga/users"), tolerated)?;
        let partitions = partition::load(&root, &members)?;
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
            partitions,
            age_identities,
            gpg_fprs,
            epochs: RefCell::default(),
            failures: RefCell::default(),
        })
    }

    /// Partition `p`, or [`Error::UnknownPartition`].
    pub(crate) fn partition(&self, p: &str) -> Result<&Partition, Error> {
        self.partitions
            .get(p)
            .ok_or_else(|| Error::UnknownPartition(p.to_string()))
    }

    /// Whether the actor is listed in partition `p` (plan 5.7).
    pub(crate) fn in_partition(&self, p: &str) -> Result<bool, Error> {
        Ok(self.partition(p)?.members.contains(&self.actor))
    }

    /// [`Error::NotInPartition`] unless the actor is listed in partition `p` (plan 7).
    pub(crate) fn require_member(&self, p: &str) -> Result<(), Error> {
        match self.in_partition(p)? {
            true => Ok(()),
            false => Err(Error::NotInPartition {
                partition: p.to_string(),
                path: None,
            }),
        }
    }

    /// The users that partition `p` lists; names that are not users are left out (plan 5.7).
    pub(crate) fn partition_members(&self, p: &str) -> Result<users::Members, Error> {
        Ok(users::select(&self.members, &self.partition(p)?.members).0)
    }

    // Unwraps epoch `id` once per command, success or failure (plan 5.6).
    fn epoch(&self, id: &str) -> Result<Rc<Epoch>, Error> {
        if let Some(epoch) = self.epochs.borrow().get(id) {
            return Ok(Rc::clone(epoch));
        }
        let path = epoch::file_path(id);
        if let Some(failure) = self.failures.borrow().get(id) {
            return Err(failure.error());
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
                let failure = EpochFailure::of(&epoch::file_path(id), &e);
                self.failures.borrow_mut().insert(id.to_string(), failure);
                Err(e)
            }
        }
    }

    /// Whether partition `p`'s current epoch is wrapped to exactly the keys of the users `p`
    /// lists (plan 5.7).
    pub(crate) fn epoch_up_to_date(&self, p: &str) -> Result<bool, Error> {
        let epoch = self.current_epoch(p)?;
        let keys = users::recipients(&self.partition_members(p)?);
        Ok(key_set(&epoch.members) == key_set(&keys))
    }

    /// The stale guard (plan 7): [`Error::EpochStale`] unless partition `p` is up to date.
    pub(crate) fn require_up_to_date(&self, p: &str) -> Result<(), Error> {
        match self.epoch_up_to_date(p)? {
            true => Ok(()),
            false => Err(Error::EpochStale(p.to_string())),
        }
    }

    /// The stale guard for every partition named by the labels of `secrets`.
    pub(crate) fn require_secrets_up_to_date(
        &self,
        secrets: &[paths::SecretPath],
    ) -> Result<(), Error> {
        let mut partitions = BTreeSet::new();
        for sp in secrets {
            let ciphertext = read_repo_file(&self.root, &sp.ciphertext)?;
            partitions.insert(secret::label_of(&sp.ciphertext, &ciphertext)?);
        }
        partitions
            .iter()
            .try_for_each(|p| self.require_up_to_date(p))
    }

    /// The current epoch of partition `p`. A failure aborts the command (plan 5.6).
    pub(crate) fn current_epoch(&self, p: &str) -> Result<Rc<Epoch>, Error> {
        self.epoch(&self.partition(p)?.current.to_string())
    }

    // The label's current epoch first, then the others in name order (plan 5.6).
    pub(crate) fn decrypt(&self, path: &str, ciphertext: &[u8]) -> Result<Decrypted, Error> {
        let partition = secret::label_of(path, ciphertext)?;
        if !self.in_partition(&partition)? {
            return Err(Error::NotInPartition {
                partition,
                path: Some(path.to_string()),
            });
        }
        self.current_epoch(&partition)?;
        let current_id = self.partition(&partition)?.current.to_string();
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
                Ok(Some((header, body))) => {
                    return Ok(Decrypted {
                        header,
                        body,
                        epoch,
                        partition,
                    });
                }
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

    /// Encrypts to partition `p`'s current epoch with label `p`; needs no unwrap (plan 7).
    pub(crate) fn encrypt(
        &self,
        p: &str,
        header: &secret::Header,
        body: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let label = secret::Label::new(p)?;
        let current = &self.partition(p)?.current;
        secret::encrypt(
            header,
            body,
            &[
                current as &dyn age::Recipient,
                &label as &dyn age::Recipient,
            ],
        )
    }

    /// Wraps `epoch` to the users partition `p` lists and writes its file (plan 5.6).
    pub(crate) fn write_epoch(&self, p: &str, epoch: &Epoch) -> Result<(), Error> {
        write_epoch(&self.root, &self.partition_members(p)?, epoch)
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
            None,
            gpg,
        )
    }

    // A `partition.*` event about `partition`, and `user` when it concerns a member (plan 5.3).
    pub(crate) fn audit_partition(
        &self,
        event: &str,
        partition: &str,
        user: Option<&str>,
    ) -> Result<(), Error> {
        audit::append(
            &self.root.join(".amaga/audit.jsonl"),
            &self.actor,
            event,
            None,
            user,
            Some(partition),
            None,
        )
    }
}

// Stale means a different set of keys; member names are only labels (plan 5.2).
fn key_set(recipients: &secret::Recipients) -> BTreeSet<&str> {
    recipients.values().flatten().map(String::as_str).collect()
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
