//! The clap definitions of `git-amaga`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "git-amaga",
    version,
    about = "Encrypted secret files for Git repositories"
)]
pub(crate) struct Cli {
    /// Run as if started in this directory, like `git -C`.
    #[arg(short = 'C', long = "repo", value_name = "PATH", global = true)]
    pub(crate) dir: Option<PathBuf>,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Generate an age identity and print its public key.
    Keygen {
        /// Where to write the identity (default: ~/.config/git-amaga/identity.txt).
        path: Option<PathBuf>,
    },
    /// Initialize this repository: create the first member and the managed state.
    Init {
        /// The new member's name.
        name: String,
        /// `age1…` recipients, an armored OpenPGP public key file (`.asc`), or a key in the local
        /// gpg keyring (key ID, fingerprint, email or user ID).
        keys: Vec<String>,
    },
    /// Encrypt new plaintext files as `.amaga` ciphertext.
    Add {
        /// Overwrite the refusal when `<path>.amaga` appears in git history.
        #[arg(long)]
        force: bool,
        /// The partition to encrypt into (default: the `amaga-partition` attribute, else `default`).
        #[arg(long, value_name = "NAME")]
        partition: Option<String>,
        /// Plaintext or `.amaga` paths to add.
        #[arg(required = true)]
        paths: Vec<String>,
    },
    /// Re-encrypt local plaintext edits.
    #[command(visible_alias = "lock")]
    Seal {
        /// Seal an `Outdated`/`Conflict` plaintext, overwriting the repository version.
        #[arg(long)]
        force: bool,
        /// Plaintext or `.amaga` paths to seal (default: every secret whose plaintext exists).
        paths: Vec<String>,
    },
    /// Decrypt secrets to local plaintext.
    ///
    /// A plaintext gets the mode of its `amaga-mode` attribute (0600, 0640, 0604 or 0644), else
    /// the mode of the file it replaces, else 0600.
    #[command(visible_alias = "unlock")]
    Open {
        /// Discard local edits and take the repository version.
        #[arg(long)]
        force: bool,
        /// Plaintext or `.amaga` paths to open (default: every secret).
        paths: Vec<String>,
    },
    /// Delete local plaintext once it is sealed.
    #[command(visible_alias = "shred")]
    Close {
        /// Plaintext or `.amaga` paths to close (default: every secret whose plaintext exists).
        paths: Vec<String>,
    },
    /// Stop managing secrets: delete their `.amaga` files but keep the plaintext.
    Remove {
        /// Plaintext or `.amaga` paths to remove.
        #[arg(required = true)]
        paths: Vec<String>,
    },
    /// Add a member to partitions, or remove one and re-encrypt the partitions you are in.
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// Manage partitions: named member lists, each with its own key.
    Partition {
        #[command(subcommand)]
        command: PartitionCommand,
    },
    /// Re-encrypt secrets with fresh keys; also finishes an interrupted removal.
    Rotate {
        /// Rotate only this partition (default: every partition you are a member of).
        #[arg(long = "partition", value_name = "NAME")]
        partitions: Vec<String>,
    },
    /// Clear NEEDS ROTATION without changing the plaintext. Name at least one path or --user.
    Dismiss {
        /// Members to dismiss (with paths only: every member flagged in those secrets).
        #[arg(long = "user", value_name = "NAME")]
        users: Vec<String>,
        /// Plaintext or `.amaga` paths (with --user only: every secret).
        paths: Vec<String>,
    },
    /// Migrate an unlocked git-crypt repository: its files become secrets and its key holders
    /// members.
    ImportGitCrypt {
        /// Name the member for a key holder's fingerprint instead of deriving one.
        #[arg(long = "name", value_name = "FPR=NAME")]
        names: Vec<String>,
    },
    /// Show the members and the state and problems of every secret.
    Status,
}

#[derive(Subcommand)]
pub(crate) enum UserCommand {
    /// Add a member: re-wrap the current epoch key to them (no secret is rewritten).
    Add {
        /// The new member's name.
        name: String,
        /// `age1…` recipients, an armored OpenPGP public key file (`.asc`), or a key in the local
        /// gpg keyring (key ID, fingerprint, email or user ID).
        #[arg(required = true)]
        keys: Vec<String>,
        /// A partition to add them to (repeatable; default: `default`).
        #[arg(long = "partition", value_name = "NAME")]
        partitions: Vec<String>,
    },
    /// Remove a member, re-encrypt the secrets of your partitions and flag the ones they could read.
    Remove {
        /// The member to remove.
        name: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum PartitionCommand {
    /// Create a partition with a new key, wrapped to the listed members.
    Create {
        /// The new partition's name.
        name: String,
        /// Members (names in `.amaga/users`) who can read its secrets.
        #[arg(required = true)]
        members: Vec<String>,
    },
    /// Add members to a partition: re-wrap its current key to them (no secret is rewritten).
    Add {
        /// The partition.
        name: String,
        /// Members (names in `.amaga/users`) to add.
        #[arg(required = true)]
        members: Vec<String>,
    },
    /// Move secrets into a partition; members of the old key who lack the new one are flagged
    /// NEEDS ROTATION.
    Move {
        /// The target partition.
        name: String,
        /// Plaintext or `.amaga` paths to move.
        #[arg(required = true)]
        paths: Vec<String>,
    },
    /// Remove members from a partition, re-encrypt its secrets and flag the ones they could read.
    Remove {
        /// The partition.
        name: String,
        /// Members to remove.
        #[arg(required = true)]
        members: Vec<String>,
    },
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::Cli;

    #[test]
    fn man_pages_cover_the_command_and_its_subcommands() {
        let dir = tempfile::tempdir().unwrap();
        clap_mangen::generate_to(Cli::command(), dir.path()).unwrap();
        let page = std::fs::read_to_string(dir.path().join("git-amaga.1")).unwrap();
        assert!(page.contains("git\\-amaga\\-init(1)"));
        assert!(dir.path().join("git-amaga-init.1").is_file());
        assert!(dir.path().join("git-amaga-partition-create.1").is_file());
    }
}
