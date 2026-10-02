//! `git-amaga` CLI entry point (plan section 7): parses arguments, calls into the library, and
//! maps [`Error`] to an exit code.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "git-amaga",
    about = "Encrypted secret files for Git repositories"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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
        /// Plaintext or `.amaga` paths to add.
        #[arg(required = true)]
        paths: Vec<String>,
    },
    /// Re-encrypt local plaintext edits.
    Seal {
        /// Seal an `Outdated`/`Conflict` plaintext, overwriting the repository version.
        #[arg(long)]
        force: bool,
        /// Plaintext or `.amaga` paths to seal (default: every secret whose plaintext exists).
        paths: Vec<String>,
    },
    /// Decrypt secrets to local plaintext.
    Open {
        /// Discard local edits and take the repository version.
        #[arg(long)]
        force: bool,
        /// Plaintext or `.amaga` paths to open (default: every secret).
        paths: Vec<String>,
    },
    /// Delete local plaintext once it is sealed.
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
    /// Add or remove a member and re-encrypt every secret.
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// Re-encrypt every secret with fresh keys; also finishes an interrupted removal.
    Rotate,
    /// Show the members and the state and problems of every secret.
    Status,
}

#[derive(Subcommand)]
enum UserCommand {
    /// Add a member and re-encrypt every secret to them.
    Add {
        /// The new member's name.
        name: String,
        /// `age1…` recipients, an armored OpenPGP public key file (`.asc`), or a key in the local
        /// gpg keyring (key ID, fingerprint, email or user ID).
        #[arg(required = true)]
        keys: Vec<String>,
    },
    /// Remove a member, re-encrypt every secret and flag the ones they could read.
    Remove {
        /// The member to remove.
        name: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Keygen { path } => git_amaga::cmd_keygen(path.as_deref()),
        Command::Init { name, keys } => git_amaga::cmd_init(&name, &keys),
        Command::Add { force, paths } => git_amaga::cmd_add(force, &paths),
        Command::Seal { force, paths } => git_amaga::cmd_seal(force, &paths),
        Command::Open { force, paths } => git_amaga::cmd_open(force, &paths),
        Command::Close { paths } => git_amaga::cmd_close(&paths),
        Command::Remove { paths } => git_amaga::cmd_remove(&paths),
        Command::User {
            command: UserCommand::Add { name, keys },
        } => git_amaga::cmd_user_add(&name, &keys),
        Command::User {
            command: UserCommand::Remove { name },
        } => git_amaga::cmd_user_remove(&name),
        Command::Rotate => git_amaga::cmd_rotate(),
        Command::Status => git_amaga::cmd_status(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
