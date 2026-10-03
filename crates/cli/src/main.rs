//! `git-amaga` CLI entry point (plan section 7): parses arguments, calls into the core, prints
//! the results and maps [`Error`] to an exit code (plan 14.3).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use git_amaga_core::{Error, GpgKey, Level, Outcome, Reencrypted, StatusReport, Warning};

#[derive(Parser)]
#[command(
    name = "git-amaga",
    version,
    about = "Encrypted secret files for Git repositories"
)]
struct Cli {
    /// Run as if started in this directory, like `git -C`.
    #[arg(short = 'C', long = "repo", value_name = "PATH", global = true)]
    dir: Option<PathBuf>,
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
        /// The partition to encrypt into (default: `default`).
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
    /// Add a member, or remove one and re-encrypt every secret.
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// Manage partitions: named member lists, each with its own key.
    Partition {
        #[command(subcommand)]
        command: PartitionCommand,
    },
    /// Re-encrypt every secret with fresh keys; also finishes an interrupted removal.
    Rotate,
    /// Clear NEEDS ROTATION without changing the plaintext.
    Dismiss {
        /// Members to dismiss (default: every member flagged in the selected secrets).
        #[arg(long = "user", value_name = "NAME")]
        users: Vec<String>,
        /// Plaintext or `.amaga` paths (default: every secret).
        paths: Vec<String>,
    },
    /// Show the members and the state and problems of every secret.
    Status,
}

#[derive(Subcommand)]
enum UserCommand {
    /// Add a member: re-wrap the current epoch key to them (no secret is rewritten).
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

#[derive(Subcommand)]
enum PartitionCommand {
    /// Create a partition with a new key, wrapped to the listed members.
    Create {
        /// The new partition's name.
        name: String,
        /// Members (names in `.amaga/users`) who can read its secrets.
        #[arg(required = true)]
        members: Vec<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.dir, cli.command) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(dir: Option<PathBuf>, command: Command) -> Result<ExitCode, Error> {
    let dir = std::path::absolute(dir.unwrap_or_else(|| ".".into()))?;
    let dir = dir.as_path();
    match command {
        Command::Keygen { path } => {
            let public = git_amaga_core::cmd_keygen(dir, path.as_deref())?;
            println!("{public}");
            eprintln!(
                "to join a repository, send this to a member: git-amaga user add <name> {public}"
            );
        }
        Command::Init { name, keys } => {
            print_gpg_key(&name, git_amaga_core::cmd_init(dir, &name, &keys)?);
        }
        Command::Add {
            force,
            partition,
            paths,
        } => {
            let added = git_amaga_core::cmd_add(dir, force, partition.as_deref(), &paths)?;
            print_outcome("added", added);
        }
        Command::Seal { force, paths } => {
            print_outcome("sealed", git_amaga_core::cmd_seal(dir, force, &paths)?);
        }
        Command::Open { force, paths } => {
            print_outcome("opened", git_amaga_core::cmd_open(dir, force, &paths)?);
        }
        Command::Close { paths } => {
            print_outcome("closed", git_amaga_core::cmd_close(dir, &paths)?)
        }
        Command::Remove { paths } => {
            print_outcome("removed", git_amaga_core::cmd_remove(dir, &paths)?)
        }
        Command::User {
            command: UserCommand::Add { name, keys },
        } => {
            print_gpg_key(&name, git_amaga_core::cmd_user_add(dir, &name, &keys)?);
        }
        Command::User {
            command: UserCommand::Remove { name },
        } => print_reencrypted(&git_amaga_core::cmd_user_remove(dir, &name)?),
        Command::Partition {
            command: PartitionCommand::Create { name, members },
        } => git_amaga_core::cmd_partition_create(dir, &name, &members)?,
        Command::Rotate => print_reencrypted(&git_amaga_core::cmd_rotate(dir)?),
        Command::Dismiss { users, paths } => print_outcome(
            "dismissed",
            git_amaga_core::cmd_dismiss(dir, &users, &paths)?,
        ),
        Command::Status => return Ok(print_status(&git_amaga_core::cmd_status(dir)?)),
    }
    Ok(ExitCode::SUCCESS)
}

fn print_warnings(warnings: &[Warning]) {
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
}

fn print_outcome(verb: &str, outcome: Outcome) {
    print_warnings(&outcome.warnings);
    for path in &outcome.changed {
        println!("{verb} {path}");
    }
}

fn print_gpg_key(name: &str, key: Option<GpgKey>) {
    if let Some(key) = key {
        println!("{name}: GPG key {} \"{}\"", key.fpr, key.uid);
    }
}

fn print_reencrypted(written: &[Reencrypted]) {
    for item in written {
        if item.exposed_to.is_empty() {
            println!("re-encrypted {}", item.path);
        } else {
            println!(
                "re-encrypted {} (NEEDS ROTATION: exposed to {})",
                item.path,
                item.exposed_to.join(", ")
            );
        }
    }
}

// Exits 1 when any secret is at `Level::Error`.
fn print_status(report: &StatusReport) -> ExitCode {
    print_warnings(&report.warnings);
    println!("members: {}", report.members);
    for (name, members) in &report.partitions {
        println!("partition {name}: {}", members.join(", "));
    }
    for secret in &report.secrets {
        let label = match secret.level {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Ok => "ok",
        };
        let partition = match secret.partition.as_str() {
            "" | "default" => String::new(),
            p => format!(" ({p})"),
        };
        let path = &secret.path;
        println!("{label} {path}{partition}: {}", secret.messages.join("; "));
    }
    match report.error_count() {
        0 => ExitCode::SUCCESS,
        n => {
            eprintln!("error: status found problems with {n} secret(s)");
            ExitCode::FAILURE
        }
    }
}
