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
        /// `age1…` recipients and/or a path to an armored OpenPGP public key file.
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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Keygen { path } => git_amaga::cmd_keygen(path.as_deref()),
        Command::Init { name, keys } => git_amaga::cmd_init(&name, &keys),
        Command::Add { force, paths } => git_amaga::cmd_add(force, &paths),
        Command::Seal { force, paths } => git_amaga::cmd_seal(force, &paths),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            // Every error in scope so far exits 1; `status`'s "needs rotation" special case
            // (exit 0, plan 7.2) is added when that command is implemented.
            ExitCode::FAILURE
        }
    }
}
