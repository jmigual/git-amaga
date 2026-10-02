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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Keygen { path } => git_amaga::cmd_keygen(path.as_deref()),
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
