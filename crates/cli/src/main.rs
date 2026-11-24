//! `git-amaga` CLI entry point (plan section 7): parses arguments, calls into the core, prints
//! the results and maps [`Error`] to an exit code (plan 14.3).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use git_amaga_core::{Error, GpgKey, Imported, Level, Outcome, Rotation, StatusReport, Warning};

mod cli;

use cli::{Cli, Command, PartitionCommand, UserCommand};

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
            command:
                UserCommand::Add {
                    name,
                    keys,
                    partitions,
                },
        } => {
            let gpg = git_amaga_core::cmd_user_add(dir, &name, &keys, &partitions)?;
            print_gpg_key(&name, gpg);
        }
        Command::User {
            command: UserCommand::Remove { name },
        } => print_rotation(&git_amaga_core::cmd_user_remove(dir, &name)?),
        Command::Partition {
            command: PartitionCommand::Create { name, members },
        } => git_amaga_core::cmd_partition_create(dir, &name, &members)?,
        Command::Partition {
            command: PartitionCommand::Add { name, members },
        } => git_amaga_core::cmd_partition_add(dir, &name, &members)?,
        Command::Partition {
            command: PartitionCommand::Move { name, paths },
        } => print_outcome(
            "moved",
            git_amaga_core::cmd_partition_move(dir, &name, &paths)?,
        ),
        Command::Partition {
            command: PartitionCommand::Remove { name, members },
        } => print_rotation(&git_amaga_core::cmd_partition_remove(dir, &name, &members)?),
        Command::Rotate { partitions } => {
            print_rotation(&git_amaga_core::cmd_rotate(dir, &partitions)?)
        }
        Command::Dismiss { users, paths } => print_outcome(
            "dismissed",
            git_amaga_core::cmd_dismiss(dir, &users, &paths)?,
        ),
        Command::ImportGitCrypt { names } => {
            print_imported(git_amaga_core::cmd_import_git_crypt(dir, &names)?)
        }
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

fn print_imported(imported: Imported) {
    print_warnings(&imported.warnings);
    for (name, key) in &imported.members {
        println!("{name}: GPG key {} \"{}\"", key.fpr, key.uid);
    }
    for path in &imported.changed {
        println!("imported {path}");
    }
}

fn print_gpg_key(name: &str, key: Option<GpgKey>) {
    if let Some(key) = key {
        println!("{name}: GPG key {} \"{}\"", key.fpr, key.uid);
    }
}

fn print_rotation(rotation: &Rotation) {
    print_warnings(&rotation.warnings);
    for item in &rotation.written {
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
