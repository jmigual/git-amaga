//! The commands of git-amaga as functions: each takes the directory it runs in (as if it were the
//! current directory), acts on the repository containing it and never prints (ADR-0014).
//! As with `git -C`, git's own environment (`GIT_DIR`, `GIT_WORK_TREE`) takes precedence over
//! `dir`; library callers control it through their process environment.

mod audit;
mod commands;
mod context;
mod dismiss;
pub mod epoch;
pub mod error;
mod failure;
mod files;
mod git;
mod gitcrypt;
pub mod gpg;
pub mod identity;
mod import;
mod keyring;
mod membership;
mod outcome;
pub mod partition;
mod partition_commands;
mod paths;
mod remove;
pub mod secret;
mod selection;
mod status;
pub mod users;

pub use commands::{cmd_add, cmd_close, cmd_init, cmd_keygen, cmd_open, cmd_seal};
pub use dismiss::cmd_dismiss;
pub use error::Error;
pub use import::cmd_import_git_crypt;
pub use keyring::GpgKey;
pub use membership::{cmd_rotate, cmd_user_add, cmd_user_remove};
pub use outcome::{
    Imported, Level, Outcome, Reencrypted, Rotation, SecretStatus, StatusReport, Warning,
};
pub use partition_commands::{
    cmd_partition_add, cmd_partition_create, cmd_partition_move, cmd_partition_remove,
};
pub use remove::cmd_remove;
pub use status::cmd_status;
