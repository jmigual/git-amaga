//! The commands of git-amaga as functions: each takes the directory it runs in (as if it were the
//! current directory), acts on the repository containing it and never prints (ADR-0014).
//! As with `git -C`, git's own environment (`GIT_DIR`, `GIT_WORK_TREE`) takes precedence over
//! `dir`; library callers control it through their process environment.

mod audit;
mod commands;
mod context;
pub mod error;
mod git;
pub mod gpg;
pub mod identity;
mod keyring;
mod membership;
mod outcome;
mod paths;
mod remove;
pub mod secret;
pub mod users;

pub use commands::{cmd_add, cmd_close, cmd_init, cmd_keygen, cmd_open, cmd_seal, cmd_status};
pub use error::Error;
pub use keyring::GpgKey;
pub use membership::{cmd_rotate, cmd_user_add, cmd_user_remove};
pub use outcome::{Level, Outcome, Reencrypted, SecretStatus, StatusReport, Warning};
pub use remove::cmd_remove;
