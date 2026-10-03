//! The commands of git-amaga as functions: they act on the repository containing the current
//! directory and never print (ADR-0014).

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
