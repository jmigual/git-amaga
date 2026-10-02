pub mod error;
pub mod git;
pub mod gpg;
pub mod identity;
pub mod secret;
pub mod users;

pub use error::Error;

use std::path::Path;

/// `git-amaga keygen [PATH]` (plan: `keygen`): generates an age identity and prints its public
/// key.
pub fn cmd_keygen(path: Option<&Path>) -> Result<(), Error> {
    let (_path, public) = identity::keygen(path)?;
    println!("{public}");
    Ok(())
}
