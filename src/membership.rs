//! Re-encrypting every secret (plan 7.1): `rotate` here, and the membership commands.

use crate::context::{Context, read_repo_file, write_repo_file};
use crate::{Error, git, secret, users};

/// Plan 7.1: decrypts every secret first and writes nothing if any fails, then runs `change` (the
/// membership change and its audit event, for `user add`/`user remove`; it may update
/// `ctx.members`), then rewrites each secret for the current members.
pub(crate) fn reencrypt_all(
    ctx: &mut Context,
    change: impl FnOnce(&mut Context) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut decrypted = Vec::new();
    let mut failures = Vec::new();
    for path in git::managed_secrets(&ctx.root)? {
        if !ctx.root.join(&path).exists() {
            continue;
        }
        match read_repo_file(&ctx.root, &path).and_then(|bytes| ctx.decrypt(&path, &bytes)) {
            Ok((header, body)) => decrypted.push((path, header, body)),
            Err(e) => failures.push(e.to_string()),
        }
    }
    if !failures.is_empty() {
        return Err(Error::ReencryptAborted(failures.join("\n")));
    }

    change(ctx)?;

    let current = users::recipients(&ctx.members);
    for (path, old_header, body) in decrypted {
        let header = secret::next_header(Some(&old_header), false, &current);
        let ciphertext = ctx.encrypt(&header, &body)?;
        write_repo_file(&ctx.root, &path, &ciphertext, None)?;
        let exposed: Vec<&str> = header.exposed_to.keys().map(String::as_str).collect();
        if exposed.is_empty() {
            println!("re-encrypted {path}");
        } else {
            println!(
                "re-encrypted {path} (NEEDS ROTATION: exposed to {})",
                exposed.join(", ")
            );
        }
    }
    Ok(())
}

/// `git-amaga rotate` (plan 7): re-encrypts everything; also finishes an interrupted run.
pub fn cmd_rotate() -> Result<(), Error> {
    let mut ctx = Context::load()?;
    reencrypt_all(&mut ctx, |_| Ok(()))?;
    ctx.audit_event("rotated", None, None)
}
