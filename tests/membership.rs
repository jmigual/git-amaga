//! Integration tests for the re-encryption commands: `rotate`, `user add`, `user remove`
//! (plan 7.1, tests 12-20, 30, 31).

mod common;

use std::path::Path;

use age::x25519;
use common::{OutputExt, Repo, repo_with_alice};
use git_amaga::secret::{self, Header};

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn add_secret(repo: &Repo, name: &str, body: &[u8]) {
    std::fs::write(repo.path().join(name), body).unwrap();
    repo.run(&["add", name]).assert_success();
}

/// Writes `.amaga/users/<name>.txt` by hand, as a merge or a teammate's commit would.
fn write_member(repo: &Repo, name: &str) -> x25519::Identity {
    let identity = x25519::Identity::generate();
    std::fs::write(
        repo.path().join(format!(".amaga/users/{name}.txt")),
        format!("{}\n", identity.to_public()),
    )
    .unwrap();
    identity
}

fn decrypt_with(
    ciphertext: &[u8],
    identity: &x25519::Identity,
) -> Result<(Header, Vec<u8>), git_amaga::Error> {
    secret::decrypt(ciphertext, &[identity as &dyn age::Identity])
}

/// The decrypted header of `path`, read with alice's identity file.
fn header_of(repo: &Repo, identity_path: &Path, path: &str) -> Header {
    let alice = git_amaga::identity::load_identity_file(identity_path).unwrap();
    let ciphertext = std::fs::read(repo.path().join(path)).unwrap();
    decrypt_with(&ciphertext, &alice[0]).unwrap().0
}

fn audit_events(repo: &Repo) -> Vec<String> {
    std::fs::read_to_string(repo.path().join(".amaga/audit.jsonl"))
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

/// A symlinked `.amaga` is rejected everywhere: `rotate` must not decrypt another repository's
/// secret and rewrite it as its own.
#[cfg(unix)]
#[test]
fn symlinked_secret_is_rejected() {
    let (repo, _identity_path) = repo_with_alice();
    add_secret(&repo, "prod.env", b"OTHER-REPO-SECRET");
    let other = tempfile::tempdir().unwrap();
    let target = other.path().join("prod.env.amaga");
    std::fs::rename(repo.path().join("prod.env.amaga"), &target).unwrap();
    let link = repo.path().join("leak.amaga");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let before_audit = audit_events(&repo);

    let rotate = repo.run(&["rotate"]);
    rotate.assert_failure();
    assert!(stderr(&rotate).contains("leak.amaga"));
    assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
    assert_eq!(audit_events(&repo), before_audit);

    repo.run(&["open", "leak"]).assert_failure();
    assert!(!repo.path().join("leak").exists());

    let status = repo.run(&["status"]);
    assert_eq!(status.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert!(
        stdout.contains("ERROR leak.amaga:")
            && stdout.contains("'leak.amaga' is not a regular file"),
        "got {stdout:?}"
    );
}

/// Test 16: `rotate` rewrites with fresh keys, keeps `exposed_to` and adds nothing.
#[test]
fn rotate_preserves_exposure() {
    let (repo, identity_path) = repo_with_alice();
    let bob = write_member(&repo, "bob");
    add_secret(&repo, "secret.env", b"v1");
    std::fs::remove_file(repo.path().join(".amaga/users/bob.txt")).unwrap();
    repo.run(&["rotate"]).assert_success();
    let first = std::fs::read(repo.path().join("secret.env.amaga")).unwrap();
    let exposed = header_of(&repo, &identity_path, "secret.env.amaga").exposed_to;
    assert_eq!(
        exposed["bob"].iter().collect::<Vec<_>>(),
        [&bob.to_public().to_string()]
    );

    repo.run(&["rotate"]).assert_success();
    let second = std::fs::read(repo.path().join("secret.env.amaga")).unwrap();
    assert_ne!(first, second, "rotate must use a fresh file key");
    let header = header_of(&repo, &identity_path, "secret.env.amaga");
    assert_eq!(header.exposed_to, exposed);
    assert_eq!(header.recipients.keys().collect::<Vec<_>>(), ["alice"]);
}

/// `rotate` appends a `rotated` audit event and does not touch the plaintext.
#[test]
fn rotate_audits_and_leaves_plaintext_alone() {
    let (repo, _identity_path) = repo_with_alice();
    add_secret(&repo, "secret.env", b"v1");
    std::fs::write(repo.path().join("secret.env"), b"local edit").unwrap();

    repo.run(&["rotate"]).assert_success();

    let events = audit_events(&repo);
    assert!(events.last().unwrap().contains("\"event\":\"rotated\""));
    assert_eq!(
        std::fs::read(repo.path().join("secret.env")).unwrap(),
        b"local edit"
    );
    // The local edit is still a pending edit, not a conflict.
    repo.run(&["seal", "secret.env"]).assert_success();
}

/// Test 17: a membership change that was interrupted (user file removed by hand) is reported
/// stale, and `rotate` finishes it and flags the exposure.
#[test]
fn interrupted_remove_reported_stale_and_rotate_completes() {
    let (repo, identity_path) = repo_with_alice();
    write_member(&repo, "bob");
    add_secret(&repo, "secret.env", b"v1");
    std::fs::remove_file(repo.path().join(".amaga/users/bob.txt")).unwrap();

    let status = repo.run(&["status"]);
    assert_eq!(status.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&status.stdout).contains("run git-amaga rotate"));

    repo.run(&["rotate"]).assert_success();
    let status = repo.run(&["status"]);
    status.assert_success();
    assert!(String::from_utf8_lossy(&status.stdout).contains("NEEDS ROTATION: exposed to bob"));
    let header = header_of(&repo, &identity_path, "secret.env.amaga");
    assert!(header.exposed_to.contains_key("bob"));
}

/// Test 19: a secret merged in from a branch that predates a removal is stale after the merge, and
/// `rotate` flags it as exposed to the removed member.
#[test]
fn merged_branch_secret_flagged_after_removal() {
    let (repo, identity_path) = repo_with_alice();
    write_member(&repo, "bob");
    repo.commit_all("init");
    let main = String::from_utf8(repo.git(&["rev-parse", "--abbrev-ref", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_string();

    repo.git(&["checkout", "-b", "feature"]).assert_success();
    add_secret(&repo, "feature.env", b"f");
    repo.commit_all("feature adds a secret");

    repo.git(&["checkout", &main]).assert_success();
    std::fs::remove_file(repo.path().join(".amaga/users/bob.txt")).unwrap();
    repo.commit_all("remove bob");
    repo.git(&["merge", "--no-edit", "feature"])
        .assert_success();

    let status = repo.run(&["status"]);
    assert_eq!(status.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&status.stdout).contains("run git-amaga rotate"));

    repo.run(&["rotate"]).assert_success();
    let header = header_of(&repo, &identity_path, "feature.env.amaga");
    assert!(header.exposed_to.contains_key("bob"));
}

/// Test 20 (rotate form): when any secret fails to decrypt nothing is written, every failing file
/// is listed, and the audit log is untouched.
#[test]
fn rotate_with_undecryptable_secret_changes_nothing() {
    let (repo, _identity_path) = repo_with_alice();
    for name in ["a.env", "b.env", "c.env"] {
        add_secret(&repo, name, b"v1");
    }
    for name in ["a.env.amaga", "b.env.amaga"] {
        let path = repo.path().join(name);
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        std::fs::write(&path, bytes).unwrap();
    }
    write_member(&repo, "bob");
    let before_c = std::fs::read(repo.path().join("c.env.amaga")).unwrap();
    let before_audit = audit_events(&repo);

    let rotate = repo.run(&["rotate"]);
    rotate.assert_failure();
    let stderr = stderr(&rotate);
    assert!(stderr.contains("a.env.amaga"), "got {stderr:?}");
    assert!(stderr.contains("b.env.amaga"), "got {stderr:?}");
    assert_eq!(
        std::fs::read(repo.path().join("c.env.amaga")).unwrap(),
        before_c
    );
    assert_eq!(audit_events(&repo), before_audit);
}
