//! Integration tests for partitions (ADR-0017, plan 5.7, tests 52-64).

mod common;

use std::path::PathBuf;
use std::process::Output;

use common::{
    OutputExt, Repo, can_unwrap, current_epoch_id, decrypt_file, load_identity, repo_with_alice,
    run_as, second_identity,
};

fn add_secret(repo: &Repo, name: &str, body: &[u8]) {
    std::fs::write(repo.path().join(name), body).unwrap();
    repo.run(&["add", name]).assert_success();
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Alice and bob in `default`; returns the repository, alice's identity file and bob's config.
fn repo_with_alice_and_bob() -> (Repo, PathBuf, PathBuf) {
    let (repo, identity_path) = repo_with_alice();
    let (bob_key, bob_config) = second_identity(&repo, "bob");
    repo.run(&["user", "add", "bob", &bob_key]).assert_success();
    (repo, identity_path, bob_config)
}

/// Test 52: the label is readable in the header, and changing it breaks authentication.
#[test]
fn secret_label_is_readable_and_authenticated() {
    let (repo, _identity_path) = repo_with_alice();
    std::fs::write(repo.path().join("a.env"), b"v1").unwrap();
    repo.run(&["add", "a.env"]).assert_success();
    std::fs::remove_file(repo.path().join("a.env")).unwrap();

    let path = repo.path().join("a.env.amaga");
    let mut bytes = std::fs::read(&path).unwrap();
    let label = b"-> amaga-partition default\n";
    let at = bytes.windows(label.len()).position(|w| w == label).unwrap();

    // The last name byte, before the newline.
    bytes[at + label.len() - 2] = b'x';
    std::fs::write(&path, &bytes).unwrap();
    repo.run(&["open", "a.env"]).assert_failure();
    assert!(!repo.path().join("a.env").exists());
}

/// Test 53: `default/members` decides who the next epoch is wrapped to; a hand edit makes the
/// partition stale until `rotate`, which locks the removed name out and flags every secret.
#[test]
fn default_members_file_controls_access() {
    let (repo, identity_path, _bob_config) = repo_with_alice_and_bob();
    add_secret(&repo, "a.env", b"a1");

    std::fs::write(
        repo.path().join(".amaga/partitions/default/members"),
        "alice\n",
    )
    .unwrap();
    let status = repo.run(&["status"]);
    status.assert_failure();
    assert!(stdout(&status).contains("run git-amaga rotate"));
    std::fs::write(repo.path().join("b.env"), b"b1").unwrap();
    let add = repo.run(&["add", "b.env"]);
    add.assert_failure();
    assert!(stderr(&add).contains("rotate"));

    repo.run(&["rotate"]).assert_success();
    let bob = load_identity(&repo.path().join("bob-identity.txt"));
    assert!(!can_unwrap(
        &repo,
        &current_epoch_id(&repo, "default"),
        &bob
    ));
    let (header, _) = decrypt_file(&repo, &identity_path, "a.env.amaga");
    assert_eq!(header.exposed_to.keys().collect::<Vec<_>>(), ["bob"]);
}

/// Test 54: a partition restricts who can read its secrets, in the cryptography and in the
/// commands.
#[test]
fn partition_create_restricts_access() {
    let (repo, _identity_path, bob_config) = repo_with_alice_and_bob();
    repo.run(&["partition", "create", "production", "alice"])
        .assert_success();
    std::fs::write(repo.path().join("p.env"), b"prod").unwrap();
    repo.run(&["add", "--partition", "production", "p.env"])
        .assert_success();
    add_secret(&repo, "d.env", b"dev");
    repo.run(&["close"]).assert_success();

    run_as(&repo, &bob_config, &["open"]).assert_success();
    assert_eq!(std::fs::read(repo.path().join("d.env")).unwrap(), b"dev");
    assert!(!repo.path().join("p.env").exists());
    let open = run_as(&repo, &bob_config, &["open", "p.env"]);
    open.assert_failure();
    assert!(stderr(&open).contains("production"), "{}", stderr(&open));

    let status = run_as(&repo, &bob_config, &["status"]);
    status.assert_success();
    assert!(stdout(&status).contains("ok p.env.amaga (production): not a member"));
    let bob = load_identity(&repo.path().join("bob-identity.txt"));
    assert!(!can_unwrap(
        &repo,
        &current_epoch_id(&repo, "production"),
        &bob
    ));

    let status = stdout(&repo.run(&["status"]));
    assert!(status.contains("partition default: alice, bob\n"));
    assert!(status.contains("partition production: alice\n"));
}

/// A listed name that is not a user grants nothing, and `status` says so without failing.
#[test]
fn status_warns_about_a_listed_name_that_is_not_a_user() {
    let (repo, _identity_path) = repo_with_alice();
    std::fs::write(
        repo.path().join(".amaga/partitions/default/members"),
        "alice\nghost\n",
    )
    .unwrap();

    let status = repo.run(&["status"]);
    status.assert_success();
    assert!(stderr(&status).contains("ghost"), "{}", stderr(&status));
}

/// Test 55: the stale guard looks at the partition written into, not at every partition.
#[test]
fn stale_guard_is_per_partition() {
    let (repo, _identity_path, _bob_config) = repo_with_alice_and_bob();
    repo.run(&["partition", "create", "production", "alice"])
        .assert_success();
    let members = repo.path().join(".amaga/partitions/production/members");
    std::fs::write(&members, "alice\nbob\n").unwrap();

    std::fs::write(repo.path().join("x.env"), b"x").unwrap();
    let add = repo.run(&["add", "--partition", "production", "x.env"]);
    add.assert_failure();
    assert!(stderr(&add).contains("rotate --partition production"));
    add_secret(&repo, "y.env", b"y");
}
