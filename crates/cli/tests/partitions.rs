//! Integration tests for partitions (ADR-0017, plan 5.7, tests 52-64).

mod common;

use common::{
    OutputExt, Repo, can_unwrap, current_epoch_id, decrypt_file, load_identity, repo_with_alice,
    second_identity,
};

fn add_secret(repo: &Repo, name: &str, body: &[u8]) {
    std::fs::write(repo.path().join(name), body).unwrap();
    repo.run(&["add", name]).assert_success();
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
    let (repo, identity_path) = repo_with_alice();
    let (bob_key, _bob_config) = second_identity(&repo, "bob");
    repo.run(&["user", "add", "bob", &bob_key]).assert_success();
    add_secret(&repo, "a.env", b"a1");

    std::fs::write(
        repo.path().join(".amaga/partitions/default/members"),
        "alice\n",
    )
    .unwrap();
    let status = repo.run(&["status"]);
    status.assert_failure();
    assert!(String::from_utf8_lossy(&status.stdout).contains("run git-amaga rotate"));
    std::fs::write(repo.path().join("b.env"), b"b1").unwrap();
    let add = repo.run(&["add", "b.env"]);
    add.assert_failure();
    assert!(String::from_utf8_lossy(&add.stderr).contains("rotate"));

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
