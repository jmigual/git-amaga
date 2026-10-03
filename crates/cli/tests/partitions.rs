//! Integration tests for partitions (ADR-0017, plan 5.7, tests 52-64).

mod common;

use std::path::PathBuf;
use std::process::Output;

use common::{
    OutputExt, Repo, can_unwrap, current_branch, current_epoch_id, decrypt_as, decrypt_file,
    load_identity, repo_with_alice, run_as, second_identity,
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

fn read(repo: &Repo, path: &str) -> Vec<u8> {
    std::fs::read(repo.path().join(path)).unwrap()
}

/// Test 56: `rotate --partition p` touches only `p`, and `rotate` skips partitions the actor is
/// not in.
#[test]
fn rotate_partition_touches_only_that_partition() {
    let (repo, _identity_path, bob_config) = repo_with_alice_and_bob();
    repo.run(&["partition", "create", "production", "alice"])
        .assert_success();
    std::fs::write(repo.path().join("p.env"), b"prod").unwrap();
    repo.run(&["add", "--partition", "production", "p.env"])
        .assert_success();
    add_secret(&repo, "d.env", b"dev");
    let default_pointer = current_epoch_id(&repo, "default");
    let production_pointer = current_epoch_id(&repo, "production");
    let (d_before, p_before) = (read(&repo, "d.env.amaga"), read(&repo, "p.env.amaga"));

    repo.run(&["rotate", "--partition", "production"])
        .assert_success();
    assert_eq!(read(&repo, "d.env.amaga"), d_before);
    assert_eq!(current_epoch_id(&repo, "default"), default_pointer);
    assert_ne!(read(&repo, "p.env.amaga"), p_before);
    assert_ne!(current_epoch_id(&repo, "production"), production_pointer);

    let p_before = read(&repo, "p.env.amaga");
    let rotate = run_as(&repo, &bob_config, &["rotate"]);
    rotate.assert_success();
    assert!(
        stderr(&rotate).contains("production"),
        "{}",
        stderr(&rotate)
    );
    assert_ne!(read(&repo, "d.env.amaga"), d_before);
    assert_eq!(read(&repo, "p.env.amaga"), p_before);
}

/// Test 57: `user remove` re-encrypts only the actor's partitions and reports the others. Alice
/// is in `default` only; bob and carol are in `default` and `production`, which holds `p.env`
/// (added by carol).
#[test]
fn user_remove_rotates_only_the_actors_partitions() {
    let (repo, alice_identity, _bob_config) = repo_with_alice_and_bob();
    let (carol_key, carol_config) = second_identity(&repo, "carol");
    repo.run(&["user", "add", "carol", &carol_key])
        .assert_success();
    repo.run(&["partition", "create", "production", "bob", "carol"])
        .assert_success();
    std::fs::write(repo.path().join("p.env"), b"prod").unwrap();
    let production = ["add", "--partition", "production", "p.env"];
    run_as(&repo, &carol_config, &production).assert_success();
    add_secret(&repo, "d.env", b"dev");
    let p_before = read(&repo, "p.env.amaga");

    let remove = repo.run(&["user", "remove", "bob"]);
    remove.assert_success();
    assert!(
        stderr(&remove).contains("production"),
        "{}",
        stderr(&remove)
    );
    assert!(stdout(&remove).contains("re-encrypted d.env.amaga (NEEDS ROTATION: exposed to bob)"));
    assert!(!repo.path().join(".amaga/users/bob.txt").exists());
    assert_eq!(
        read(&repo, ".amaga/partitions/production/members"),
        b"carol\n"
    );
    assert_eq!(read(&repo, "p.env.amaga"), p_before);
    let (header, _) = decrypt_file(&repo, &alice_identity, "d.env.amaga");
    assert_eq!(header.exposed_to.keys().collect::<Vec<_>>(), ["bob"]);

    let status = run_as(&repo, &carol_config, &["status"]);
    status.assert_failure();
    assert!(stdout(&status).contains("run git-amaga rotate --partition production"));
    run_as(&repo, &carol_config, &["rotate"]).assert_success();
    let carol = load_identity(&repo.path().join("carol-identity.txt"));
    let (header, _) = decrypt_as(&repo, &read(&repo, "p.env.amaga"), &carol).unwrap();
    assert_eq!(header.exposed_to.keys().collect::<Vec<_>>(), ["bob"]);
}

/// Test 58: the last member of a partition cannot be removed by `user remove`.
#[test]
fn last_partition_member_cannot_be_removed_by_user_remove() {
    let (repo, _identity_path, _bob_config) = repo_with_alice_and_bob();
    repo.run(&["partition", "create", "production", "alice"])
        .assert_success();
    let members = ".amaga/partitions/production/members";
    let before = (read(&repo, members), read(&repo, ".amaga/audit.jsonl"));

    let remove = repo.run(&["user", "remove", "alice"]);
    remove.assert_failure();
    assert!(
        stderr(&remove).contains("production"),
        "{}",
        stderr(&remove)
    );
    assert!(repo.path().join(".amaga/users/alice.txt").exists());
    assert_eq!(
        before,
        (read(&repo, members), read(&repo, ".amaga/audit.jsonl"))
    );
}

/// Test 59: `partition remove` flags only that partition's secrets, and keeps its last member.
#[test]
fn partition_remove_flags_only_that_partition() {
    let (repo, identity_path, _bob_config) = repo_with_alice_and_bob();
    repo.run(&["partition", "create", "production", "alice", "bob"])
        .assert_success();
    std::fs::write(repo.path().join("p.env"), b"prod").unwrap();
    repo.run(&["add", "--partition", "production", "p.env"])
        .assert_success();
    add_secret(&repo, "d.env", b"dev");
    let d_before = read(&repo, "d.env.amaga");
    let default_pointer = current_epoch_id(&repo, "default");

    let remove = repo.run(&["partition", "remove", "production", "bob"]);
    remove.assert_success();
    assert!(stdout(&remove).contains("re-encrypted p.env.amaga (NEEDS ROTATION: exposed to bob)"));
    assert_eq!(read(&repo, "d.env.amaga"), d_before);
    assert_eq!(current_epoch_id(&repo, "default"), default_pointer);
    let (header, _) = decrypt_file(&repo, &identity_path, "p.env.amaga");
    assert_eq!(header.exposed_to.keys().collect::<Vec<_>>(), ["bob"]);

    let members = ".amaga/partitions/production/members";
    let before = (read(&repo, members), read(&repo, "p.env.amaga"));
    repo.run(&["partition", "remove", "production", "alice"])
        .assert_failure();
    assert_eq!(before, (read(&repo, members), read(&repo, "p.env.amaga")));
}

/// Test 60: `partition add` re-wraps the partition's epoch and rewrites no secret.
#[test]
fn partition_add_rewraps_only() {
    let (repo, _identity_path, bob_config) = repo_with_alice_and_bob();
    repo.run(&["partition", "create", "production", "alice"])
        .assert_success();
    std::fs::write(repo.path().join("p.env"), b"prod").unwrap();
    repo.run(&["add", "--partition", "production", "p.env"])
        .assert_success();
    repo.run(&["close"]).assert_success();
    repo.commit_all("base");
    let secret_before = read(&repo, "p.env.amaga");
    let epoch_id = current_epoch_id(&repo, "production");

    repo.run(&["partition", "add", "production", "bob"])
        .assert_success();

    assert_eq!(read(&repo, "p.env.amaga"), secret_before);
    assert_eq!(current_epoch_id(&repo, "production"), epoch_id);
    let porcelain = String::from_utf8(repo.git(&["status", "--porcelain"]).stdout).unwrap();
    let mut changed: Vec<&str> = porcelain
        .lines()
        .filter(|line| !line.ends_with(" identity.txt"))
        .map(|line| &line[3..])
        .collect();
    changed.sort();
    let epoch_file = format!(".amaga/epochs/{epoch_id}.age");
    assert_eq!(
        changed,
        [
            ".amaga/audit.jsonl",
            epoch_file.as_str(),
            ".amaga/partitions/production/members",
        ]
    );
    run_as(&repo, &bob_config, &["open", "p.env"]).assert_success();
    assert_eq!(read(&repo, "p.env"), b"prod");
}

/// Test 61: `partition add` on a branch and `rotate --partition` on main merge cleanly into a
/// stale partition, which `rotate --partition` then fixes.
#[test]
fn partition_add_on_branch_rotate_on_main() {
    let (repo, identity_path, bob_config) = repo_with_alice_and_bob();
    repo.run(&["partition", "create", "production", "alice"])
        .assert_success();
    std::fs::write(repo.path().join("p.env"), b"prod").unwrap();
    repo.run(&["add", "--partition", "production", "p.env"])
        .assert_success();
    repo.run(&["close"]).assert_success();
    repo.commit_all("base");
    let main = current_branch(&repo);

    repo.git(&["checkout", "-b", "feature"]).assert_success();
    repo.run(&["partition", "add", "production", "bob"])
        .assert_success();
    repo.commit_all("feature adds bob");
    repo.git(&["checkout", &main]).assert_success();
    repo.run(&["rotate", "--partition", "production"])
        .assert_success();
    repo.commit_all("rotate production");
    repo.git(&["merge", "--no-edit", "feature"])
        .assert_success();

    let status = repo.run(&["status"]);
    status.assert_failure();
    assert!(stdout(&status).contains("p.env.amaga (production): stale recipients"));
    std::fs::write(repo.path().join("x.env"), b"x").unwrap();
    let add = repo.run(&["add", "--partition", "production", "x.env"]);
    add.assert_failure();
    assert!(stderr(&add).contains("rotate --partition production"));

    repo.run(&["rotate", "--partition", "production"])
        .assert_success();
    run_as(&repo, &bob_config, &["open", "p.env"]).assert_success();
    let (header, _) = decrypt_file(&repo, &identity_path, "p.env.amaga");
    assert!(header.exposed_to.is_empty());
}

/// Test 62: `user add --partition` adds the member to that partition only.
#[test]
fn user_add_into_partition_only() {
    let (repo, _identity_path) = repo_with_alice();
    repo.run(&["partition", "create", "production", "alice"])
        .assert_success();
    std::fs::write(repo.path().join("p.env"), b"prod").unwrap();
    repo.run(&["add", "--partition", "production", "p.env"])
        .assert_success();
    add_secret(&repo, "d.env", b"dev");
    repo.run(&["close"]).assert_success();
    let epoch = format!(".amaga/epochs/{}.age", current_epoch_id(&repo, "default"));
    let default_before = (
        read(&repo, &epoch),
        current_epoch_id(&repo, "default"),
        read(&repo, ".amaga/partitions/default/members"),
    );

    let (carol_key, carol_config) = second_identity(&repo, "carol");
    repo.run(&[
        "user",
        "add",
        "carol",
        &carol_key,
        "--partition",
        "production",
    ])
    .assert_success();

    run_as(&repo, &carol_config, &["open", "p.env"]).assert_success();
    assert_eq!(read(&repo, "p.env"), b"prod");
    run_as(&repo, &carol_config, &["open", "d.env"]).assert_failure();
    let default_after = (
        read(&repo, &epoch),
        current_epoch_id(&repo, "default"),
        read(&repo, ".amaga/partitions/default/members"),
    );
    assert_eq!(default_before, default_after);
}

/// Test 63: `partition move` flags the members of the old epoch that the target lacks, and
/// leaves plaintext and base alone.
#[test]
fn partition_move_flags_members_missing_from_target() {
    let (repo, identity_path, bob_config) = repo_with_alice_and_bob();
    repo.run(&["partition", "create", "production", "alice"])
        .assert_success();
    add_secret(&repo, "d.env", b"dev");
    let base = ".git/amaga-base";
    let base_before = read(&repo, base);

    let moved = repo.run(&["partition", "move", "production", "d.env"]);
    moved.assert_success();
    assert_eq!(stdout(&moved), "moved d.env.amaga\n");
    assert_eq!(read(&repo, "d.env"), b"dev");
    assert_eq!(read(&repo, base), base_before);
    let ciphertext = read(&repo, "d.env.amaga");
    let label = git_amaga_core::secret::label_of("d.env.amaga", &ciphertext).unwrap();
    assert_eq!(label, "production");
    let status = stdout(&repo.run(&["status"]));
    assert!(
        status.contains("WARN d.env.amaga (production): NEEDS ROTATION: exposed to bob"),
        "{status}"
    );
    let audit = String::from_utf8(read(&repo, ".amaga/audit.jsonl")).unwrap();
    assert!(
        audit
            .lines()
            .last()
            .unwrap()
            .contains("\"event\":\"secret.moved\"")
    );
    run_as(&repo, &bob_config, &["open", "d.env"]).assert_failure();

    repo.run(&["partition", "move", "default", "d.env"])
        .assert_success();
    let (header, _) = decrypt_file(&repo, &identity_path, "d.env.amaga");
    assert_eq!(header.exposed_to.keys().collect::<Vec<_>>(), ["bob"]);
}
