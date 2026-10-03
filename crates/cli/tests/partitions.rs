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
    // An existing partition of the same name length that alice is in, so the relabelled file
    // fails on the header MAC and not on an unknown partition.
    repo.run(&["partition", "create", "staging", "alice"])
        .assert_success();
    std::fs::write(repo.path().join("a.env"), b"v1").unwrap();
    repo.run(&["add", "a.env"]).assert_success();
    std::fs::remove_file(repo.path().join("a.env")).unwrap();

    let path = repo.path().join("a.env.amaga");
    let mut bytes = std::fs::read(&path).unwrap();
    let label = b"-> amaga-partition default\n";
    let at = bytes.windows(label.len()).position(|w| w == label).unwrap();

    let forged = b"-> amaga-partition staging\n";
    bytes[at..at + label.len()].copy_from_slice(forged);
    std::fs::write(&path, &bytes).unwrap();
    let open = repo.run(&["open", "a.env"]);
    open.assert_failure();
    assert!(stderr(&open).contains("MAC"), "{}", stderr(&open));
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
    assert!(decrypt_as(&repo, &read(&repo, "p.env.amaga"), &bob).is_err());

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
    let bob = load_identity(&repo.path().join("bob-identity.txt"));
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
    let production = current_epoch_id(&repo, "production");
    assert!(!can_unwrap(&repo, &production, &bob));
    assert!(decrypt_as(&repo, &read(&repo, "p.env.amaga"), &bob).is_err());

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
    // carol is in `default` only: re-wrapping `production` must not reach her.
    let (carol_key, _carol_config) = second_identity(&repo, "carol");
    repo.run(&["user", "add", "carol", &carol_key])
        .assert_success();
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
    let carol = load_identity(&repo.path().join("carol-identity.txt"));
    assert!(!can_unwrap(&repo, &epoch_id, &carol));
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

/// Test 64: the attribute picks the partition at `add` only. A later change makes `status` fail,
/// but `rotate` follows the label and never widens access (decision 17).
#[test]
fn partition_is_chosen_at_add_and_attribute_never_moves_it() {
    let (repo, _identity_path, bob_config) = repo_with_alice_and_bob();
    repo.run(&["partition", "create", "production", "alice"])
        .assert_success();
    let attributes = repo.path().join(".gitattributes");
    let original = std::fs::read_to_string(&attributes).unwrap();
    std::fs::write(
        &attributes,
        format!("{original}prod/** amaga-partition=production\n"),
    )
    .unwrap();
    let with_production = std::fs::read_to_string(&attributes).unwrap();
    std::fs::create_dir(repo.path().join("prod")).unwrap();
    add_secret(&repo, "prod/db.env", b"db");
    let ciphertext = read(&repo, "prod/db.env.amaga");
    let label = git_amaga_core::secret::label_of("prod/db.env.amaga", &ciphertext).unwrap();
    assert_eq!(label, "production");
    repo.commit_all("add prod/db.env");

    std::fs::write(
        &attributes,
        with_production.replace("=production", "=default"),
    )
    .unwrap();
    repo.commit_all("point the attribute at default");
    let status = repo.run(&["status"]);
    status.assert_failure();
    assert!(stdout(&status).contains(".gitattributes says default"));
    repo.run(&["rotate"]).assert_success();
    let ciphertext = read(&repo, "prod/db.env.amaga");
    let label = git_amaga_core::secret::label_of("prod/db.env.amaga", &ciphertext).unwrap();
    assert_eq!(label, "production");
    std::fs::remove_file(repo.path().join("prod/db.env")).unwrap();
    run_as(&repo, &bob_config, &["open", "prod/db.env"]).assert_failure();

    std::fs::write(&attributes, with_production).unwrap();
    repo.run(&["status"]).assert_success();
}

/// An attribute that is set or unset without a value, empty, or not a partition name is refused
/// at `add`, and nothing falls back to `default`.
#[test]
fn add_refuses_an_attribute_without_a_partition_name() {
    let (repo, _identity_path) = repo_with_alice();
    let attributes = repo.path().join(".gitattributes");
    let original = std::fs::read_to_string(&attributes).unwrap();
    std::fs::write(repo.path().join("a.env"), b"a").unwrap();

    for attr in [
        "amaga-partition",
        "-amaga-partition",
        "amaga-partition=Prod",
        "amaga-partition=",
    ] {
        std::fs::write(&attributes, format!("{original}*.env {attr}\n")).unwrap();
        let add = repo.run(&["add", "a.env"]);
        add.assert_failure();
        assert!(
            stderr(&add).contains("amaga-partition"),
            "{attr}: {}",
            stderr(&add)
        );
        assert!(!repo.path().join("a.env.amaga").exists(), "{attr}");
    }
}

/// `user remove` also re-encrypts a partition whose `members` no longer list the name but whose
/// current epoch is still wrapped to them (a hand edit, or an interrupted run).
#[test]
fn user_remove_rotates_a_partition_whose_epoch_still_holds_the_user() {
    let (repo, _identity_path, _bob_config) = repo_with_alice_and_bob();
    std::fs::write(
        repo.path().join(".amaga/partitions/default/members"),
        "alice\n",
    )
    .unwrap();

    repo.run(&["user", "remove", "bob"]).assert_success();

    let bob = load_identity(&repo.path().join("bob-identity.txt"));
    assert!(!can_unwrap(
        &repo,
        &current_epoch_id(&repo, "default"),
        &bob
    ));
}

/// `user add` refuses a name that a `members` file still lists, so a stale name cannot give a new
/// member that partition's access.
#[test]
fn user_add_refuses_a_name_still_listed_in_a_partition() {
    let (repo, _identity_path) = repo_with_alice();
    repo.run(&["partition", "create", "production", "alice"])
        .assert_success();
    let members = ".amaga/partitions/production/members";
    std::fs::write(repo.path().join(members), "alice\ndave\n").unwrap();
    let before = read(&repo, ".amaga/audit.jsonl");

    let (dave_key, _config) = second_identity(&repo, "dave");
    let add = repo.run(&["user", "add", "dave", &dave_key]);
    add.assert_failure();
    assert!(
        stderr(&add).contains("partition remove production dave"),
        "{}",
        stderr(&add)
    );
    assert!(!repo.path().join(".amaga/users/dave.txt").exists());
    assert_eq!(read(&repo, ".amaga/audit.jsonl"), before);
}

/// A non-member naming another partition's secret gets the access error, not an epoch error and
/// not the `git rm` hint of `remove`.
#[test]
fn non_members_get_not_in_partition_for_seal_dismiss_and_remove() {
    let (repo, _identity_path, bob_config) = repo_with_alice_and_bob();
    repo.run(&["partition", "create", "production", "alice"])
        .assert_success();
    std::fs::write(repo.path().join("p.env"), b"prod").unwrap();
    repo.run(&["add", "--partition", "production", "p.env"])
        .assert_success();

    for args in [
        vec!["seal", "p.env"],
        vec!["dismiss", "--user", "alice", "p.env"],
        vec!["remove", "p.env"],
    ] {
        let output = run_as(&repo, &bob_config, &args);
        output.assert_failure();
        let err = stderr(&output);
        assert!(
            err.contains("not a member of partition 'production'"),
            "{args:?}: {err}"
        );
        assert!(!err.contains("git rm"), "{args:?}: {err}");
    }
}

/// `user add --partition` runs the access check and the stale guard for each named partition,
/// and writes nothing when one fails.
#[test]
fn user_add_partition_checks_access_and_staleness() {
    let (repo, _identity_path, bob_config) = repo_with_alice_and_bob();
    repo.run(&["partition", "create", "production", "alice"])
        .assert_success();
    let (carol_key, _carol_config) = second_identity(&repo, "carol");
    let before = read(&repo, ".amaga/audit.jsonl");

    // bob is not in `production`.
    let denied = run_as(
        &repo,
        &bob_config,
        &[
            "user",
            "add",
            "carol",
            &carol_key,
            "--partition",
            "production",
        ],
    );
    denied.assert_failure();
    assert!(
        stderr(&denied).contains("not a member of partition 'production'"),
        "{}",
        stderr(&denied)
    );

    // `production` is stale after a hand edit, while `default` is fine.
    let members = repo.path().join(".amaga/partitions/production/members");
    std::fs::write(&members, "alice\nbob\n").unwrap();
    let stale = repo.run(&[
        "user",
        "add",
        "carol",
        &carol_key,
        "--partition",
        "default",
        "--partition",
        "production",
    ]);
    stale.assert_failure();
    assert!(
        stderr(&stale).contains("rotate --partition production"),
        "{}",
        stderr(&stale)
    );
    assert!(!repo.path().join(".amaga/users/carol.txt").exists());
    assert_eq!(read(&repo, ".amaga/audit.jsonl"), before);
}

/// `partition move` refuses a target the actor is not in or that is stale, and leaves a secret
/// that is already in the target byte for byte.
#[test]
fn partition_move_checks_the_target_and_skips_secrets_already_there() {
    let (repo, _identity_path, bob_config) = repo_with_alice_and_bob();
    repo.run(&["partition", "create", "production", "alice"])
        .assert_success();
    std::fs::write(repo.path().join("p.env"), b"prod").unwrap();
    repo.run(&["add", "--partition", "production", "p.env"])
        .assert_success();
    add_secret(&repo, "d.env", b"dev");
    let (p_before, d_before) = (read(&repo, "p.env.amaga"), read(&repo, "d.env.amaga"));

    let denied = run_as(
        &repo,
        &bob_config,
        &["partition", "move", "production", "d.env"],
    );
    denied.assert_failure();
    assert!(
        stderr(&denied).contains("not a member of partition 'production'"),
        "{}",
        stderr(&denied)
    );
    assert_eq!(read(&repo, "d.env.amaga"), d_before);

    repo.run(&["partition", "move", "production", "p.env", "d.env"])
        .assert_success();
    assert_eq!(read(&repo, "p.env.amaga"), p_before);
    assert_ne!(read(&repo, "d.env.amaga"), d_before);

    let members = repo.path().join(".amaga/partitions/production/members");
    std::fs::write(&members, "alice\nbob\n").unwrap();
    repo.run(&["partition", "move", "default", "d.env"])
        .assert_success();
    let d_back = read(&repo, "d.env.amaga");
    let stale = repo.run(&["partition", "move", "production", "d.env"]);
    stale.assert_failure();
    assert!(
        stderr(&stale).contains("rotate --partition production"),
        "{}",
        stderr(&stale)
    );
    assert_eq!(read(&repo, "d.env.amaga"), d_back);
}
