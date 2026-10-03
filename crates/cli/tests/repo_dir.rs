//! `-C <path>` / `--repo <path>`: every command runs as if started in that directory (ADR-0014).

mod common;

use common::{OutputExt, Repo, repo_with_alice};

/// A directory outside the repository, to start the binary from.
fn elsewhere() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

#[test]
fn status_add_and_open_work_on_the_repository_given_with_c() {
    let (repo, _identity) = repo_with_alice();
    let cwd = elsewhere();
    let repo_arg = repo.path().to_str().unwrap();

    // Without -C the unrelated directory is not a repository.
    repo.run_in(cwd.path(), &["status"]).assert_failure();

    let status = repo.run_in(cwd.path(), &["-C", repo_arg, "status"]);
    status.assert_success();
    assert!(String::from_utf8_lossy(&status.stdout).contains("members: alice"));
    repo.run_in(cwd.path(), &["--repo", repo_arg, "status"])
        .assert_success();

    std::fs::write(repo.path().join("prod.env"), b"v1").unwrap();
    let add = repo.run_in(cwd.path(), &["-C", repo_arg, "add", "prod.env"]);
    add.assert_success();
    assert!(String::from_utf8_lossy(&add.stdout).contains("added prod.env.amaga"));
    assert!(repo.path().join("prod.env.amaga").is_file());

    std::fs::remove_file(repo.path().join("prod.env")).unwrap();
    repo.run_in(cwd.path(), &["status", "-C", repo_arg])
        .assert_success();
    repo.run_in(cwd.path(), &["-C", repo_arg, "open"])
        .assert_success();
    assert_eq!(std::fs::read(repo.path().join("prod.env")).unwrap(), b"v1");
}

#[test]
fn relative_path_arguments_resolve_against_the_c_directory() {
    let (repo, _identity) = repo_with_alice();
    let cwd = elsewhere();
    let sub = repo.path().join("sub");
    std::fs::create_dir(&sub).unwrap();
    std::fs::write(sub.join("a.env"), b"a").unwrap();
    std::fs::write(sub.join("b.env"), b"b").unwrap();

    repo.run_in(cwd.path(), &["-C", sub.to_str().unwrap(), "add", "a.env"])
        .assert_success();
    assert!(sub.join("a.env.amaga").is_file());

    // A relative -C is relative to the process's directory.
    repo.run_in(repo.path(), &["-C", "sub", "add", "b.env"])
        .assert_success();
    assert!(sub.join("b.env.amaga").is_file());
}

#[test]
fn relative_asc_key_resolves_against_the_c_directory() {
    let (repo, _identity) = repo_with_alice();
    let cwd = elsewhere();
    let keys = repo.path().join("keys");
    std::fs::create_dir(&keys).unwrap();
    let armored = include_str!("../../core/tests/fixtures/valid_cv25519.asc");
    std::fs::write(keys.join("bob-key.asc"), armored).unwrap();

    let add = repo.run_in(
        cwd.path(),
        &[
            "-C",
            keys.to_str().unwrap(),
            "user",
            "add",
            "bob",
            "bob-key.asc",
        ],
    );

    add.assert_success();
    let stored = std::fs::read_to_string(repo.path().join(".amaga/users/bob.asc")).unwrap();
    assert_eq!(stored, armored);
}

#[test]
fn keygen_path_resolves_against_the_c_directory() {
    let repo = Repo::new();
    let cwd = elsewhere();

    repo.run_in(
        cwd.path(),
        &["-C", repo.path().to_str().unwrap(), "keygen", "id.txt"],
    )
    .assert_success();

    assert!(repo.path().join("id.txt").is_file());
    assert!(!cwd.path().join("id.txt").exists());
}

#[test]
fn relative_amaga_identity_resolves_against_the_c_directory() {
    let (repo, _identity) = repo_with_alice();
    let cwd = elsewhere();
    let repo_arg = repo.path().to_str().unwrap();
    std::fs::write(repo.path().join("prod.env"), b"v1").unwrap();
    repo.run(&["add", "prod.env"]).assert_success();
    std::fs::remove_file(repo.path().join("prod.env")).unwrap();
    repo.git(&["config", "--global", "amaga.identity", "identity.txt"])
        .assert_success();

    repo.run_in(cwd.path(), &["-C", repo_arg, "open"])
        .assert_success();

    assert_eq!(std::fs::read(repo.path().join("prod.env")).unwrap(), b"v1");
}

#[test]
fn an_unusable_c_directory_is_an_error_naming_it() {
    let (repo, _identity) = repo_with_alice();
    let missing = repo.path().join("missing");
    let file = repo.path().join("identity.txt");

    for path in [&missing, &file] {
        let output = repo.run(&["-C", path.to_str().unwrap(), "status"]);

        output.assert_failure();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(path.to_str().unwrap()), "{stderr}");
    }
}

#[test]
fn keygen_in_an_unusable_c_directory_writes_and_configures_nothing() {
    let repo = Repo::new();
    let missing = repo.path().join("missing");
    let file = repo.path().join("file");
    std::fs::write(&file, "").unwrap();

    for path in [&missing, &file] {
        repo.run(&["-C", path.to_str().unwrap(), "keygen", "id.txt"])
            .assert_failure();
    }

    assert!(!missing.exists());
    assert!(file.is_file());
    let configured = repo.git(&["config", "--global", "--get", "amaga.identity"]);
    assert_eq!(configured.status.code(), Some(1), "amaga.identity is set");
}
