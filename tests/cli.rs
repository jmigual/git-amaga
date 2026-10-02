mod common;

use common::{OutputExt, Repo};

#[test]
fn keygen_writes_identity_refuses_overwrite_and_sets_global_identity() {
    let repo = Repo::new();
    let identity_path = repo.path().join("identity.txt");

    let keygen = repo.run(&["keygen", identity_path.to_str().unwrap()]);
    keygen.assert_success();
    let public_key = String::from_utf8_lossy(&keygen.stdout).trim().to_string();
    assert!(public_key.starts_with("age1"), "got {public_key:?}");
    assert!(identity_path.is_file());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&identity_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    // Refuses to overwrite.
    repo.run(&["keygen", identity_path.to_str().unwrap()])
        .assert_failure();

    // Sets amaga.identity globally, since it was unset.
    let configured = repo.git(&["config", "--global", "--get", "amaga.identity"]);
    configured.assert_success();
    assert_eq!(
        String::from_utf8_lossy(&configured.stdout).trim(),
        identity_path.to_str().unwrap()
    );
}

#[test]
fn keygen_with_relative_path_stores_absolute_identity() {
    let repo = Repo::new();

    repo.run(&["keygen", "id.txt"]).assert_success();

    let configured = repo.git(&["config", "--global", "--get", "amaga.identity"]);
    configured.assert_success();
    let stored = String::from_utf8_lossy(&configured.stdout)
        .trim()
        .to_string();
    assert!(
        std::path::Path::new(&stored).is_absolute(),
        "expected an absolute path, got {stored:?}"
    );
    assert!(std::path::Path::new(&stored).is_file());
}

#[test]
fn keygen_does_not_overwrite_an_already_configured_global_identity() {
    let repo = Repo::new();
    repo.git(&[
        "config",
        "--global",
        "amaga.identity",
        "/preexisting/identity.txt",
    ])
    .assert_success();

    repo.run(&["keygen", "other.txt"]).assert_success();

    let configured = repo.git(&["config", "--global", "--get", "amaga.identity"]);
    configured.assert_success();
    assert_eq!(
        String::from_utf8_lossy(&configured.stdout).trim(),
        "/preexisting/identity.txt"
    );
}

/// Test 1 (plan section 11): `keygen` then `init` with no `KEY` creates the member file from the
/// configured identity, the `.gitattributes`/`.gitignore` lines, and the `init` audit event.
#[test]
fn keygen_then_init_creates_state() {
    let repo = Repo::new();
    let identity_path = repo.path().join("identity.txt");

    let keygen = repo.run(&["keygen", identity_path.to_str().unwrap()]);
    keygen.assert_success();
    let public_key = String::from_utf8_lossy(&keygen.stdout).trim().to_string();

    repo.run(&["init", "alice"]).assert_success();

    let user_file = repo.path().join(".amaga/users/alice.txt");
    assert!(user_file.is_file());
    assert_eq!(
        std::fs::read_to_string(&user_file).unwrap().trim(),
        public_key
    );

    let gitattributes = std::fs::read_to_string(repo.path().join(".gitattributes")).unwrap();
    assert!(gitattributes.contains("*.amaga binary"));
    assert!(gitattributes.contains(".amaga/audit.jsonl merge=union"));
    assert!(gitattributes.contains(".gitignore merge=union"));

    let gitignore = std::fs::read_to_string(repo.path().join(".gitignore")).unwrap();
    assert!(gitignore.contains("# BEGIN git-amaga"));
    assert!(gitignore.contains("*.amaga-tmp"));

    let audit = std::fs::read_to_string(repo.path().join(".amaga/audit.jsonl")).unwrap();
    assert!(audit.contains("\"actor\":\"alice\""));
    assert!(audit.contains("\"event\":\"init\""));

    // Refuses to run again once `.amaga/` exists.
    repo.run(&["init", "bob"]).assert_failure();
}

/// Regression for the bug where `keygen` stored a relative path in `amaga.identity`: a later
/// command run from a different working directory would resolve it against the wrong cwd.
#[test]
fn keygen_then_init_from_a_different_directory_succeeds() {
    let repo = Repo::new();
    let keygen_dir = repo.path().join("keygen-here");
    std::fs::create_dir(&keygen_dir).unwrap();

    repo.run_in(&keygen_dir, &["keygen", "id.txt"])
        .assert_success();
    assert!(keygen_dir.join("id.txt").is_file());

    let init_dir = repo.path().join("init-from-here");
    std::fs::create_dir(&init_dir).unwrap();
    repo.run_in(&init_dir, &["init", "alice"]).assert_success();

    assert!(repo.path().join(".amaga/users/alice.txt").is_file());
}

#[test]
fn init_with_empty_identity_file_fails_and_creates_nothing() {
    let repo = Repo::new();
    let identity_path = repo.path().join("identity.txt");
    std::fs::write(&identity_path, "# no keys here\n\n").unwrap();
    repo.git(&[
        "config",
        "--global",
        "amaga.identity",
        identity_path.to_str().unwrap(),
    ])
    .assert_success();

    let init = repo.run(&["init", "alice"]);
    init.assert_failure();
    assert!(
        String::from_utf8_lossy(&init.stderr).contains("keygen"),
        "expected the NoIdentity hint to mention keygen, got {:?}",
        String::from_utf8_lossy(&init.stderr)
    );

    assert!(!repo.path().join(".amaga").exists());
}

/// Regression: `init` used to create `.amaga/users/<name>.txt` before updating
/// `.gitattributes`/`.gitignore`, so a failure in either of those (for example an unreadable
/// `.gitignore`) left a half-initialized `.amaga/` that a retry would then refuse with
/// AlreadyInitialized.
#[cfg(unix)]
#[test]
fn init_fails_on_unreadable_gitignore_and_creates_nothing() {
    use std::os::unix::fs::PermissionsExt;

    let repo = Repo::new();
    let gitignore_path = repo.path().join(".gitignore");
    std::fs::write(&gitignore_path, "*.log\n").unwrap();
    std::fs::set_permissions(&gitignore_path, std::fs::Permissions::from_mode(0o000)).unwrap();

    if std::fs::read(&gitignore_path).is_ok() {
        std::fs::set_permissions(&gitignore_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        println!(
            "skipping init_fails_on_unreadable_gitignore_and_creates_nothing: running as root"
        );
        return;
    }

    repo.run(&["keygen", "id.txt"]).assert_success();

    repo.run(&["init", "alice"]).assert_failure();

    std::fs::set_permissions(&gitignore_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!repo.path().join(".amaga").exists());
}

#[test]
fn init_deduplicates_a_key_given_twice() {
    let repo = Repo::new();
    let keygen = repo.run(&["keygen", "id.txt"]);
    keygen.assert_success();
    let public_key = String::from_utf8_lossy(&keygen.stdout).trim().to_string();

    repo.run(&["init", "alice", &public_key, &public_key])
        .assert_success();

    let user_file = repo.path().join(".amaga/users/alice.txt");
    let contents = std::fs::read_to_string(&user_file).unwrap();
    assert_eq!(contents.lines().count(), 1);
    assert_eq!(contents.trim(), public_key);
}
