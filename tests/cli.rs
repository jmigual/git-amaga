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
