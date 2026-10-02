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

/// A repository with one age member `alice`, plus the identity file path.
fn repo_with_alice() -> (Repo, std::path::PathBuf) {
    let repo = Repo::new();
    let identity_path = repo.path().join("identity.txt");
    repo.run(&["keygen", identity_path.to_str().unwrap()])
        .assert_success();
    repo.run(&["init", "alice"]).assert_success();
    (repo, identity_path)
}

/// Overwrites `secret.env.amaga` with a fresh encryption of `body` to alice, standing in for a
/// teammate's push. Returns the new ciphertext.
fn rotate_ciphertext(repo: &Repo, body: &[u8]) -> Vec<u8> {
    let members = git_amaga::users::load(&repo.path().join(".amaga/users")).unwrap();
    let header =
        git_amaga::secret::next_header(None, false, &git_amaga::users::recipients(&members));
    let alice = members["alice"].age_keys[0].clone();
    let ciphertext =
        git_amaga::secret::encrypt(&header, body, &[&alice as &dyn age::Recipient]).unwrap();
    std::fs::write(repo.path().join("secret.env.amaga"), &ciphertext).unwrap();
    ciphertext
}

/// Test 3: `add` refuses tracked plaintext and prints the `git rm --cached` remediation.
#[test]
fn add_refuses_tracked_plaintext() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("secret.env"), b"hello").unwrap();
    repo.git(&["add", "secret.env"]).assert_success();

    let add = repo.run(&["add", "secret.env"]);
    add.assert_failure();
    let stderr = String::from_utf8_lossy(&add.stderr);
    assert!(stderr.contains("git rm --cached"), "got {stderr:?}");
    assert!(!repo.path().join("secret.env.amaga").exists());
}

/// Test 4: `add` makes the plaintext ignored.
#[test]
fn add_makes_plaintext_ignored() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("secret.env"), b"hello").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();

    repo.git(&["check-ignore", "-q", "secret.env"])
        .assert_success();
}

/// Test 5: sealing unchanged plaintext leaves the ciphertext bytes identical.
#[test]
fn seal_unchanged_is_noop() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("secret.env"), b"hello").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();

    let before = std::fs::read(repo.path().join("secret.env.amaga")).unwrap();
    repo.run(&["seal", "secret.env"]).assert_success();
    let after = std::fs::read(repo.path().join("secret.env.amaga")).unwrap();
    assert_eq!(before, after);
}

/// Test 6 (change 7): `seal` must not overwrite a rotated ciphertext with stale plaintext.
#[test]
fn seal_refuses_outdated_plaintext_after_pull() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();

    let pulled = rotate_ciphertext(&repo, b"v2-from-teammate");
    let cipher_path = repo.path().join("secret.env.amaga");

    let seal = repo.run(&["seal", "secret.env"]);
    seal.assert_failure();
    assert_eq!(
        std::fs::read(&cipher_path).unwrap(),
        pulled,
        "seal must not overwrite the rotated ciphertext without --force"
    );

    repo.run(&["seal", "--force", "secret.env"])
        .assert_success();
    assert_ne!(
        std::fs::read(&cipher_path).unwrap(),
        pulled,
        "seal --force must write the local (stale) plaintext back"
    );
}

/// Test 23: re-adding a secret whose ciphertext is in history needs `--force`.
#[test]
fn readd_deleted_secret_requires_force() {
    let (repo, identity_path) = repo_with_alice();

    let members = git_amaga::users::load(&repo.path().join(".amaga/users")).unwrap();
    let recipients = git_amaga::users::recipients(&members);
    let age_recipient = members["alice"].age_keys[0].clone();
    let mut exposed_to = git_amaga::secret::Recipients::new();
    exposed_to.insert(
        "charlie".to_string(),
        std::collections::BTreeSet::from(["age1charliestalekey".to_string()]),
    );
    let header = git_amaga::secret::Header {
        v: 1,
        recipients,
        exposed_to,
    };
    let body: &[u8] = b"v1";
    let original =
        git_amaga::secret::encrypt(&header, body, &[&age_recipient as &dyn age::Recipient])
            .unwrap();
    let cipher_path = repo.path().join("secret.env.amaga");
    std::fs::write(&cipher_path, &original).unwrap();
    repo.git(&[
        "add",
        ".gitattributes",
        ".gitignore",
        ".amaga",
        "secret.env.amaga",
    ])
    .assert_success();
    repo.git(&["commit", "-m", "synthetic exposed secret"])
        .assert_success();

    std::fs::remove_file(&cipher_path).unwrap();
    repo.git(&["add", "secret.env.amaga"]).assert_success();
    repo.git(&["commit", "-m", "remove secret"])
        .assert_success();

    std::fs::write(repo.path().join("secret.env"), body).unwrap();
    repo.run(&["add", "secret.env"]).assert_failure();
    assert!(!cipher_path.exists());

    let forced = repo.run(&["add", "--force", "secret.env"]);
    forced.assert_success();
    assert!(
        String::from_utf8_lossy(&forced.stderr).contains("exposure history is dropped"),
        "got {:?}",
        String::from_utf8_lossy(&forced.stderr)
    );
    let identities = git_amaga::identity::load_identity_file(&identity_path).unwrap();
    let id_refs: Vec<&dyn age::Identity> =
        identities.iter().map(|i| i as &dyn age::Identity).collect();
    let (forced_header, _) =
        git_amaga::secret::decrypt(&std::fs::read(&cipher_path).unwrap(), &id_refs).unwrap();
    assert!(
        forced_header.exposed_to.is_empty(),
        "add --force drops exposure history"
    );

    repo.git(&["checkout", "HEAD~1", "--", "secret.env.amaga"])
        .assert_success();
    repo.run(&["seal", "secret.env"]).assert_success();
    let (restored_header, _) =
        git_amaga::secret::decrypt(&std::fs::read(&cipher_path).unwrap(), &id_refs).unwrap();
    assert_eq!(
        restored_header.exposed_to.len(),
        1,
        "seal on an unchanged restore must keep exposed_to"
    );
}

/// `seal` also runs the ensure-ignored step (plan 5.4).
#[test]
fn seal_makes_renamed_plaintext_ignored() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("a.env"), b"v1").unwrap();
    repo.run(&["add", "a.env"]).assert_success();
    repo.git(&["add", ".gitattributes", ".amaga", "a.env.amaga"])
        .assert_success();
    repo.git(&["commit", "-m", "add a.env"]).assert_success();
    repo.git(&["mv", "a.env.amaga", "b.env.amaga"])
        .assert_success();

    std::fs::write(repo.path().join("b.env"), b"v1").unwrap();
    repo.run(&["seal", "b.env"]).assert_success();
    repo.git(&["check-ignore", "-q", "b.env"]).assert_success();
}

/// `add` refuses an existing `<path>.amaga`, even with `--force`.
#[test]
fn add_refuses_existing_ciphertext() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();
    let before = std::fs::read(repo.path().join("secret.env.amaga")).unwrap();

    std::fs::write(repo.path().join("secret.env"), b"v2").unwrap();
    repo.run(&["add", "secret.env"]).assert_failure();
    repo.run(&["add", "--force", "secret.env"]).assert_failure();
    assert_eq!(
        std::fs::read(repo.path().join("secret.env.amaga")).unwrap(),
        before
    );
}

/// `seal --force` of an `Outdated` file warns when it clears `exposed_to`.
#[test]
fn seal_force_warns_when_clearing_exposed_to() {
    let (repo, identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();

    let members = git_amaga::users::load(&repo.path().join(".amaga/users")).unwrap();
    let age_recipient = members["alice"].age_keys[0].clone();
    let mut header =
        git_amaga::secret::next_header(None, false, &git_amaga::users::recipients(&members));
    header.exposed_to.insert(
        "charlie".to_string(),
        std::collections::BTreeSet::from(["age1charliestalekey".to_string()]),
    );
    let pulled = git_amaga::secret::encrypt(
        &header,
        b"v2-rotated",
        &[&age_recipient as &dyn age::Recipient],
    )
    .unwrap();
    let cipher_path = repo.path().join("secret.env.amaga");
    std::fs::write(&cipher_path, &pulled).unwrap();

    repo.run(&["seal", "secret.env"]).assert_failure();
    assert_eq!(std::fs::read(&cipher_path).unwrap(), pulled);

    let forced = repo.run(&["seal", "--force", "secret.env"]);
    forced.assert_success();
    assert!(
        String::from_utf8_lossy(&forced.stderr).contains("NEEDS ROTATION"),
        "got {:?}",
        String::from_utf8_lossy(&forced.stderr)
    );
    let identities = git_amaga::identity::load_identity_file(&identity_path).unwrap();
    let id_refs: Vec<&dyn age::Identity> =
        identities.iter().map(|i| i as &dyn age::Identity).collect();
    let (sealed_header, body) =
        git_amaga::secret::decrypt(&std::fs::read(&cipher_path).unwrap(), &id_refs).unwrap();
    assert!(sealed_header.exposed_to.is_empty());
    assert_eq!(body, b"v1");
}

/// `add` and a sealed edit append `secret.added` / `secret.updated`; a no-op seal does not.
#[test]
fn add_and_seal_append_audit_events() {
    let (repo, _identity_path) = repo_with_alice();
    let audit_path = repo.path().join(".amaga/audit.jsonl");

    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();
    repo.run(&["seal", "secret.env"]).assert_success();
    std::fs::write(repo.path().join("secret.env"), b"v2").unwrap();
    repo.run(&["seal", "secret.env"]).assert_success();

    let audit = std::fs::read_to_string(&audit_path).unwrap();
    let lines: Vec<&str> = audit.lines().collect();
    assert_eq!(
        lines.len(),
        3,
        "init, secret.added, secret.updated: {audit}"
    );
    assert!(lines[1].contains("\"event\":\"secret.added\""));
    assert!(lines[1].contains("\"path\":\"secret.env\""));
    assert!(lines[1].contains("\"actor\":\"alice\""));
    assert!(lines[2].contains("\"event\":\"secret.updated\""));
    assert!(lines[2].contains("\"path\":\"secret.env\""));
}

/// Test 27: `NotAMember` names every member.
#[test]
fn no_identity_error_lists_members() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(
        repo.path().join(".amaga/users/bob.asc"),
        include_str!("fixtures/valid_cv25519.asc"),
    )
    .unwrap();
    repo.git(&["config", "--global", "--unset", "amaga.identity"])
        .assert_success();

    std::fs::write(repo.path().join("secret.env"), b"hello").unwrap();
    let add = repo.run(&["add", "secret.env"]);
    add.assert_failure();
    let stderr = String::from_utf8_lossy(&add.stderr);
    assert!(stderr.contains("alice"), "got {stderr:?}");
    assert!(stderr.contains("bob"), "got {stderr:?}");
    assert!(stderr.contains("not a member"), "got {stderr:?}");
}

/// Two edits sealed in a row need no `--force`: `seal` records the new base.
#[test]
fn seal_after_seal_needs_no_force() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();
    std::fs::write(repo.path().join("secret.env"), b"v2").unwrap();
    repo.run(&["seal", "secret.env"]).assert_success();
    std::fs::write(repo.path().join("secret.env"), b"v3").unwrap();
    repo.run(&["seal", "secret.env"]).assert_success();
}

/// An in-sync `seal` restores a lost base entry, so a later edit is `Modified`, not `Conflict`.
#[test]
fn insync_seal_restores_a_lost_base() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();
    std::fs::remove_file(repo.path().join(".git/amaga-base")).unwrap();

    repo.run(&["seal", "secret.env"]).assert_success();
    std::fs::write(repo.path().join("secret.env"), b"v2").unwrap();
    repo.run(&["seal", "secret.env"]).assert_success();
}

/// `add` refuses a symlink and creates no ciphertext.
#[cfg(unix)]
#[test]
fn add_refuses_symlink() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("target.txt"), b"x").unwrap();
    std::os::unix::fs::symlink("target.txt", repo.path().join("secret.env")).unwrap();

    repo.run(&["add", "secret.env"]).assert_failure();
    assert!(!repo.path().join("secret.env.amaga").exists());
}

/// `add` warns when the plaintext path was committed once, then untracked.
#[test]
fn add_warns_when_plaintext_is_in_history() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.git(&["add", "secret.env"]).assert_success();
    repo.git(&["commit", "-m", "oops"]).assert_success();
    repo.git(&["rm", "--cached", "-q", "secret.env"])
        .assert_success();
    repo.git(&["commit", "-m", "untrack"]).assert_success();

    let add = repo.run(&["add", "secret.env"]);
    add.assert_success();
    assert!(String::from_utf8_lossy(&add.stderr).contains("appears in git history"));
    assert!(repo.path().join("secret.env.amaga").exists());
}

/// `seal` of a file that is not a secret fails before touching `.gitignore`.
#[test]
fn seal_unmanaged_file_does_not_touch_gitignore() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("README.md"), b"hi").unwrap();
    repo.run(&["seal", "README.md"]).assert_failure();

    let gitignore = std::fs::read_to_string(repo.path().join(".gitignore")).unwrap();
    assert!(!gitignore.contains("README"), "got {gitignore:?}");
}

/// A path starting with `:` is a literal path, not pathspec magic: `x.env` being ignored and
/// having `x.env.amaga` in history must not leak onto `:x.env`.
#[cfg(unix)]
#[test]
fn add_treats_a_leading_colon_as_a_literal_path() {
    let (repo, _identity_path) = repo_with_alice();
    let gitignore = repo.path().join(".gitignore");
    let mut contents = std::fs::read_to_string(&gitignore).unwrap();
    contents.push_str("/x.env\n");
    std::fs::write(&gitignore, contents).unwrap();
    std::fs::write(repo.path().join("x.env.amaga"), b"old").unwrap();
    repo.git(&["add", "x.env.amaga"]).assert_success();
    repo.git(&["commit", "-m", "old"]).assert_success();
    repo.git(&["rm", "-q", "x.env.amaga"]).assert_success();
    repo.git(&["commit", "-m", "gone"]).assert_success();

    std::fs::write(repo.path().join(":x.env"), b"v1").unwrap();
    repo.run(&["add", ":x.env"]).assert_success();

    repo.git(&["check-ignore", "-q", "--no-index", "--", "./:x.env"])
        .assert_success();
}

/// A tracked `:x.env` is found even though `x.env` is not tracked.
#[cfg(unix)]
#[test]
fn add_refuses_tracked_plaintext_with_a_leading_colon() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join(":x.env"), b"v1").unwrap();
    repo.git(&["add", "--", "./:x.env"]).assert_success();

    repo.run(&["add", ":x.env"]).assert_failure();
    assert!(!repo.path().join(":x.env.amaga").exists());
}
