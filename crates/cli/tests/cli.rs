mod common;

use common::{OutputExt, Repo, repo_with_alice};

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

/// Overwrites `secret.env.amaga` with a fresh encryption of `body` to alice, standing in for a
/// teammate's push. Returns the new ciphertext.
fn rotate_ciphertext(repo: &Repo, body: &[u8]) -> Vec<u8> {
    let members = git_amaga_core::users::load(&repo.path().join(".amaga/users")).unwrap();
    let header = git_amaga_core::secret::next_header(
        None,
        false,
        &git_amaga_core::users::recipients(&members),
    );
    let alice = members["alice"].age_keys[0].clone();
    let ciphertext =
        git_amaga_core::secret::encrypt(&header, body, &[&alice as &dyn age::Recipient]).unwrap();
    std::fs::write(repo.path().join("secret.env.amaga"), &ciphertext).unwrap();
    ciphertext
}

/// Test 2: NUL, CRLF and a missing trailing newline round-trip exactly.
#[test]
fn roundtrip_text_and_binary_exact_bytes() {
    let (repo, _identity_path) = repo_with_alice();

    let body: &[u8] = b"line1\r\nline2\x00binary\r\nno trailing newline";
    std::fs::write(repo.path().join("secret.env"), body).unwrap();
    repo.run(&["add", "secret.env"]).assert_success();

    std::fs::remove_file(repo.path().join("secret.env")).unwrap();
    repo.run(&["open", "secret.env"]).assert_success();

    assert_eq!(std::fs::read(repo.path().join("secret.env")).unwrap(), body);
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
    assert_status_error(&repo, "outdated");

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

/// Test 7: `open` replaces unmodified plaintext after the ciphertext changed.
#[test]
fn open_updates_outdated_unmodified_plaintext() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();

    rotate_ciphertext(&repo, b"v2");

    repo.run(&["open", "secret.env"]).assert_success();
    assert_eq!(
        std::fs::read(repo.path().join("secret.env")).unwrap(),
        b"v2"
    );
    assert!(status_stdout(&repo).contains("ok secret.env.amaga: in sync"));
}

/// Test 8: `open` refuses to discard local edits without `--force`.
#[test]
fn open_refuses_local_edits() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();

    std::fs::write(repo.path().join("secret.env"), b"locally edited").unwrap();
    assert_status_error(&repo, "local edits");

    repo.run(&["open", "secret.env"]).assert_failure();
    assert_eq!(
        std::fs::read(repo.path().join("secret.env")).unwrap(),
        b"locally edited"
    );

    repo.run(&["open", "--force", "secret.env"])
        .assert_success();
    assert_eq!(
        std::fs::read(repo.path().join("secret.env")).unwrap(),
        b"v1"
    );
}

/// Test 9: `close` refuses to delete unsealed plaintext.
#[test]
fn close_refuses_unsealed() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();

    std::fs::write(repo.path().join("secret.env"), b"edited, not sealed").unwrap();
    assert_status_error(&repo, "local edits");

    repo.run(&["close", "secret.env"]).assert_failure();
    assert!(repo.path().join("secret.env").exists());

    repo.run(&["seal", "secret.env"]).assert_success();
    repo.run(&["close", "secret.env"]).assert_success();
    assert!(!repo.path().join("secret.env").exists());
    assert!(status_stdout(&repo).contains("ok secret.env.amaga: closed"));
}

/// Test 11: a corrupted ciphertext fails, names the file and writes no plaintext.
#[test]
fn tampered_ciphertext_fails_and_writes_nothing() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("secret.env"), b"hello").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();
    std::fs::remove_file(repo.path().join("secret.env")).unwrap();

    let cipher_path = repo.path().join("secret.env.amaga");
    let mut bytes = std::fs::read(&cipher_path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&cipher_path, &bytes).unwrap();

    let open = repo.run(&["open", "secret.env"]);
    open.assert_failure();
    assert!(String::from_utf8_lossy(&open.stderr).contains("secret.env.amaga"));
    assert!(!repo.path().join("secret.env").exists());
}

/// Test 21: `open` on a `git mv`-ed secret ignores the new plaintext path.
#[test]
fn renamed_secret_plaintext_stays_ignored() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("a.env"), b"v1").unwrap();
    repo.run(&["add", "a.env"]).assert_success();
    repo.git(&[
        "add",
        ".gitattributes",
        ".gitignore",
        ".amaga",
        "a.env.amaga",
    ])
    .assert_success();
    repo.git(&["commit", "-m", "add a.env"]).assert_success();

    repo.git(&["mv", "a.env.amaga", "b.env.amaga"])
        .assert_success();

    repo.run(&["open", "b.env"]).assert_success();
    repo.git(&["check-ignore", "-q", "b.env"]).assert_success();
}

/// Test 23: re-adding a secret whose ciphertext is in history needs `--force`.
#[test]
fn readd_deleted_secret_requires_force() {
    let (repo, identity_path) = repo_with_alice();

    let members = git_amaga_core::users::load(&repo.path().join(".amaga/users")).unwrap();
    let recipients = git_amaga_core::users::recipients(&members);
    let age_recipient = members["alice"].age_keys[0].clone();
    let mut exposed_to = git_amaga_core::secret::Recipients::new();
    exposed_to.insert(
        "charlie".to_string(),
        std::collections::BTreeSet::from(["age1charliestalekey".to_string()]),
    );
    let header = git_amaga_core::secret::Header {
        v: 1,
        recipients,
        exposed_to,
    };
    let body: &[u8] = b"v1";
    let original =
        git_amaga_core::secret::encrypt(&header, body, &[&age_recipient as &dyn age::Recipient])
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
    let identities = git_amaga_core::identity::load_identity_file(&identity_path).unwrap();
    let id_refs: Vec<&dyn age::Identity> =
        identities.iter().map(|i| i as &dyn age::Identity).collect();
    let (forced_header, _) =
        git_amaga_core::secret::decrypt(&std::fs::read(&cipher_path).unwrap(), &id_refs).unwrap();
    assert!(
        forced_header.exposed_to.is_empty(),
        "add --force drops exposure history"
    );

    repo.git(&["checkout", "HEAD~1", "--", "secret.env.amaga"])
        .assert_success();
    repo.run(&["seal", "secret.env"]).assert_success();
    let (restored_header, _) =
        git_amaga_core::secret::decrypt(&std::fs::read(&cipher_path).unwrap(), &id_refs).unwrap();
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

    let members = git_amaga_core::users::load(&repo.path().join(".amaga/users")).unwrap();
    let age_recipient = members["alice"].age_keys[0].clone();
    let mut header = git_amaga_core::secret::next_header(
        None,
        false,
        &git_amaga_core::users::recipients(&members),
    );
    header.exposed_to.insert(
        "charlie".to_string(),
        std::collections::BTreeSet::from(["age1charliestalekey".to_string()]),
    );
    let pulled = git_amaga_core::secret::encrypt(
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
    let identities = git_amaga_core::identity::load_identity_file(&identity_path).unwrap();
    let id_refs: Vec<&dyn age::Identity> =
        identities.iter().map(|i| i as &dyn age::Identity).collect();
    let (sealed_header, body) =
        git_amaga_core::secret::decrypt(&std::fs::read(&cipher_path).unwrap(), &id_refs).unwrap();
    assert!(sealed_header.exposed_to.is_empty());
    assert_eq!(body, b"v1");
}

/// `open` writes plaintext with mode 0600.
#[cfg(unix)]
#[test]
fn open_writes_plaintext_with_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("secret.env"), b"hello").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();
    std::fs::remove_file(repo.path().join("secret.env")).unwrap();

    repo.run(&["open", "secret.env"]).assert_success();
    let mode = std::fs::metadata(repo.path().join("secret.env"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

/// An unreadable plaintext is an error, not an absent one that `open` overwrites.
#[cfg(unix)]
#[test]
fn open_does_not_overwrite_unreadable_plaintext() {
    use std::os::unix::fs::PermissionsExt;
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();
    let plaintext = repo.path().join("secret.env");
    std::fs::write(&plaintext, b"locally edited").unwrap();
    std::fs::set_permissions(&plaintext, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&plaintext).is_ok() {
        println!("skipping open_does_not_overwrite_unreadable_plaintext: permissions not enforced");
        return;
    }

    repo.run(&["open", "secret.env"]).assert_failure();
    std::fs::set_permissions(&plaintext, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(std::fs::read(&plaintext).unwrap(), b"locally edited");
}

/// A repository where `<name>.amaga` is unmerged: both branches added it, and `name` (its
/// plaintext) exists.
fn repo_with_unmerged_secret(name: &str) -> Repo {
    let (repo, _identity_path) = repo_with_alice();
    repo.git(&["add", ".gitattributes", ".gitignore", ".amaga"])
        .assert_success();
    repo.git(&["commit", "-m", "init"]).assert_success();
    let base_branch = String::from_utf8(repo.git(&["rev-parse", "--abbrev-ref", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_string();
    let ciphertext = format!("{name}.amaga");

    repo.git(&["checkout", "-b", "other"]).assert_success();
    std::fs::write(repo.path().join(name), b"from other").unwrap();
    repo.run(&["add", name]).assert_success();
    repo.git(&["add", ".gitignore", &ciphertext])
        .assert_success();
    repo.git(&["commit", "-m", "other adds the secret"])
        .assert_success();

    repo.git(&["checkout", &base_branch]).assert_success();
    std::fs::write(repo.path().join(name), b"from main").unwrap();
    // `other` already holds the ciphertext in history, so a plain `add` would refuse.
    repo.run(&["add", "--force", name]).assert_success();
    repo.git(&["add", ".gitignore", &ciphertext])
        .assert_success();
    repo.git(&["commit", "-m", "main adds the secret"])
        .assert_success();
    repo.git(&["merge", "other"]).assert_failure();
    assert!(
        !repo
            .git(&["ls-files", "-u", "--", "*.amaga"])
            .stdout
            .is_empty(),
        "merge should leave {ciphertext} unmerged"
    );
    repo
}

/// `add`, `seal`, `open` and `close` refuse while a `*.amaga` is unmerged.
#[test]
fn commands_refuse_during_amaga_merge_conflict() {
    let repo = repo_with_unmerged_secret("a.env");

    std::fs::write(repo.path().join("b.env"), b"b").unwrap();
    repo.run(&["add", "b.env"]).assert_failure();
    assert!(!repo.path().join("b.env.amaga").exists());
    repo.run(&["seal"]).assert_failure();
    repo.run(&["open"]).assert_failure();
    repo.run(&["close"]).assert_failure();
    assert!(repo.path().join("a.env").exists());

    // `status` still runs and lists the unmerged file instead of refusing.
    let status = repo.run(&["status"]);
    assert_eq!(status.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert!(
        stdout.contains("ERROR a.env.amaga: unmerged"),
        "got {stdout:?}"
    );
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

/// Test 24: a `core.autocrlf=true` clone opens; the `*.amaga binary` attribute must win over a
/// pre-existing `* text eol=crlf`.
#[test]
fn autocrlf_clone_opens() {
    let repo = Repo::new();
    std::fs::write(repo.path().join(".gitattributes"), "* text eol=crlf\n").unwrap();
    let identity_path = repo.path().join("identity.txt");
    repo.run(&["keygen", identity_path.to_str().unwrap()])
        .assert_success();
    repo.run(&["init", "alice"]).assert_success();
    repo.git(&["config", "core.autocrlf", "true"])
        .assert_success();

    std::fs::write(repo.path().join("secret.env"), b"hello").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();
    repo.git(&[
        "add",
        ".gitattributes",
        ".gitignore",
        ".amaga",
        "secret.env.amaga",
    ])
    .assert_success();
    repo.git(&["commit", "-m", "add secret"]).assert_success();

    let clone_parent = tempfile::tempdir().unwrap();
    let clone_dir = clone_parent.path().join("clone");
    repo.git_in(
        clone_parent.path(),
        &[
            "clone",
            "-c",
            "core.autocrlf=true",
            repo.path().to_str().unwrap(),
            clone_dir.to_str().unwrap(),
        ],
    )
    .assert_success();

    repo.run_in(&clone_dir, &["open", "secret.env"])
        .assert_success();
    assert_eq!(
        std::fs::read(clone_dir.join("secret.env")).unwrap(),
        b"hello"
    );
}

/// Test 27: `NotAMember` names every member.
#[test]
fn no_identity_error_lists_members() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(
        repo.path().join(".amaga/users/bob.asc"),
        include_str!("../../core/tests/fixtures/valid_cv25519.asc"),
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

/// `seal` and `open` without paths act on every secret.
#[test]
fn seal_and_open_with_no_paths_act_on_every_secret() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("a.env"), b"a1").unwrap();
    std::fs::write(repo.path().join("b.env"), b"b1").unwrap();
    repo.run(&["add", "a.env"]).assert_success();
    repo.run(&["add", "b.env"]).assert_success();

    std::fs::write(repo.path().join("a.env"), b"a2").unwrap();
    std::fs::write(repo.path().join("b.env"), b"b2").unwrap();
    repo.run(&["seal"]).assert_success();

    std::fs::remove_file(repo.path().join("a.env")).unwrap();
    std::fs::remove_file(repo.path().join("b.env")).unwrap();
    repo.run(&["open"]).assert_success();

    assert_eq!(std::fs::read(repo.path().join("a.env")).unwrap(), b"a2");
    assert_eq!(std::fs::read(repo.path().join("b.env")).unwrap(), b"b2");
}

/// Test 28 (gpg): a GPG-only member can `add` and `open`.
#[test]
fn init_with_gpg_key_file() {
    let repo = Repo::new();
    let Some(gpg_home) = common::GpgHome::new("init_with_gpg_key_file") else {
        return;
    };
    gpg_home.import_secret_key(include_str!(
        "../../core/tests/fixtures/valid_cv25519.secret.asc"
    ));

    let key_path = repo.path().join("alice.asc");
    std::fs::write(
        &key_path,
        include_str!("../../core/tests/fixtures/valid_cv25519.asc"),
    )
    .unwrap();
    repo.run(&["init", "alice", key_path.to_str().unwrap()])
        .assert_success();
    assert!(repo.path().join(".amaga/users/alice.asc").is_file());

    std::fs::write(repo.path().join("secret.env"), b"hello").unwrap();
    repo.run_with_env(
        &["add", "secret.env"],
        &[("GNUPGHOME", gpg_home.path().as_os_str())],
    )
    .assert_success();

    std::fs::remove_file(repo.path().join("secret.env")).unwrap();
    repo.run_with_env(
        &["open", "secret.env"],
        &[("GNUPGHOME", gpg_home.path().as_os_str())],
    )
    .assert_success();
    assert_eq!(
        std::fs::read(repo.path().join("secret.env")).unwrap(),
        b"hello"
    );
}

/// Test 29 (gpg): an age member seals without gpg on PATH; the GPG member then opens.
#[cfg(unix)]
#[test]
fn age_member_seals_for_gpg_member_without_gpg() {
    let (repo, _identity_path) = repo_with_alice();
    let Some(gpg_home) = common::GpgHome::new("age_member_seals_for_gpg_member_without_gpg") else {
        return;
    };
    gpg_home.import_secret_key(include_str!(
        "../../core/tests/fixtures/valid_cv25519.secret.asc"
    ));

    // bob: a GPG member, added by writing the file directly.
    std::fs::write(
        repo.path().join(".amaga/users/bob.asc"),
        include_str!("../../core/tests/fixtures/valid_cv25519.asc"),
    )
    .unwrap();

    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();

    let bin_dir = tempfile::tempdir().unwrap();
    let git_path = common::find_on_path("git");
    std::os::unix::fs::symlink(&git_path, bin_dir.path().join("git")).unwrap();

    std::fs::write(repo.path().join("secret.env"), b"v2").unwrap();
    repo.run_with_env(
        &["seal", "secret.env"],
        &[("PATH", bin_dir.path().as_os_str())],
    )
    .assert_success();

    // bob opens with gpg: an empty global config means bob has no age identity configured.
    std::fs::remove_file(repo.path().join("secret.env")).unwrap();
    let empty_global = repo.path().join("bob-gitconfig");
    std::fs::write(&empty_global, "").unwrap();
    repo.run_with_env(
        &["open", "secret.env"],
        &[
            ("GNUPGHOME", gpg_home.path().as_os_str()),
            ("GIT_CONFIG_GLOBAL", empty_global.as_os_str()),
        ],
    )
    .assert_success();
    assert_eq!(
        std::fs::read(repo.path().join("secret.env")).unwrap(),
        b"v2"
    );
}

/// Test 32 (gpg): a gpg failure names the member and writes nothing.
#[test]
fn gpg_decrypt_failure_writes_nothing() {
    let repo = Repo::new();
    let Some(gpg_home) = common::GpgHome::new("gpg_decrypt_failure_writes_nothing") else {
        return;
    };
    gpg_home.import_secret_key(include_str!(
        "../../core/tests/fixtures/valid_cv25519.secret.asc"
    ));

    let key_path = repo.path().join("alice.asc");
    std::fs::write(
        &key_path,
        include_str!("../../core/tests/fixtures/valid_cv25519.asc"),
    )
    .unwrap();
    repo.run(&["init", "alice", key_path.to_str().unwrap()])
        .assert_success();

    std::fs::write(repo.path().join("secret.env"), b"hello").unwrap();
    repo.run_with_env(
        &["add", "secret.env"],
        &[("GNUPGHOME", gpg_home.path().as_os_str())],
    )
    .assert_success();
    std::fs::remove_file(repo.path().join("secret.env")).unwrap();

    let asc =
        git_amaga_core::gpg::validate(include_str!("../../core/tests/fixtures/valid_cv25519.asc"))
            .unwrap();
    gpg_home.delete_secret_key(&asc.fpr);

    let open = repo.run_with_env(
        &["open", "secret.env"],
        &[("GNUPGHOME", gpg_home.path().as_os_str())],
    );
    open.assert_failure();
    let stderr = String::from_utf8_lossy(&open.stderr);
    assert!(stderr.contains("gpg decryption failed"), "got {stderr:?}");
    assert!(stderr.contains("secret.env.amaga"), "got {stderr:?}");
    assert!(stderr.contains("member alice"), "got {stderr:?}");
    assert!(!repo.path().join("secret.env").exists());
}

fn gnupghome_env(home: &common::GpgHome) -> [(&'static str, &std::ffi::OsStr); 1] {
    [("GNUPGHOME", home.path().as_os_str())]
}

/// Test 33 (gpg): a unique email resolves to exactly that key, not the `malice@` substring match.
#[test]
fn init_gpg_key_by_unique_email() {
    let repo = Repo::new();
    let Some(gpg_home) = common::GpgHome::new("init_gpg_key_by_unique_email") else {
        return;
    };
    let alice = gpg_home.generate_key("Alice <alice@example.invalid>");
    gpg_home.generate_key("Malice <malice@example.invalid>");

    let init = repo.run_with_env(
        &["init", "alice", "alice@example.invalid"],
        &gnupghome_env(&gpg_home),
    );
    init.assert_success();

    let stored = std::fs::read_to_string(repo.path().join(".amaga/users/alice.asc")).unwrap();
    assert_eq!(stored, gpg_home.export_minimal(&alice));
    assert_eq!(
        git_amaga_core::gpg::validate(&stored)
            .unwrap()
            .primary_fpr(),
        alice
    );
    let stdout = String::from_utf8_lossy(&init.stdout);
    assert!(stdout.contains(&alice), "got {stdout:?}");
    assert!(
        stdout.contains("Alice <alice@example.invalid>"),
        "got {stdout:?}"
    );
    let audit = std::fs::read_to_string(repo.path().join(".amaga/audit.jsonl")).unwrap();
    assert!(
        audit.contains(&format!("\"gpg_fpr\":\"{alice}\"")),
        "got {audit:?}"
    );
    assert!(
        audit.contains("\"gpg_uid\":\"Alice <alice@example.invalid>\""),
        "got {audit:?}"
    );
}

/// Test 34 (gpg): two keys with one email are refused and listed; nothing is written.
#[test]
fn gpg_lookup_refuses_ambiguous_email() {
    let repo = Repo::new();
    let Some(gpg_home) = common::GpgHome::new("gpg_lookup_refuses_ambiguous_email") else {
        return;
    };
    let one = gpg_home.generate_key("Alice One <dup@example.invalid>");
    let two = gpg_home.generate_key("Alice Two <dup@example.invalid>");

    let init = repo.run_with_env(
        &["init", "alice", "dup@example.invalid"],
        &gnupghome_env(&gpg_home),
    );

    init.assert_failure();
    let stderr = String::from_utf8_lossy(&init.stderr);
    assert!(
        stderr.contains(&one) && stderr.contains(&two),
        "got {stderr:?}"
    );
    assert!(!repo.path().join(".amaga").exists());
}

/// A revoked key cannot be added, so it does not make a shared email ambiguous.
#[test]
fn gpg_lookup_skips_a_revoked_key_under_the_same_email() {
    let repo = Repo::new();
    let Some(gpg_home) = common::GpgHome::new("gpg_lookup_skips_a_revoked_key") else {
        return;
    };
    let old = gpg_home.generate_key("Alice Old <dup@example.invalid>");
    gpg_home.revoke_key(&old);
    let new = gpg_home.generate_key("Alice New <dup@example.invalid>");

    repo.run_with_env(
        &["init", "alice", "dup@example.invalid"],
        &gnupghome_env(&gpg_home),
    )
    .assert_success();

    let stored = std::fs::read_to_string(repo.path().join(".amaga/users/alice.asc")).unwrap();
    assert_eq!(
        git_amaga_core::gpg::validate(&stored)
            .unwrap()
            .primary_fpr(),
        new
    );
}

/// A revoked-only match is reported as such, not as a plain miss.
#[test]
fn gpg_lookup_reports_when_only_a_revoked_key_matches() {
    let repo = Repo::new();
    let Some(gpg_home) = common::GpgHome::new("gpg_lookup_reports_only_revoked") else {
        return;
    };
    let old = gpg_home.generate_key("Alice Old <old@example.invalid>");
    gpg_home.revoke_key(&old);

    let init = repo.run_with_env(
        &["init", "alice", "old@example.invalid"],
        &gnupghome_env(&gpg_home),
    );

    init.assert_failure();
    let stderr = String::from_utf8_lossy(&init.stderr);
    assert!(
        stderr.contains("only revoked, expired or disabled"),
        "got {stderr:?}"
    );
    assert!(!repo.path().join(".amaga").exists());
}

/// A mistyped `.asc` path says the file is missing, not just that the keyring has no match.
#[test]
fn missing_asc_file_says_the_file_does_not_exist() {
    let repo = Repo::new();
    let Some(gpg_home) = common::GpgHome::new("missing_asc_file_says_the_file_does_not_exist")
    else {
        return;
    };
    gpg_home.generate_key("Alice <alice@example.invalid>");

    let init = repo.run_with_env(&["init", "alice", "alcie.asc"], &gnupghome_env(&gpg_home));

    init.assert_failure();
    let stderr = String::from_utf8_lossy(&init.stderr);
    assert!(stderr.contains("not an existing file"), "got {stderr:?}");
    assert!(!repo.path().join(".amaga").exists());
}

/// Test 35 (gpg): an unknown key is reported as not in the keyring; nothing is written.
#[test]
fn gpg_lookup_unknown_key_errors() {
    let repo = Repo::new();
    let Some(gpg_home) = common::GpgHome::new("gpg_lookup_unknown_key_errors") else {
        return;
    };
    gpg_home.generate_key("Alice <alice@example.invalid>");

    let init = repo.run_with_env(
        &["init", "bob", "bob@example.invalid"],
        &gnupghome_env(&gpg_home),
    );

    init.assert_failure();
    let stderr = String::from_utf8_lossy(&init.stderr);
    assert!(
        stderr.contains("not in your local gpg keyring"),
        "got {stderr:?}"
    );
    assert!(!repo.path().join(".amaga").exists());
}

/// Test 36 (gpg): a third-party certification in the keyring is left out of the stored key.
#[test]
fn gpg_lookup_exports_minimal() {
    let repo = Repo::new();
    let Some(gpg_home) = common::GpgHome::new("gpg_lookup_exports_minimal") else {
        return;
    };
    let alice = gpg_home.generate_key("Alice <alice@example.invalid>");
    let signer = gpg_home.generate_key("Signer <signer@example.invalid>");
    gpg_home.certify(&signer, &alice);

    repo.run_with_env(&["init", "alice", &alice], &gnupghome_env(&gpg_home))
        .assert_success();

    let stored = std::fs::read_to_string(repo.path().join(".amaga/users/alice.asc")).unwrap();
    git_amaga_core::gpg::validate(&stored).expect("stored key passes verify_bindings");
}

/// Test 37: keygen's stdout is the bare public key; the `user add` line goes to stderr.
#[test]
fn keygen_prints_user_add_line() {
    let repo = Repo::new();
    let identity_path = repo.path().join("identity.txt");

    let keygen = repo.run(&["keygen", identity_path.to_str().unwrap()]);

    keygen.assert_success();
    let key = String::from_utf8_lossy(&keygen.stdout).trim().to_string();
    assert!(key.starts_with("age1") && !key.contains(' '), "got {key:?}");
    let stderr = String::from_utf8_lossy(&keygen.stderr);
    assert!(
        stderr.contains(&format!("git-amaga user add <name> {key}")),
        "got {stderr:?}"
    );
}

/// Test 38 (Unix): with no gpg on PATH, a keyring lookup fails with the gpg-not-found error.
#[cfg(unix)]
#[test]
fn gpg_lookup_without_gpg_errors() {
    let repo = Repo::new();
    let bin_dir = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(common::find_on_path("git"), bin_dir.path().join("git")).unwrap();

    let init = repo.run_with_env(
        &["init", "alice", "alice@example.invalid"],
        &[("PATH", bin_dir.path().as_os_str())],
    );

    init.assert_failure();
    let stderr = String::from_utf8_lossy(&init.stderr);
    assert!(stderr.contains("gpg not found on PATH"), "got {stderr:?}");
    assert!(!repo.path().join(".amaga").exists());
}

fn base_file(repo: &Repo) -> String {
    std::fs::read_to_string(repo.path().join(".git/amaga-base")).unwrap_or_default()
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

/// `seal`, `open` and `close` of `<path>` without a `<path>.amaga` point at `add`, not a raw I/O
/// error.
#[test]
fn explicit_path_without_ciphertext_says_use_add() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("README.md"), b"hi").unwrap();
    for command in ["seal", "open", "close"] {
        let out = repo.run(&[command, "README.md"]);
        out.assert_failure();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("not a managed secret"),
            "{command}: got {stderr:?}"
        );
    }
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

/// Without paths, listed `*.amaga` files that are not valid secret paths are skipped.
#[test]
fn commands_without_paths_skip_invalid_managed_paths() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();
    let ciphertext = std::fs::read(repo.path().join("secret.env.amaga")).unwrap();
    std::fs::write(repo.path().join("secret.env.amaga.amaga"), &ciphertext).unwrap();
    std::fs::create_dir(repo.path().join("foo")).unwrap();
    std::fs::write(repo.path().join("foo/.amaga"), &ciphertext).unwrap();

    repo.run(&["open", "--force"]).assert_success();
    repo.run(&["seal"]).assert_success();

    assert_eq!(
        std::fs::read(repo.path().join("secret.env.amaga")).unwrap(),
        ciphertext
    );
    let gitignore = std::fs::read_to_string(repo.path().join(".gitignore")).unwrap();
    assert!(!gitignore.contains("foo"), "got {gitignore:?}");
    assert!(!gitignore.contains("secret.env.amaga"), "got {gitignore:?}");
}

/// An in-sync `open` restores a lost base entry.
#[test]
fn insync_open_restores_a_lost_base() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();
    std::fs::remove_file(repo.path().join(".git/amaga-base")).unwrap();

    repo.run(&["open", "secret.env"]).assert_success();
    std::fs::write(repo.path().join("secret.env"), b"v2").unwrap();
    repo.run(&["seal", "secret.env"]).assert_success();
}

/// `open` of an `Outdated` file records the base, so a later edit seals without `--force`.
#[test]
fn edit_after_opening_outdated_plaintext_seals_without_force() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();
    rotate_ciphertext(&repo, b"v2");
    repo.run(&["open", "secret.env"]).assert_success();

    std::fs::write(repo.path().join("secret.env"), b"v3").unwrap();
    repo.run(&["seal", "secret.env"]).assert_success();
}

/// `close` drops the base entry.
#[test]
fn close_drops_the_base_entry() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();
    assert!(base_file(&repo).contains("secret.env"));

    repo.run(&["close", "secret.env"]).assert_success();
    assert!(!base_file(&repo).contains("secret.env"));
}

/// `open` refuses a plaintext path that is tracked and writes nothing.
#[test]
fn open_refuses_tracked_plaintext() {
    let (repo, _identity_path) = repo_with_alice();

    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();
    repo.git(&["add", "-f", "secret.env"]).assert_success();
    std::fs::remove_file(repo.path().join("secret.env")).unwrap();

    repo.run(&["open", "secret.env"]).assert_failure();
    assert!(!repo.path().join("secret.env").exists());
}

fn status_stdout(repo: &Repo) -> String {
    let status = repo.run(&["status"]);
    status.assert_success();
    String::from_utf8_lossy(&status.stdout).into_owned()
}

/// `status` exits 1 and prints an `ERROR` line containing `token`.
fn assert_status_error(repo: &Repo, token: &str) {
    let status = repo.run(&["status"]);
    assert_eq!(status.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&status.stdout);
    let error_line = stdout.lines().find(|l| l.starts_with("ERROR "));
    assert!(
        error_line.is_some_and(|l| l.contains(token)),
        "expected an ERROR line with {token:?}, got {stdout:?}"
    );
}

/// `status` prints the members and one `ok` line per healthy secret.
#[test]
fn status_lists_members_and_healthy_secrets() {
    let (repo, _identity_path) = repo_with_alice();
    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();

    let stdout = status_stdout(&repo);
    assert!(stdout.contains("members: alice (age)"), "got {stdout:?}");
    assert!(
        stdout.contains("ok secret.env.amaga: in sync"),
        "got {stdout:?}"
    );
}

/// Test 10: a force-added (tracked) plaintext is a critical error.
#[test]
fn status_flags_force_added_plaintext() {
    let (repo, _identity_path) = repo_with_alice();
    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();
    status_stdout(&repo);
    repo.git(&["add", "-f", "secret.env"]).assert_success();

    assert_status_error(&repo, "CRITICAL plaintext 'secret.env' is tracked");
}

/// A managed plaintext path that is not ignored is critical even when the file does not exist.
#[test]
fn status_flags_unignored_plaintext_path_even_when_closed() {
    let (repo, _identity_path) = repo_with_alice();
    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();
    repo.run(&["close", "secret.env"]).assert_success();
    std::fs::write(repo.path().join(".gitignore"), "").unwrap();

    assert_status_error(&repo, "CRITICAL plaintext 'secret.env' is not ignored");
}

/// Local edits and a changed repository version together are a `Conflict`.
#[test]
fn status_reports_conflict() {
    let (repo, _identity_path) = repo_with_alice();
    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();
    std::fs::write(repo.path().join("secret.env"), b"local").unwrap();
    rotate_ciphertext(&repo, b"theirs");

    assert_status_error(&repo, "conflicts");
}

/// Error lines come before healthy ones, whatever the path order.
#[test]
fn status_lists_problems_first() {
    let (repo, _identity_path) = repo_with_alice();
    std::fs::write(repo.path().join("a.env"), b"a").unwrap();
    std::fs::write(repo.path().join("z.env"), b"z").unwrap();
    repo.run(&["add", "a.env"]).assert_success();
    repo.run(&["add", "z.env"]).assert_success();
    std::fs::write(repo.path().join("z.env"), b"edited").unwrap();

    let status = repo.run(&["status"]);
    let stdout = String::from_utf8_lossy(&status.stdout);
    let error = stdout.find("ERROR z.env.amaga").expect("error line");
    let ok = stdout.find("ok a.env.amaga").expect("ok line");
    assert!(error < ok, "got {stdout:?}");
}

/// An undecryptable secret is an error that names the file.
#[test]
fn status_names_undecryptable_secret() {
    let (repo, _identity_path) = repo_with_alice();
    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();
    let cipher_path = repo.path().join("secret.env.amaga");
    let mut bytes = std::fs::read(&cipher_path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&cipher_path, &bytes).unwrap();

    assert_status_error(&repo, "secret.env.amaga");
    let stdout = String::from_utf8_lossy(&repo.run(&["status"]).stdout).into_owned();
    assert!(!stdout.contains("cannot decrypt"), "got {stdout:?}");
    assert_eq!(
        stdout.matches("secret.env.amaga").count(),
        1,
        "got {stdout:?}"
    );
    assert!(stdout.contains("decryption error"), "got {stdout:?}");
}

/// A secret whose header key set differs from the members is stale until `rotate`.
#[test]
fn status_reports_stale_recipients() {
    let (repo, _identity_path) = repo_with_alice();
    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();
    let bob = age::x25519::Identity::generate().to_public();
    std::fs::write(repo.path().join(".amaga/users/bob.txt"), format!("{bob}\n")).unwrap();

    assert_status_error(&repo, "run git-amaga rotate");
}

/// `NEEDS ROTATION` is only a warning: exit 0.
#[test]
fn status_warns_about_exposure_with_exit_zero() {
    let (repo, _identity_path) = repo_with_alice();
    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();
    let members = git_amaga_core::users::load(&repo.path().join(".amaga/users")).unwrap();
    let mut header = git_amaga_core::secret::next_header(
        None,
        false,
        &git_amaga_core::users::recipients(&members),
    );
    header
        .exposed_to
        .insert("charlie".into(), Default::default());
    let alice = members["alice"].age_keys[0].clone();
    let ciphertext =
        git_amaga_core::secret::encrypt(&header, b"v1", &[&alice as &dyn age::Recipient]).unwrap();
    std::fs::write(repo.path().join("secret.env.amaga"), ciphertext).unwrap();

    let stdout = status_stdout(&repo);
    assert!(
        stdout.contains("WARN secret.env.amaga: NEEDS ROTATION: exposed to charlie"),
        "got {stdout:?}"
    );
}

/// A `*.amaga` whose `text` attribute is not unset (git could rewrite line endings) is an error.
#[test]
fn status_flags_text_attribute_on_amaga_files() {
    let (repo, _identity_path) = repo_with_alice();
    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();
    std::fs::write(repo.path().join(".gitattributes"), "").unwrap();

    assert_status_error(&repo, "`text` attribute");
}

/// `status` needs a valid membership and an identity that matches a member.
#[test]
fn status_requires_valid_users_and_an_identity() {
    let (repo, _identity_path) = repo_with_alice();
    std::fs::write(repo.path().join(".amaga/users/junk.xyz"), "").unwrap();
    let status = repo.run(&["status"]);
    assert_eq!(status.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&status.stderr).contains("junk.xyz"));

    std::fs::remove_file(repo.path().join(".amaga/users/junk.xyz")).unwrap();
    repo.git(&["config", "--global", "--unset", "amaga.identity"])
        .assert_success();
    let status = repo.run(&["status"]);
    assert_eq!(status.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&status.stderr).contains("not a member"));
}

/// `status` lists an unmerged secret whose path git would C-quote (non-ASCII).
#[test]
fn status_lists_unmerged_non_ascii_secret() {
    let repo = repo_with_unmerged_secret("sé.env");

    let status = repo.run(&["status"]);
    assert_eq!(status.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert!(
        stdout.contains("ERROR sé.env.amaga: unmerged"),
        "got {stdout:?}"
    );
}

/// An unmerged `*.amaga` that was deleted from the worktree is still reported.
#[test]
fn status_lists_unmerged_secret_missing_from_worktree() {
    let repo = repo_with_unmerged_secret("a.env");
    std::fs::remove_file(repo.path().join("a.env.amaga")).unwrap();

    assert_status_error(&repo, "a.env.amaga: unmerged");
}

/// An unreadable plaintext is reported for its secret without hiding other secrets' findings.
#[test]
fn status_reports_io_errors_per_secret() {
    let (repo, _identity_path) = repo_with_alice();
    std::fs::write(repo.path().join("a.env"), b"a").unwrap();
    std::fs::write(repo.path().join("b.env"), b"b").unwrap();
    repo.run(&["add", "a.env"]).assert_success();
    repo.run(&["add", "b.env"]).assert_success();
    std::fs::remove_file(repo.path().join("a.env")).unwrap();
    std::fs::create_dir(repo.path().join("a.env")).unwrap();
    repo.git(&["add", "-f", "b.env"]).assert_success();

    let status = repo.run(&["status"]);
    assert_eq!(status.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert!(
        stdout.contains("ERROR a.env.amaga: 'a.env' is not a regular file"),
        "got {stdout:?}"
    );
    assert!(
        stdout.contains("CRITICAL plaintext 'b.env' is tracked"),
        "got {stdout:?}"
    );
}

/// Stale means a different key set: a removed or replaced key is stale, a renamed member is not.
#[test]
fn status_stale_compares_key_sets_not_names() {
    let (repo, _identity_path) = repo_with_alice();
    let bob = age::x25519::Identity::generate().to_public();
    let bob_file = repo.path().join(".amaga/users/bob.txt");
    std::fs::write(&bob_file, format!("{bob}\n")).unwrap();
    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();
    assert!(status_stdout(&repo).contains("ok secret.env.amaga"));

    let robert_file = repo.path().join(".amaga/users/robert.txt");
    std::fs::rename(&bob_file, &robert_file).unwrap();
    assert!(status_stdout(&repo).contains("ok secret.env.amaga"));

    let other = age::x25519::Identity::generate().to_public();
    std::fs::write(&robert_file, format!("{other}\n")).unwrap();
    assert_status_error(&repo, "run git-amaga rotate");

    std::fs::remove_file(&robert_file).unwrap();
    assert_status_error(&repo, "run git-amaga rotate");
}

/// Test 25: two branches that each `add` a secret merge without a `.gitignore` conflict, and
/// both plaintexts stay ignored.
#[test]
fn parallel_adds_merge_cleanly() {
    let (repo, _identity_path) = repo_with_alice();
    repo.git(&["add", ".gitattributes", ".gitignore", ".amaga"])
        .assert_success();
    repo.git(&["commit", "-m", "init"]).assert_success();
    let base_branch = String::from_utf8(repo.git(&["rev-parse", "--abbrev-ref", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_string();

    repo.git(&["checkout", "-b", "other"]).assert_success();
    std::fs::write(repo.path().join("a.env"), b"a").unwrap();
    repo.run(&["add", "a.env"]).assert_success();
    repo.git(&["add", ".gitignore", "a.env.amaga"])
        .assert_success();
    repo.git(&["commit", "-m", "add a"]).assert_success();

    repo.git(&["checkout", &base_branch]).assert_success();
    std::fs::write(repo.path().join("b.env"), b"b").unwrap();
    repo.run(&["add", "b.env"]).assert_success();
    repo.git(&["add", ".gitignore", "b.env.amaga"])
        .assert_success();
    repo.git(&["commit", "-m", "add b"]).assert_success();

    repo.git(&["merge", "--no-edit", "other"]).assert_success();
    repo.git(&["check-ignore", "-q", "a.env"]).assert_success();
    repo.git(&["check-ignore", "-q", "b.env"]).assert_success();
    let stdout = status_stdout(&repo);
    assert!(stdout.contains("ok a.env.amaga"), "got {stdout:?}");
    assert!(stdout.contains("ok b.env.amaga"), "got {stdout:?}");
}

/// `remove` deletes only the `.amaga` file and its base entry: the plaintext and its ignore entry
/// stay, and the event is audited.
#[test]
fn remove_deletes_ciphertext_and_keeps_plaintext_and_ignore_entry() {
    let (repo, _identity_path) = repo_with_alice();
    std::fs::write(repo.path().join("a.env"), b"a").unwrap();
    std::fs::write(repo.path().join("b.env"), b"b").unwrap();
    repo.run(&["add", "a.env", "b.env"]).assert_success();
    let gitignore = std::fs::read_to_string(repo.path().join(".gitignore")).unwrap();

    repo.run(&["remove", "a.env"]).assert_success();

    assert!(!repo.path().join("a.env.amaga").exists());
    assert!(repo.path().join("b.env.amaga").exists());
    assert_eq!(std::fs::read(repo.path().join("a.env")).unwrap(), b"a");
    assert_eq!(
        std::fs::read_to_string(repo.path().join(".gitignore")).unwrap(),
        gitignore
    );
    repo.git(&["check-ignore", "-q", "a.env"]).assert_success();
    let base = base_file(&repo);
    assert!(!base.contains("a.env"), "got {base:?}");
    assert!(base.contains("b.env"), "got {base:?}");
    let audit = std::fs::read_to_string(repo.path().join(".amaga/audit.jsonl")).unwrap();
    let last = audit.lines().last().unwrap();
    assert!(
        last.contains("\"event\":\"secret.removed\""),
        "got {last:?}"
    );
    assert!(last.contains("\"path\":\"a.env\""), "got {last:?}");
}

/// `remove` of an unmanaged path fails, and nothing named alongside it is removed.
#[test]
fn remove_refuses_unmanaged_path_and_removes_nothing() {
    let (repo, _identity_path) = repo_with_alice();
    std::fs::write(repo.path().join("a.env"), b"a").unwrap();
    repo.run(&["add", "a.env"]).assert_success();

    let remove = repo.run(&["remove", "a.env", "missing.env"]);
    remove.assert_failure();
    assert!(String::from_utf8_lossy(&remove.stderr).contains("missing.env"));
    assert!(repo.path().join("a.env.amaga").exists());
}

/// Test 22: after a teammate pulls a `remove`, their plaintext is still ignored.
#[test]
fn remove_keeps_teammates_plaintext_ignored() {
    let (repo, _identity_path) = repo_with_alice();
    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["add", "secret.env"]).assert_success();
    repo.commit_all("add secret");

    let clones = tempfile::tempdir().unwrap();
    let source = repo.path().to_str().unwrap();
    repo.git_in(clones.path(), &["clone", "-q", source, "mate"])
        .assert_success();
    let mate = clones.path().join("mate");
    repo.run_in(&mate, &["open", "secret.env"]).assert_success();
    repo.git_in(&mate, &["check-ignore", "-q", "secret.env"])
        .assert_success();

    repo.run(&["remove", "secret.env"]).assert_success();
    repo.commit_all("remove secret");
    repo.git_in(&mate, &["pull", "-q", "--ff-only"])
        .assert_success();

    assert!(!mate.join("secret.env.amaga").exists());
    assert_eq!(std::fs::read(mate.join("secret.env")).unwrap(), b"v1");
    repo.git_in(&mate, &["check-ignore", "-q", "secret.env"])
        .assert_success();
}

/// `rotate`, `user add`, `user remove` and `remove` refuse while a `*.amaga` is unmerged.
#[test]
fn membership_commands_refuse_during_amaga_merge_conflict() {
    let repo = repo_with_unmerged_secret("a.env");
    // A second member, so that `user remove alice` is not refused as the last member.
    let bob = age::x25519::Identity::generate().to_public();
    std::fs::write(repo.path().join(".amaga/users/bob.txt"), format!("{bob}\n")).unwrap();
    let carol = age::x25519::Identity::generate().to_public().to_string();

    for args in [
        vec!["rotate"],
        vec!["user", "add", "carol", &carol],
        vec!["user", "remove", "bob"],
        vec!["remove", "a.env"],
    ] {
        let output = repo.run(&args);
        output.assert_failure();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("unmerged"), "{args:?} gave {stderr:?}");
    }
    assert!(!repo.path().join(".amaga/users/carol.txt").exists());
    assert!(repo.path().join(".amaga/users/bob.txt").exists());
    assert!(repo.path().join("a.env.amaga").exists());
}

/// `remove` needs the plaintext open and in sync, so the user keeps a copy; nothing is removed
/// when any path is refused.
#[test]
fn remove_refuses_closed_and_modified_plaintext() {
    let (repo, _identity_path) = repo_with_alice();
    for name in ["a.env", "b.env"] {
        std::fs::write(repo.path().join(name), b"v1").unwrap();
        repo.run(&["add", name]).assert_success();
    }
    repo.run(&["close", "a.env"]).assert_success();

    let closed = repo.run(&["remove", "b.env", "a.env"]);
    closed.assert_failure();
    assert!(String::from_utf8_lossy(&closed.stderr).contains("a.env"));
    assert!(repo.path().join("a.env.amaga").exists());
    assert!(repo.path().join("b.env.amaga").exists());

    repo.run(&["open", "a.env"]).assert_success();
    std::fs::write(repo.path().join("a.env"), b"edited").unwrap();
    repo.run(&["remove", "a.env"]).assert_failure();
    assert!(repo.path().join("a.env.amaga").exists());

    repo.run(&["seal", "a.env"]).assert_success();
    repo.run(&["remove", "a.env", "b.env"]).assert_success();
    assert!(!repo.path().join("a.env.amaga").exists());
    assert_eq!(std::fs::read(repo.path().join("a.env")).unwrap(), b"edited");
}

/// A `.amaga` that `remove` cannot decrypt is refused with the way out.
#[test]
fn remove_unreadable_secret_points_to_git_rm() {
    let (repo, _identity_path) = repo_with_alice();
    std::fs::write(repo.path().join("a.env"), b"a").unwrap();
    repo.run(&["add", "a.env"]).assert_success();
    std::fs::write(repo.path().join("a.env.amaga"), b"garbage").unwrap();

    let remove = repo.run(&["remove", "a.env"]);
    remove.assert_failure();
    let stderr = String::from_utf8_lossy(&remove.stderr);
    assert!(stderr.contains("git rm a.env.amaga"), "got {stderr:?}");
    assert!(repo.path().join("a.env.amaga").exists());
}

/// Naming a secret twice (plaintext and `.amaga` form) removes and audits it once.
#[test]
fn remove_dedupes_paths() {
    let (repo, _identity_path) = repo_with_alice();
    std::fs::write(repo.path().join("a.env"), b"a").unwrap();
    repo.run(&["add", "a.env"]).assert_success();

    repo.run(&["remove", "a.env", "a.env.amaga"])
        .assert_success();

    let audit = std::fs::read_to_string(repo.path().join(".amaga/audit.jsonl")).unwrap();
    assert_eq!(audit.matches("secret.removed").count(), 1, "got {audit:?}");
}
