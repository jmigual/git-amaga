//! Integration tests for the re-encryption commands: `rotate`, `user add`, `user remove`
//! (plan 7.1, tests 12-20, 30, 31).

mod common;

use std::path::Path;
use std::process::Output;

use age::x25519;
use common::{
    OutputExt, Repo, current_branch, current_epoch, decrypt_as, decrypt_file, load_identity,
    repo_with_alice, run_as, second_identity,
};
use git_amaga_core::secret::Header;

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn add_secret(repo: &Repo, name: &str, body: &[u8]) {
    std::fs::write(repo.path().join(name), body).unwrap();
    repo.run(&["add", name]).assert_success();
}

/// Writes `.amaga/users/<name>.txt` by hand, as a merge or a teammate's commit would. The
/// current epoch is not wrapped to the new member until `rotate`.
fn write_member_file(repo: &Repo, name: &str) -> x25519::Identity {
    let identity = x25519::Identity::generate();
    std::fs::write(
        repo.path().join(format!(".amaga/users/{name}.txt")),
        format!("{}\n", identity.to_public()),
    )
    .unwrap();
    common::join_default(repo, name);
    identity
}

/// Like [`write_member_file`], then runs `rotate` so the new member can read the secrets.
fn write_member(repo: &Repo, name: &str) -> x25519::Identity {
    let identity = write_member_file(repo, name);
    repo.run(&["rotate"]).assert_success();
    identity
}

/// The decrypted header of `path`, read with alice's identity file.
fn header_of(repo: &Repo, identity_path: &Path, path: &str) -> Header {
    decrypt_file(repo, identity_path, path).0
}

/// The members recorded in the current epoch, as alice reads them.
fn epoch_members(repo: &Repo, identity_path: &Path) -> git_amaga_core::secret::Recipients {
    current_epoch(repo, &load_identity(identity_path)).members
}

/// The current epoch id and every epoch file id.
fn epoch_state(repo: &Repo) -> (String, Vec<String>) {
    (
        common::current_epoch_id(repo, "default"),
        git_amaga_core::epoch::list(repo.path()).unwrap(),
    )
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
    assert!(!stderr(&rotate).contains("do not decrypt"));
    assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
    assert_eq!(audit_events(&repo), before_audit);

    repo.run(&["open", "leak"]).assert_failure();
    assert!(!repo.path().join("leak").exists());

    let status = repo.run(&["status"]);
    assert_eq!(status.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert!(
        stdout.contains("ERROR leak.amaga:") && stdout.contains("; not a regular file"),
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

    let epoch_before = epoch_state(&repo);
    repo.run(&["rotate"]).assert_success();
    let second = std::fs::read(repo.path().join("secret.env.amaga")).unwrap();
    assert_ne!(first, second, "rotate must use a fresh file key");
    let epoch_after = epoch_state(&repo);
    assert_ne!(
        epoch_after.0, epoch_before.0,
        "rotate must move current-epoch"
    );
    assert_eq!(epoch_after.1.len(), epoch_before.1.len() + 1);
    let header = header_of(&repo, &identity_path, "secret.env.amaga");
    assert_eq!(header.exposed_to, exposed);
    assert_eq!(
        epoch_members(&repo, &identity_path)
            .keys()
            .collect::<Vec<_>>(),
        ["alice"]
    );
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

    std::fs::write(repo.path().join("secret.env"), b"v2").unwrap();
    let before = std::fs::read(repo.path().join("secret.env.amaga")).unwrap();
    let seal = repo.run(&["seal", "secret.env"]);
    seal.assert_failure();
    assert!(stderr(&seal).contains("rotate"), "got {:?}", stderr(&seal));
    assert_eq!(
        std::fs::read(repo.path().join("secret.env.amaga")).unwrap(),
        before
    );
    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();

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
    write_member(&repo, "bob");
    corrupt(&repo, "a.env.amaga");
    corrupt(&repo, "b.env.amaga");
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

/// A secret whose name is not UTF-8 is reported by `status` and makes `rotate` refuse, instead of
/// being left out and staying under the old epoch.
#[cfg(target_os = "linux")]
#[test]
fn non_utf8_secret_is_reported_and_blocks_rotate() {
    use std::os::unix::ffi::OsStrExt;

    let (repo, _identity_path) = repo_with_alice();
    add_secret(&repo, "a.env", b"a1");
    add_secret(&repo, "b.env", b"b1");
    let odd = (repo.path()).join(std::ffi::OsStr::from_bytes(b"caf\xe9.env.amaga"));
    std::fs::rename(repo.path().join("b.env.amaga"), &odd).unwrap();
    let before = std::fs::read(&odd).unwrap();
    let before_epoch = common::current_epoch_id(&repo, "default");

    let status = repo.run(&["status"]);
    assert!(stderr(&status).contains("not valid UTF-8"), "{status:?}");
    let rotate = repo.run(&["rotate"]);
    rotate.assert_failure();
    assert!(stderr(&rotate).contains("not valid UTF-8"), "{rotate:?}");
    assert_eq!(std::fs::read(&odd).unwrap(), before);
    assert_eq!(common::current_epoch_id(&repo, "default"), before_epoch);

    // Once deleted, it is skipped like a deleted UTF-8 secret, even while still tracked.
    repo.commit_all("odd name");
    std::fs::remove_file(&odd).unwrap();
    repo.run(&["rotate"]).assert_success();
}

fn user_files(repo: &Repo) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(repo.path().join(".amaga/users"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn corrupt(repo: &Repo, name: &str) {
    let path = repo.path().join(name);
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&path, bytes).unwrap();
}

fn user_add(repo: &Repo, name: &str, key: &str) -> Output {
    repo.run(&["user", "add", name, key])
}

/// Test 12: `user add` re-wraps the current epoch only. No secret changes; bob reads the
/// current version and the one committed earlier under the same epoch (decision 1).
#[test]
fn user_add_rewraps_epoch_only() {
    let (repo, identity_path) = repo_with_alice();
    add_secret(&repo, "secret.env", b"v1");
    repo.commit_all("add secret");
    let secret_before = std::fs::read(repo.path().join("secret.env.amaga")).unwrap();
    let epoch_id = common::current_epoch_id(&repo, "default");
    let bob = x25519::Identity::generate();

    user_add(&repo, "bob", &bob.to_public().to_string()).assert_success();

    assert_eq!(
        std::fs::read(repo.path().join("secret.env.amaga")).unwrap(),
        secret_before
    );
    assert_eq!(common::current_epoch_id(&repo, "default"), epoch_id);
    let porcelain = String::from_utf8(repo.git(&["status", "--porcelain"]).stdout).unwrap();
    let mut changed: Vec<&str> = porcelain
        .lines()
        .filter(|line| !line.ends_with("identity.txt"))
        .map(|line| &line[3..])
        .collect();
    changed.sort();
    let epoch_file = format!(".amaga/epochs/{epoch_id}.age");
    assert_eq!(
        changed,
        [
            ".amaga/audit.jsonl",
            epoch_file.as_str(),
            ".amaga/partitions/default/members",
            ".amaga/users/bob.txt"
        ]
    );

    let current = std::fs::read(repo.path().join("secret.env.amaga")).unwrap();
    assert_eq!(decrypt_as(&repo, &current, &bob).unwrap().1, b"v1");
    let history = repo.git(&["show", "HEAD:secret.env.amaga"]).stdout;
    assert_eq!(decrypt_as(&repo, &history, &bob).unwrap().1, b"v1");
    assert_eq!(
        epoch_members(&repo, &identity_path)
            .keys()
            .collect::<Vec<_>>(),
        ["alice", "bob"]
    );
    assert!(
        header_of(&repo, &identity_path, "secret.env.amaga")
            .exposed_to
            .is_empty()
    );
    let audit = audit_events(&repo);
    let added = &audit[audit.len() - 2];
    assert!(added.contains("\"event\":\"user.added\""), "got {added:?}");
    assert!(added.contains("\"user\":\"bob\""), "got {added:?}");
    let granted = audit.last().unwrap();
    assert!(
        granted.contains("\"event\":\"partition.member_added\""),
        "got {granted:?}"
    );
    assert!(
        granted.contains("\"partition\":\"default\""),
        "got {granted:?}"
    );
    assert_eq!(user_files(&repo), ["alice.txt", "bob.txt"]);
}

/// Test 39 (decision 1): after a `rotate`, a new member reads the current version but not the
/// one committed before it.
#[test]
fn rotate_before_user_add_hides_history() {
    let (repo, _identity_path) = repo_with_alice();
    add_secret(&repo, "secret.env", b"v1");
    repo.commit_all("add secret");
    repo.run(&["rotate"]).assert_success();
    let carol = x25519::Identity::generate();

    user_add(&repo, "carol", &carol.to_public().to_string()).assert_success();

    let current = std::fs::read(repo.path().join("secret.env.amaga")).unwrap();
    assert_eq!(decrypt_as(&repo, &current, &carol).unwrap().1, b"v1");
    let history = repo.git(&["show", "HEAD:secret.env.amaga"]).stdout;
    assert!(decrypt_as(&repo, &history, &carol).is_err());
}

/// `user add` refuses an existing name and changes nothing.
#[test]
fn user_add_refuses_existing_name() {
    let (repo, _identity_path) = repo_with_alice();
    add_secret(&repo, "secret.env", b"v1");
    let before = std::fs::read(repo.path().join("secret.env.amaga")).unwrap();
    let before_audit = audit_events(&repo);
    let other = x25519::Identity::generate().to_public().to_string();

    user_add(&repo, "alice", &other).assert_failure();

    assert_eq!(
        std::fs::read(repo.path().join("secret.env.amaga")).unwrap(),
        before
    );
    assert_eq!(audit_events(&repo), before_audit);
    assert_eq!(user_files(&repo), ["alice.txt"]);
}

/// A key already used by another member is refused before anything is written.
#[test]
fn user_add_refuses_duplicate_key_and_writes_nothing() {
    let (repo, _identity_path) = repo_with_alice();
    add_secret(&repo, "secret.env", b"v1");
    let before = std::fs::read(repo.path().join("secret.env.amaga")).unwrap();
    let before_audit = audit_events(&repo);
    let alice_key = std::fs::read_to_string(repo.path().join(".amaga/users/alice.txt")).unwrap();

    user_add(&repo, "bob", alice_key.trim()).assert_failure();
    user_add(&repo, "Bob", "age1xyz").assert_failure();

    assert_eq!(
        std::fs::read(repo.path().join("secret.env.amaga")).unwrap(),
        before
    );
    assert_eq!(audit_events(&repo), before_audit);
    assert_eq!(user_files(&repo), ["alice.txt"]);
}

/// Test 30: expired, revoked, sign-only and third-party-certified keys are each refused and
/// `.amaga/users` is unchanged. Needs no gpg.
#[test]
fn user_add_rejects_unusable_gpg_keys() {
    let (repo, _identity_path) = repo_with_alice();
    add_secret(&repo, "secret.env", b"v1");
    let before_audit = audit_events(&repo);
    let fixtures = [
        (
            "expired",
            include_str!("../../core/tests/fixtures/expired.asc"),
        ),
        (
            "revoked",
            include_str!("../../core/tests/fixtures/revoked.asc"),
        ),
        (
            "sign_only",
            include_str!("../../core/tests/fixtures/sign_only.asc"),
        ),
        (
            "third_party",
            include_str!("../../core/tests/fixtures/third_party.asc"),
        ),
    ];
    for (name, armored) in fixtures {
        let key_path = repo.path().join(format!("{name}.asc"));
        std::fs::write(&key_path, armored).unwrap();
        let output = user_add(&repo, "bob", key_path.to_str().unwrap());
        output.assert_failure();
        assert_eq!(user_files(&repo), ["alice.txt"], "after {name}");
    }
    assert_eq!(audit_events(&repo), before_audit);
}

/// A GPG member added from a key file: stored byte for byte, audited with its fingerprint, and
/// removing it flags secrets as exposed to its `pgp:` key.
#[test]
fn gpg_member_add_then_remove_flags_its_pgp_key() {
    let (repo, identity_path) = repo_with_alice();
    add_secret(&repo, "secret.env", b"v1");
    let armored = include_str!("../../core/tests/fixtures/valid_cv25519.asc");
    let key_path = repo.path().join("bob-key.asc");
    std::fs::write(&key_path, armored).unwrap();
    let asc = git_amaga_core::gpg::validate(armored).unwrap();

    let add = user_add(&repo, "bob", key_path.to_str().unwrap());
    add.assert_success();
    assert!(String::from_utf8_lossy(&add.stdout).contains(&asc.primary_fpr()));
    assert_eq!(
        std::fs::read_to_string(repo.path().join(".amaga/users/bob.asc")).unwrap(),
        armored
    );
    assert!(epoch_members(&repo, &identity_path)["bob"].contains(&format!("pgp:{}", asc.fpr)));
    let audit = audit_events(&repo);
    let added = &audit[audit.len() - 2];
    assert!(
        added.contains(&format!("\"gpg_fpr\":\"{}\"", asc.primary_fpr())),
        "{added}"
    );

    repo.run(&["user", "remove", "bob"]).assert_success();
    assert_eq!(user_files(&repo), ["alice.txt"]);
    let header = header_of(&repo, &identity_path, "secret.env.amaga");
    assert!(header.exposed_to["bob"].contains(&format!("pgp:{}", asc.fpr)));
}

/// `user add` takes a gpg key spec (here an email) and exports it from the local keyring.
#[test]
fn user_add_resolves_an_email_from_the_gpg_keyring() {
    let (repo, _identity_path) = repo_with_alice();
    let Some(gpg_home) = common::GpgHome::new("user_add_resolves_an_email_from_the_gpg_keyring")
    else {
        return;
    };
    let bob = gpg_home.generate_key("Bob <bob@example.invalid>");
    add_secret(&repo, "secret.env", b"v1");

    let add = repo.run_with_env(
        &["user", "add", "bob", "bob@example.invalid"],
        &gpg_home.env(),
    );
    add.assert_success();

    assert_eq!(
        std::fs::read_to_string(repo.path().join(".amaga/users/bob.asc")).unwrap(),
        gpg_home.export_minimal(&bob)
    );
    let audit = audit_events(&repo);
    assert!(audit[audit.len() - 2].contains(&bob));
}

/// Test 31: replacing a member's encryption subkey is a key change: secrets go stale and `rotate`
/// flags exposure to the old `pgp:` key.
#[test]
fn gpg_subkey_replacement_flags_exposure() {
    let (repo, identity_path) = repo_with_alice();
    let old = include_str!("../../core/tests/fixtures/rotated_subkey_old.asc");
    let new = include_str!("../../core/tests/fixtures/rotated_subkey_new.asc");
    let old_fpr = git_amaga_core::gpg::validate(old).unwrap().fpr;
    let new_fpr = git_amaga_core::gpg::validate(new).unwrap().fpr;
    let key_path = repo.path().join("bob-key.asc");
    std::fs::write(&key_path, old).unwrap();
    user_add(&repo, "bob", key_path.to_str().unwrap()).assert_success();
    add_secret(&repo, "secret.env", b"v1");

    std::fs::write(repo.path().join(".amaga/users/bob.asc"), new).unwrap();
    let status = repo.run(&["status"]);
    assert_eq!(status.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&status.stdout).contains("run git-amaga rotate"));

    repo.run(&["rotate"]).assert_success();
    let header = header_of(&repo, &identity_path, "secret.env.amaga");
    assert_eq!(
        header.exposed_to["bob"].iter().collect::<Vec<_>>(),
        [&format!("pgp:{old_fpr}")]
    );
    assert!(epoch_members(&repo, &identity_path)["bob"].contains(&format!("pgp:{new_fpr}")));
}

/// A repository with members alice and bob and secrets `a.env` and `b.env`.
fn repo_with_two_members() -> (Repo, std::path::PathBuf, x25519::Identity) {
    let (repo, identity_path) = repo_with_alice();
    let bob = x25519::Identity::generate();
    user_add(&repo, "bob", &bob.to_public().to_string()).assert_success();
    add_secret(&repo, "a.env", b"a1");
    add_secret(&repo, "b.env", b"b1");
    (repo, identity_path, bob)
}

/// Test 13: after `user remove` the member cannot decrypt, every secret is flagged, and the user
/// file is gone.
#[test]
fn user_remove_locks_out_and_flags_all() {
    let (repo, identity_path, bob) = repo_with_two_members();

    repo.run(&["user", "remove", "bob"]).assert_success();

    assert_eq!(user_files(&repo), ["alice.txt"]);
    for name in ["a.env.amaga", "b.env.amaga"] {
        let ciphertext = std::fs::read(repo.path().join(name)).unwrap();
        assert!(decrypt_as(&repo, &ciphertext, &bob).is_err());
        let header = header_of(&repo, &identity_path, name);
        assert_eq!(
            header.exposed_to["bob"].iter().collect::<Vec<_>>(),
            [&bob.to_public().to_string()]
        );
    }
    let status = repo.run(&["status"]);
    status.assert_success();
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert_eq!(stdout.matches("NEEDS ROTATION: exposed to bob").count(), 2);
    let audit = audit_events(&repo);
    let last = audit.last().unwrap();
    assert!(last.contains("\"event\":\"user.removed\""), "got {last:?}");
    assert!(last.contains("\"user\":\"bob\""), "got {last:?}");
}

/// A `user remove` interrupted after its change step (user file deleted, name unlisted) but
/// before the pointer moved is finished by a rerun, which locks the member out.
#[test]
fn user_remove_rerun_after_interruption_locks_out() {
    let (repo, _identity_path, bob) = repo_with_two_members();
    std::fs::remove_file(repo.path().join(".amaga/users/bob.txt")).unwrap();
    let members = repo.path().join(".amaga/partitions/default/members");
    std::fs::write(&members, "alice\n").unwrap();

    repo.run(&["user", "remove", "bob"]).assert_success();

    let id = common::current_epoch_id(&repo, "default");
    assert!(!common::can_unwrap(&repo, &id, &bob));
    for name in ["a.env.amaga", "b.env.amaga"] {
        let ciphertext = std::fs::read(repo.path().join(name)).unwrap();
        assert!(decrypt_as(&repo, &ciphertext, &bob).is_err(), "{name}");
    }
}

/// A user file `user remove` cannot delete is named in the error.
#[cfg(unix)]
#[test]
fn user_remove_names_a_user_file_it_cannot_delete() {
    use std::os::unix::fs::PermissionsExt;

    let (repo, _identity_path, _bob) = repo_with_two_members();
    let users = repo.path().join(".amaga/users");

    // Restores the mode on drop so a panic cannot leave a read-only directory that the temp
    // dir cleanup fails on.
    struct Restore(std::path::PathBuf);
    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
        }
    }

    std::fs::set_permissions(&users, std::fs::Permissions::from_mode(0o555)).unwrap();
    let _restore = Restore(users.clone());
    if std::fs::write(users.join("probe"), b"").is_ok() {
        eprintln!("skipping: running as a user that ignores directory permissions");
        return;
    }

    let remove = repo.run(&["user", "remove", "bob"]);

    remove.assert_failure();
    assert!(stderr(&remove).contains("bob.txt"), "{}", stderr(&remove));
}

/// Test 14: sealing an edit clears the flag only on that file, and re-encryption never clears it.
#[test]
fn seal_change_clears_only_that_file() {
    let (repo, identity_path, _bob) = repo_with_two_members();
    repo.run(&["user", "remove", "bob"]).assert_success();
    repo.run(&["rotate"]).assert_success();
    assert!(
        !header_of(&repo, &identity_path, "a.env.amaga")
            .exposed_to
            .is_empty()
    );

    std::fs::write(repo.path().join("a.env"), b"a2-rotated").unwrap();
    repo.run(&["seal", "a.env"]).assert_success();

    assert!(
        header_of(&repo, &identity_path, "a.env.amaga")
            .exposed_to
            .is_empty()
    );
    assert!(
        !header_of(&repo, &identity_path, "b.env.amaga")
            .exposed_to
            .is_empty()
    );
}

/// Test 15: a secret added after a removal is not flagged.
#[test]
fn secret_added_after_removal_not_flagged() {
    let (repo, identity_path, _bob) = repo_with_two_members();
    repo.run(&["user", "remove", "bob"]).assert_success();

    add_secret(&repo, "c.env", b"c1");
    repo.run(&["rotate"]).assert_success();

    assert!(
        header_of(&repo, &identity_path, "c.env.amaga")
            .exposed_to
            .is_empty()
    );
}

/// `user remove` refuses the last member, an unknown member and an invalid name.
#[test]
fn user_remove_refuses_last_unknown_and_invalid() {
    let (repo, _identity_path) = repo_with_alice();
    add_secret(&repo, "secret.env", b"v1");
    let before = std::fs::read(repo.path().join("secret.env.amaga")).unwrap();

    // `../alice` would resolve to this file if the name were not validated.
    std::fs::write(repo.path().join(".amaga/alice.txt"), "not a member").unwrap();

    repo.run(&["user", "remove", "alice"]).assert_failure();
    repo.run(&["user", "remove", "nobody"]).assert_failure();
    repo.run(&["user", "remove", "../alice"]).assert_failure();

    assert!(repo.path().join(".amaga/alice.txt").exists());

    assert_eq!(user_files(&repo), ["alice.txt"]);
    assert_eq!(
        std::fs::read(repo.path().join("secret.env.amaga")).unwrap(),
        before
    );
}

/// Test 20: with an undecryptable secret `user remove` changes nothing: the user files, the
/// audit log, the epochs and the other secrets stay as they were.
#[test]
fn user_remove_with_undecryptable_secret_changes_nothing() {
    let (repo, _identity_path, _bob) = repo_with_two_members();
    corrupt(&repo, "b.env.amaga");
    let before_a = std::fs::read(repo.path().join("a.env.amaga")).unwrap();
    let before_audit = audit_events(&repo);
    let before_epochs = epoch_state(&repo);

    let remove = repo.run(&["user", "remove", "bob"]);
    remove.assert_failure();
    assert!(stderr(&remove).contains("b.env.amaga"));

    assert_eq!(user_files(&repo), ["alice.txt", "bob.txt"]);
    assert_eq!(audit_events(&repo), before_audit);
    assert_eq!(epoch_state(&repo), before_epochs);
    assert_eq!(
        std::fs::read(repo.path().join("a.env.amaga")).unwrap(),
        before_a
    );
}

/// The files being removed are not validated: a broken member file can still be removed.
#[test]
fn user_remove_accepts_a_broken_member_file() {
    let (repo, _identity_path) = repo_with_alice();
    add_secret(&repo, "secret.env", b"v1");
    std::fs::write(repo.path().join(".amaga/users/bob.asc"), "not a key").unwrap();
    repo.run(&["status"]).assert_failure();

    repo.run(&["user", "remove", "bob"]).assert_success();

    assert_eq!(user_files(&repo), ["alice.txt"]);
    repo.run(&["status"]).assert_success();
}

/// Removing yourself works; you are then no longer a member, so another member must `rotate`.
#[test]
fn user_can_remove_themselves() {
    let (repo, _identity_path) = repo_with_alice();
    let bob = write_member(&repo, "bob");
    add_secret(&repo, "secret.env", b"v1");

    repo.run(&["user", "remove", "alice"]).assert_success();

    let ciphertext = std::fs::read(repo.path().join("secret.env.amaga")).unwrap();
    let (header, body) = decrypt_as(&repo, &ciphertext, &bob).unwrap();
    assert_eq!(body, b"v1");
    assert!(header.exposed_to.contains_key("alice"));
    repo.run(&["rotate"]).assert_failure();
}

/// `user add` validates the name: `../evil` must not write outside `.amaga/users`.
#[test]
fn user_add_refuses_a_path_traversal_name() {
    let (repo, _identity_path) = repo_with_alice();
    let key = x25519::Identity::generate().to_public().to_string();

    user_add(&repo, "../evil", &key).assert_failure();

    assert!(!repo.path().join(".amaga/evil.txt").exists());
    assert_eq!(user_files(&repo), ["alice.txt"]);
}

/// The member being removed is not validated: a comment-only file and a key that duplicates
/// another member's key do not block `user remove`.
#[test]
fn user_remove_ignores_the_removed_members_empty_file_and_duplicate_key() {
    let (repo, _identity_path) = repo_with_alice();
    add_secret(&repo, "secret.env", b"v1");
    let bob_txt = repo.path().join(".amaga/users/bob.txt");

    std::fs::write(&bob_txt, "# no keys\n").unwrap();
    repo.run(&["user", "remove", "bob"]).assert_success();
    assert_eq!(user_files(&repo), ["alice.txt"]);

    let alice_key = std::fs::read_to_string(repo.path().join(".amaga/users/alice.txt")).unwrap();
    std::fs::write(&bob_txt, alice_key).unwrap();
    repo.run(&["user", "remove", "bob"]).assert_success();
    assert_eq!(user_files(&repo), ["alice.txt"]);
    repo.run(&["status"]).assert_success();
}

/// A broken `.asc` next to a valid `.txt`: both files go, and the valid `.txt` keys count as
/// bob's (so secrets get flagged for them).
#[test]
fn user_remove_with_a_broken_asc_and_a_valid_txt() {
    let (repo, identity_path) = repo_with_alice();
    let bob = write_member(&repo, "bob");
    add_secret(&repo, "secret.env", b"v1");
    std::fs::write(repo.path().join(".amaga/users/bob.asc"), "not a key").unwrap();

    repo.run(&["user", "remove", "bob"]).assert_success();

    assert_eq!(user_files(&repo), ["alice.txt"]);
    let header = header_of(&repo, &identity_path, "secret.env.amaga");
    assert!(header.exposed_to["bob"].contains(&bob.to_public().to_string()));
}

/// Test 40: a secret a branch added under an epoch that `user remove` then replaced stays
/// readable after the merge; it is stale, and `rotate` flags the removed member.
#[test]
fn branch_secret_under_old_epoch_after_user_remove() {
    let (repo, identity_path) = repo_with_alice();
    let bob = x25519::Identity::generate().to_public().to_string();
    user_add(&repo, "bob", &bob).assert_success();
    repo.commit_all("add bob");
    let main = current_branch(&repo);

    repo.git(&["checkout", "-b", "feature"]).assert_success();
    add_secret(&repo, "feature.env", b"f");
    repo.commit_all("feature adds a secret");
    // `main` does not ignore the plaintext, so it must not stay in the work tree.
    std::fs::remove_file(repo.path().join("feature.env")).unwrap();

    repo.git(&["checkout", &main]).assert_success();
    repo.run(&["user", "remove", "bob"]).assert_success();
    repo.commit_all("remove bob");
    repo.git(&["merge", "--no-edit", "feature"])
        .assert_success();

    repo.run(&["open", "feature.env"]).assert_success();
    assert_eq!(
        std::fs::read(repo.path().join("feature.env")).unwrap(),
        b"f"
    );
    let status = repo.run(&["status"]);
    assert_eq!(status.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&status.stdout).contains("run git-amaga rotate"));

    repo.run(&["rotate"]).assert_success();
    let header = header_of(&repo, &identity_path, "feature.env.amaga");
    assert!(header.exposed_to.contains_key("bob"));
}

/// Test 43: a member who is not in an old epoch cannot read the secrets still under it, and
/// their `rotate` writes nothing; after another member's `rotate` they can.
#[test]
fn member_not_in_old_epoch_cannot_read_its_secrets() {
    let (repo, _identity_path) = repo_with_alice();
    repo.commit_all("init");
    let main = current_branch(&repo);
    repo.git(&["checkout", "-b", "feature"]).assert_success();
    add_secret(&repo, "feature.env", b"f");
    repo.commit_all("feature adds a secret");
    std::fs::remove_file(repo.path().join("feature.env")).unwrap();

    repo.git(&["checkout", &main]).assert_success();
    repo.run(&["rotate"]).assert_success();
    let (carol_key, carol_config) = second_identity(&repo, "carol");
    user_add(&repo, "carol", &carol_key).assert_success();
    repo.commit_all("rotate, add carol");
    repo.git(&["merge", "--no-edit", "feature"])
        .assert_success();

    let as_carol = |args: &[&str]| run_as(&repo, &carol_config, args);
    let secret_before = std::fs::read(repo.path().join("feature.env.amaga")).unwrap();
    let epochs_before = epoch_state(&repo);
    let audit_before = audit_events(&repo);

    as_carol(&["open", "feature.env"]).assert_failure();
    as_carol(&["rotate"]).assert_failure();
    assert!(!repo.path().join("feature.env").exists());
    assert_eq!(
        std::fs::read(repo.path().join("feature.env.amaga")).unwrap(),
        secret_before
    );
    assert_eq!(epoch_state(&repo), epochs_before);
    assert_eq!(audit_events(&repo), audit_before);

    repo.run(&["rotate"]).assert_success();
    as_carol(&["open", "feature.env"]).assert_success();
    assert_eq!(
        std::fs::read(repo.path().join("feature.env")).unwrap(),
        b"f"
    );
}

/// Test 44: a member file written by hand leaves the epoch stale: writes refuse with the rotate
/// hint, and `rotate` finishes the job without flagging anyone.
#[test]
fn interrupted_user_add_finished_by_rotate() {
    let (repo, identity_path) = repo_with_alice();
    add_secret(&repo, "secret.env", b"v1");
    let carol = write_member_file(&repo, "carol");

    let status = repo.run(&["status"]);
    assert_eq!(status.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&status.stdout).contains("run git-amaga rotate"));

    let before = std::fs::read(repo.path().join("secret.env.amaga")).unwrap();
    let before_audit = audit_events(&repo);
    let epoch_file = repo
        .path()
        .join(git_amaga_core::epoch::file_path(&common::current_epoch_id(
            &repo, "default",
        )));
    let epoch_before = std::fs::read(&epoch_file).unwrap();
    std::fs::write(repo.path().join("new.env"), b"n").unwrap();
    std::fs::write(repo.path().join("secret.env"), b"v2").unwrap();
    let dave = x25519::Identity::generate().to_public().to_string();
    let user_add_dave = ["user", "add", "dave", &dave];
    let refused_commands: Vec<&[&str]> = vec![
        &["add", "new.env"],
        &["seal", "secret.env"],
        &user_add_dave,
        &["dismiss", "--user", "x"],
    ];
    for args in refused_commands {
        let refused = repo.run(args);
        refused.assert_failure();
        assert!(
            stderr(&refused).contains("rotate"),
            "{args:?}: got {:?}",
            stderr(&refused)
        );
    }
    assert!(!repo.path().join("new.env.amaga").exists());
    assert_eq!(user_files(&repo), ["alice.txt", "carol.txt"]);
    assert_eq!(
        std::fs::read(repo.path().join("secret.env.amaga")).unwrap(),
        before
    );
    assert_eq!(audit_events(&repo), before_audit);
    assert_eq!(std::fs::read(&epoch_file).unwrap(), epoch_before);

    std::fs::write(repo.path().join("secret.env"), b"v1").unwrap();
    repo.run(&["rotate"]).assert_success();
    let ciphertext = std::fs::read(repo.path().join("secret.env.amaga")).unwrap();
    assert_eq!(decrypt_as(&repo, &ciphertext, &carol).unwrap().1, b"v1");
    assert!(
        header_of(&repo, &identity_path, "secret.env.amaga")
            .exposed_to
            .is_empty()
    );
}

/// Test 42: a member added on a branch and a removal on main merge cleanly into a stale state;
/// after `rotate` the newcomer reads everything, the removed member is flagged and the newcomer
/// is not. A member `bobby` sits between the two edits of `default/members`, so that they do not
/// touch adjacent lines (which would conflict as text, ADR-0017).
#[test]
fn member_added_on_branch_and_removal_on_main() {
    let (repo, identity_path) = repo_with_alice();
    add_secret(&repo, "a.env", b"a1");
    let bob = x25519::Identity::generate().to_public().to_string();
    user_add(&repo, "bob", &bob).assert_success();
    let bobby = x25519::Identity::generate().to_public().to_string();
    user_add(&repo, "bobby", &bobby).assert_success();
    repo.commit_all("base");
    std::fs::remove_file(repo.path().join("a.env")).unwrap();
    let main = current_branch(&repo);

    repo.git(&["checkout", "-b", "feature"]).assert_success();
    let (carol_key, carol_config) = second_identity(&repo, "carol");
    user_add(&repo, "carol", &carol_key).assert_success();
    repo.commit_all("add carol");

    repo.git(&["checkout", &main]).assert_success();
    repo.run(&["user", "remove", "bob"]).assert_success();
    repo.commit_all("remove bob");
    repo.git(&["merge", "--no-edit", "feature"])
        .assert_success();

    let status = repo.run(&["status"]);
    assert_eq!(status.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&status.stdout).contains("run git-amaga rotate"));
    std::fs::write(repo.path().join("new.env"), b"n").unwrap();
    let add = repo.run(&["add", "new.env"]);
    add.assert_failure();
    assert!(stderr(&add).contains("rotate"), "got {:?}", stderr(&add));
    std::fs::remove_file(repo.path().join("new.env")).unwrap();

    repo.run(&["rotate"]).assert_success();
    run_as(&repo, &carol_config, &["open"]).assert_success();
    assert_eq!(std::fs::read(repo.path().join("a.env")).unwrap(), b"a1");
    let exposed = header_of(&repo, &identity_path, "a.env.amaga").exposed_to;
    assert_eq!(exposed.keys().collect::<Vec<_>>(), ["bob"]);
    repo.run(&["status"]).assert_success();
}

/// A repository with members alice, bob and carol, secrets `a.env` and `b.env` (both left open),
/// and bob and carol removed, so both secrets are flagged for both.
fn repo_with_two_exposed_secrets() -> Repo {
    let (repo, _identity_path) = repo_with_alice();
    for name in ["bob", "carol"] {
        let key = x25519::Identity::generate().to_public().to_string();
        user_add(&repo, name, &key).assert_success();
    }
    add_secret(&repo, "a.env", b"a1");
    add_secret(&repo, "b.env", b"b1");
    repo.run(&["user", "remove", "bob"]).assert_success();
    repo.run(&["user", "remove", "carol"]).assert_success();
    repo
}

fn exposed(repo: &Repo, identity_path: &Path, path: &str) -> Vec<String> {
    header_of(repo, identity_path, path)
        .exposed_to
        .into_keys()
        .collect()
}

/// Test 49: `dismiss --user bob a.env` clears bob from that secret only and audits it.
#[test]
fn dismiss_clears_selected_user_and_paths() {
    let repo = repo_with_two_exposed_secrets();
    let identity_path = repo.path().join("identity.txt");
    let audit_before = audit_events(&repo);

    let dismiss = repo.run(&["dismiss", "--user", "bob", "a.env"]);
    dismiss.assert_success();

    assert_eq!(
        String::from_utf8_lossy(&dismiss.stdout),
        "dismissed a.env.amaga\n"
    );
    assert_eq!(exposed(&repo, &identity_path, "a.env.amaga"), ["carol"]);
    assert_eq!(
        exposed(&repo, &identity_path, "b.env.amaga"),
        ["bob", "carol"]
    );
    // The plaintext is untouched: `status` finds no edit or outdated copy, only the warnings.
    assert_eq!(std::fs::read(repo.path().join("a.env")).unwrap(), b"a1");
    let status = repo.run(&["status"]);
    status.assert_success();
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert!(stdout.contains("WARN a.env.amaga: NEEDS ROTATION: exposed to carol"));
    assert!(stdout.contains("WARN b.env.amaga: NEEDS ROTATION: exposed to bob, carol"));
    let audit = audit_events(&repo);
    let added = &audit[audit_before.len()..];
    assert_eq!(added.len(), 1, "got {added:?}");
    assert!(added[0].contains("\"event\":\"exposure.dismissed\""));
    assert!(added[0].contains("\"path\":\"a.env\""));
    assert!(added[0].contains("\"user\":\"bob\""));
}

/// Test 50: a bare `dismiss` and an unknown `--user` are refused and write nothing.
#[test]
fn dismiss_refuses_without_target_or_unknown_user() {
    let repo = repo_with_two_exposed_secrets();
    let read = |name: &str| std::fs::read(repo.path().join(name)).unwrap();
    let before = (
        read("a.env.amaga"),
        read("b.env.amaga"),
        audit_events(&repo),
    );

    repo.run(&["dismiss"]).assert_failure();
    repo.run(&["dismiss", "--user", "nobody"]).assert_failure();

    assert_eq!(
        (
            read("a.env.amaga"),
            read("b.env.amaga"),
            audit_events(&repo)
        ),
        before
    );
}

/// Test 51: `dismiss --user bob` clears bob everywhere; repeating it is `NotExposed`.
#[test]
fn dismiss_user_across_all_secrets() {
    let repo = repo_with_two_exposed_secrets();
    let identity_path = repo.path().join("identity.txt");

    repo.run(&["dismiss", "--user", "bob"]).assert_success();
    for name in ["a.env.amaga", "b.env.amaga"] {
        assert_eq!(exposed(&repo, &identity_path, name), ["carol"]);
    }
    let before = audit_events(&repo);

    repo.run(&["dismiss", "--user", "bob"]).assert_failure();
    assert_eq!(audit_events(&repo), before);
}

/// `user add` refuses while a member was removed by hand: re-wrapping an epoch that the removed
/// key can still open would hide that key from the exposure record. Nothing is written.
#[test]
fn user_add_refuses_while_a_member_was_removed_by_hand() {
    let (repo, _identity_path) = repo_with_alice();
    write_member(&repo, "charlie");
    add_secret(&repo, "secret.env", b"v1");
    std::fs::remove_file(repo.path().join(".amaga/users/charlie.txt")).unwrap();
    let epoch_file = repo
        .path()
        .join(git_amaga_core::epoch::file_path(&common::current_epoch_id(
            &repo, "default",
        )));
    let epoch_before = std::fs::read(&epoch_file).unwrap();
    let audit_before = audit_events(&repo);
    let dave = x25519::Identity::generate().to_public().to_string();

    let refused = user_add(&repo, "dave", &dave);

    refused.assert_failure();
    assert!(
        stderr(&refused).contains("rotate"),
        "got {:?}",
        stderr(&refused)
    );
    assert_eq!(std::fs::read(&epoch_file).unwrap(), epoch_before);
    assert_eq!(user_files(&repo), ["alice.txt"]);
    assert_eq!(audit_events(&repo), audit_before);
}
