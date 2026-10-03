//! Integration tests for `import-git-crypt` (ADR-0018, plan 7.5, tests 65-69). Only test 69 needs
//! a real git-crypt; the others simulate an unlocked repository with tracked plaintext, the
//! attribute lines and `.git-crypt/keys/...` files.

mod common;

use std::path::{Path, PathBuf};

use common::{GpgHome, OutputExt, Repo, decrypt_file, git_crypt_available};
use git_amaga_core::secret::label_of;

const ALICE_ASC: &str = include_str!("../../core/tests/fixtures/valid_cv25519.asc");
const UNKNOWN_FPR: &str = "0123456789ABCDEF0123456789ABCDEF01234567";
const ATTRIBUTES: &str = "secret.env filter=git-crypt diff=git-crypt\n\
prod/** filter=git-crypt-Prod diff=git-crypt-Prod\n\
*.key filter=git-crypt diff=git-crypt -text\n";

fn alice_fpr() -> String {
    git_amaga_core::gpg::validate(ALICE_ASC)
        .unwrap()
        .primary_fpr()
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn read(repo: &Repo, path: &str) -> Vec<u8> {
    std::fs::read(repo.path().join(path)).unwrap()
}

/// A repository where alice (an age key and the fixture's GPG key) ran `init`, plus the files of
/// an unlocked git-crypt repository, committed. `holders` are `(git-crypt key, fingerprint)`
/// pairs besides alice, who holds `default`. Returns the directory holding alice's identity file.
fn simulated_repo(holders: &[(&str, &str)]) -> (Repo, tempfile::TempDir, PathBuf) {
    simulated_repo_with(holders, "", &[])
}

/// Like [`simulated_repo`], with more `.gitattributes` lines and more tracked files.
fn simulated_repo_with(
    holders: &[(&str, &str)],
    extra_attributes: &str,
    extra_files: &[(&str, &str)],
) -> (Repo, tempfile::TempDir, PathBuf) {
    let repo = Repo::new();
    let keys = tempfile::tempdir().unwrap();
    let identity_path = keys.path().join("identity.txt");
    let keygen = repo.run(&["keygen", identity_path.to_str().unwrap()]);
    keygen.assert_success();
    let asc_path = keys.path().join("alice.asc");
    std::fs::write(&asc_path, ALICE_ASC).unwrap();
    let age_key = stdout(&keygen).trim().to_string();
    repo.run(&["init", "alice", &age_key, asc_path.to_str().unwrap()])
        .assert_success();

    // What an unlocked git-crypt repository has: the filter in the local config.
    for key in ["clean", "smudge"] {
        let name = format!("filter.git-crypt.{key}");
        repo.git(&["config", &name, "cat"]).assert_success();
    }
    let gitattributes = repo.path().join(".gitattributes");
    let existing = std::fs::read_to_string(&gitattributes).unwrap();
    std::fs::write(
        &gitattributes,
        format!("{existing}{ATTRIBUTES}{extra_attributes}"),
    )
    .unwrap();
    std::fs::create_dir(repo.path().join("prod")).unwrap();
    for (path, body) in [
        ("secret.env", "S=1\n"),
        ("prod/db.env", "DB=1\n"),
        ("a.key", "key\r\nbytes"),
        ("plain.txt", "plain\n"),
    ]
    .iter()
    .chain(extra_files)
    {
        std::fs::write(repo.path().join(path), body).unwrap();
    }
    let alice = alice_fpr();
    let mut all = vec![("default", alice.as_str())];
    all.extend_from_slice(holders);
    std::fs::create_dir_all(repo.path().join(".git-crypt")).unwrap();
    std::fs::write(
        repo.path().join(".git-crypt/.gitattributes"),
        "* !filter !diff\n*.gpg binary\n",
    )
    .unwrap();
    for (key, fpr) in all {
        let dir = repo.path().join(format!(".git-crypt/keys/{key}/0"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{fpr}.gpg")), "wrapped").unwrap();
    }
    repo.commit_all("simulated git-crypt repository");
    (repo, keys, identity_path)
}

/// Everything an import must leave alone when it refuses: the status, `.amaga`, `.gitignore` and
/// `.gitattributes`.
fn snapshot(repo: &Repo) -> Vec<(String, Vec<u8>)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, root, out);
            } else {
                let name = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                out.push((name, std::fs::read(&path).unwrap()));
            }
        }
    }
    let mut tree = Vec::new();
    walk(&repo.path().join(".amaga"), repo.path(), &mut tree);
    tree.sort();
    let status = stdout(&repo.git(&["status", "--porcelain"]));
    tree.push(("git status".into(), status.into_bytes()));
    for file in [".gitignore", ".gitattributes"] {
        tree.push((file.into(), read(repo, file)));
    }
    tree
}

fn tracked_files(repo: &Repo) -> Vec<String> {
    stdout(&repo.git(&["ls-files"]))
        .lines()
        .map(str::to_string)
        .collect()
}

/// Test 65: a simulated unlocked repository is imported, with an unknown holder skipped.
#[test]
fn import_simulated_git_crypt_repo() {
    let (repo, _keys, identity_path) = simulated_repo(&[("Prod", UNKNOWN_FPR)]);

    let import = repo.run(&["import-git-crypt"]);
    import.assert_success();
    let err = stderr(&import);
    assert!(err.contains(UNKNOWN_FPR), "{err}");
    assert!(err.contains("git history"), "{err}");

    assert_eq!(read(&repo, ".amaga/partitions/default/members"), b"alice\n");
    assert_eq!(read(&repo, ".amaga/partitions/prod/members"), b"alice\n");
    for (path, partition, body) in [
        ("secret.env", "default", &b"S=1\n"[..]),
        ("a.key", "default", &b"key\r\nbytes"[..]),
        ("prod/db.env", "prod", &b"DB=1\n"[..]),
    ] {
        let ciphertext = read(&repo, &format!("{path}.amaga"));
        assert_eq!(label_of(path, &ciphertext).unwrap(), partition);
        let (_, decrypted) = decrypt_file(&repo, &identity_path, &format!("{path}.amaga"));
        assert_eq!(decrypted, body, "{path}");
        repo.git(&["check-ignore", "-q", path]).assert_success();
    }

    let tracked = tracked_files(&repo);
    for path in ["secret.env", "prod/db.env", "a.key"] {
        assert!(
            !tracked.contains(&path.to_string()),
            "{path} is still tracked"
        );
    }
    assert!(tracked.contains(&"plain.txt".to_string()));
    let attributes = String::from_utf8(read(&repo, ".gitattributes")).unwrap();
    assert!(attributes.contains("*.key -text\n"), "{attributes}");
    assert!(!attributes.contains("git-crypt"), "{attributes}");
    let attr = repo.git(&["check-attr", "filter", "--", "prod/db.env.amaga"]);
    assert!(stdout(&attr).trim_end().ends_with(": unspecified"));
    assert!(!repo.path().join(".git-crypt").exists());
    let smudge = repo.git(&["config", "filter.git-crypt.smudge"]);
    assert_eq!(stdout(&smudge).trim(), "cat");
}

/// Test 66: locked or staged files make the import refuse before it writes anything.
#[test]
fn import_refuses_locked_or_staged_files_and_writes_nothing() {
    let (repo, _keys, _identity_path) = simulated_repo(&[]);
    let before = snapshot(&repo);

    std::fs::write(repo.path().join("secret.env"), b"\0GITCRYPT\0locked").unwrap();
    let locked_before = snapshot(&repo);
    let import = repo.run(&["import-git-crypt"]);
    import.assert_failure();
    assert!(
        stderr(&import).contains("git-crypt unlock"),
        "{}",
        stderr(&import)
    );
    assert_eq!(snapshot(&repo), locked_before);

    std::fs::write(repo.path().join("secret.env"), b"S=1\n").unwrap();
    assert_eq!(snapshot(&repo), before);
    std::fs::write(repo.path().join("secret.env"), b"S=2\n").unwrap();
    repo.git(&["add", "secret.env"]).assert_success();
    let staged_before = snapshot(&repo);
    repo.run(&["import-git-crypt"]).assert_failure();
    assert_eq!(snapshot(&repo), staged_before);
}

/// Test 67: a repository that already has a secret is refused.
#[test]
fn import_refuses_repo_with_secrets() {
    let (repo, _keys, _identity_path) = simulated_repo(&[]);
    std::fs::write(repo.path().join("extra.env"), b"x").unwrap();
    repo.run(&["add", "extra.env"]).assert_success();
    let before = snapshot(&repo);

    repo.run(&["import-git-crypt"]).assert_failure();
    assert_eq!(snapshot(&repo), before);
}

/// Test 68: a holder is exported from the keyring, named from its user ID or by `--name`.
#[test]
fn import_exports_holder_from_keyring_and_names_it() {
    let Some(gpg_home) = GpgHome::new("import_exports_holder_from_keyring_and_names_it") else {
        return;
    };
    let dave = gpg_home.generate_key("Dave Smith <dave.smith@example.invalid>");
    let env = [("GNUPGHOME", gpg_home.path().as_os_str())];

    let (repo, _keys, _identity_path) = simulated_repo(&[("default", &dave)]);
    let import = repo.run_with_env(&["import-git-crypt"], &env);
    import.assert_success();
    assert!(repo.path().join(".amaga/users/dave.smith.asc").exists());
    assert!(stdout(&import).contains(&format!("dave.smith: GPG key {dave}")));
    let members = read(&repo, ".amaga/partitions/default/members");
    assert_eq!(members, b"alice\ndave.smith\n");

    let (repo, _keys, _identity_path) = simulated_repo(&[("default", &dave)]);
    let wrong = format!("{UNKNOWN_FPR}=x");
    repo.run_with_env(&["import-git-crypt", "--name", &wrong], &env)
        .assert_failure();
    assert!(!repo.path().join(".amaga/users/x.asc").exists());
    let named = format!("{dave}=dave");
    repo.run_with_env(&["import-git-crypt", "--name", &named], &env)
        .assert_success();
    assert!(repo.path().join(".amaga/users/dave.asc").exists());
}

/// Test 69: a repository set up and locked by the real git-crypt imports once unlocked.
#[test]
fn import_real_git_crypt_repo() {
    let name = "import_real_git_crypt_repo";
    let Some(gpg_home) = GpgHome::new(name) else {
        return;
    };
    if !git_crypt_available(name) {
        return;
    }
    let dave = gpg_home.generate_key("Dave <dave@example.invalid>");
    let env = [("GNUPGHOME", gpg_home.path().as_os_str())];
    let repo = Repo::new();
    let keys = tempfile::tempdir().unwrap();
    let identity_path = keys.path().join("identity.txt");
    repo.run(&["keygen", identity_path.to_str().unwrap()])
        .assert_success();
    repo.run(&["init", "alice"]).assert_success();
    repo.commit_all("init");

    repo.run_tool("git-crypt", &["init"], &env).assert_success();
    repo.run_tool("git-crypt", &["add-gpg-user", "--trusted", &dave], &env)
        .assert_success();
    let gitattributes = repo.path().join(".gitattributes");
    let existing = std::fs::read_to_string(&gitattributes).unwrap();
    let line = "secret.env filter=git-crypt diff=git-crypt\n";
    std::fs::write(&gitattributes, format!("{existing}{line}")).unwrap();
    std::fs::write(repo.path().join("secret.env"), b"S=1\nbinary\0bytes").unwrap();
    repo.commit_all("add the secret");

    repo.run_tool("git-crypt", &["lock"], &env).assert_success();
    let locked = repo.run_with_env(&["import-git-crypt"], &env);
    locked.assert_failure();
    assert!(
        stderr(&locked).contains("git-crypt unlock"),
        "{}",
        stderr(&locked)
    );

    repo.run_tool("git-crypt", &["unlock"], &env)
        .assert_success();
    repo.run_with_env(&["import-git-crypt"], &env)
        .assert_success();
    assert!(repo.path().join(".amaga/users/dave.asc").exists());
    let (_, body) = decrypt_file(&repo, &identity_path, "secret.env.amaga");
    assert_eq!(body, b"S=1\nbinary\0bytes");
}

/// An attribute with an empty value (`filter=`) must not hide the files after it: every file with
/// a git-crypt filter becomes a secret, and none is left behind in clear.
#[test]
fn import_covers_every_file_after_an_empty_attribute_value() {
    let (repo, _keys, identity_path) = simulated_repo_with(
        &[],
        "b.txt filter=\nc.env filter=git-crypt diff=git-crypt\n",
        &[("b.txt", "b\n"), ("c.env", "C_SECRET=1\n")],
    );

    repo.run(&["import-git-crypt"]).assert_success();

    for (path, body) in [
        ("a.key", &b"key\r\nbytes"[..]),
        ("c.env", b"C_SECRET=1\n"),
        ("secret.env", b"S=1\n"),
        ("prod/db.env", b"DB=1\n"),
    ] {
        let (_, decrypted) = decrypt_file(&repo, &identity_path, &format!("{path}.amaga"));
        assert_eq!(decrypted, body, "{path}");
    }
    let tracked = tracked_files(&repo);
    assert!(!tracked.contains(&"c.env".to_string()), "{tracked:?}");
    assert!(tracked.contains(&"b.txt".to_string()));
}
