//! Shared integration-test helpers: an isolated Git repository for running the built binary
//! (plan 11).

// Each test crate uses a different subset of these helpers.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A throwaway repository with its own `GIT_CONFIG_GLOBAL`, `HOME`/`USERPROFILE` and
/// `GNUPGHOME`, so child processes never touch the developer's real config, home or keyring (on
/// Windows gpg ignores `HOME` and uses `%APPDATA%\gnupg`). The isolation is set on children only,
/// never via `set_var`.
pub struct Repo {
    dir: tempfile::TempDir,
    global_config: PathBuf,
    home: tempfile::TempDir,
    gnupg_home: tempfile::TempDir,
}

impl Repo {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let global_config = dir.path().join("gitconfig");
        std::fs::write(&global_config, "").expect("write empty global config");
        let home = tempfile::tempdir().expect("tempdir");
        let repo = Self {
            dir,
            global_config,
            home,
            gnupg_home: gnupg_tempdir(),
        };
        repo.git(&["init", "--quiet"]).assert_success();
        repo.git(&["config", "user.email", "test@example.invalid"])
            .assert_success();
        repo.git(&["config", "user.name", "Test"]).assert_success();
        repo
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    fn isolate(&self, command: &mut Command, cwd: &Path) {
        // A hook or `rebase -x` exports GIT_DIR, GIT_INDEX_FILE, ...; children must not inherit
        // them.
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("GIT_") {
                command.env_remove(key);
            }
        }
        command
            .current_dir(cwd)
            .env("GIT_CONFIG_GLOBAL", &self.global_config)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", self.home.path())
            .env("USERPROFILE", self.home.path())
            .env("GNUPGHOME", self.gnupg_home.path());
    }

    pub fn git(&self, args: &[&str]) -> Output {
        let mut command = Command::new("git");
        command.args(args);
        self.isolate(&mut command, self.path());
        command.output().expect("spawn git")
    }

    pub fn run(&self, args: &[&str]) -> Output {
        self.run_in(self.path(), args)
    }

    /// Like [`Repo::run`], but inside `cwd`.
    pub fn run_in(&self, cwd: &Path, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_git-amaga"));
        command.args(args);
        self.isolate(&mut command, cwd);
        command.output().expect("spawn git-amaga")
    }

    /// Like [`Repo::run`], with `extra_env` applied after the isolation.
    pub fn run_with_env(&self, args: &[&str], extra_env: &[(&str, &std::ffi::OsStr)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_git-amaga"));
        command.args(args);
        self.isolate(&mut command, self.path());
        for (key, value) in extra_env {
            command.env(key, value);
        }
        command.output().expect("spawn git-amaga")
    }

    /// Commits everything except the identity file `repo_with_alice` writes into the repository.
    pub fn commit_all(&self, message: &str) {
        self.git(&["add", "-A", "--", ".", ":(exclude)identity.txt"])
            .assert_success();
        self.git(&["commit", "-m", message]).assert_success();
    }

    pub fn git_in(&self, cwd: &Path, args: &[&str]) -> Output {
        let mut command = Command::new("git");
        command.args(args);
        self.isolate(&mut command, cwd);
        command.output().expect("spawn git")
    }
}

impl Drop for Repo {
    fn drop(&mut self) {
        // gpg only populates the directory when it started an agent or wrote a keyring.
        if std::fs::read_dir(self.gnupg_home.path())
            .is_ok_and(|mut entries| entries.next().is_some())
        {
            kill_gpg_agent(self.gnupg_home.path());
        }
    }
}

/// A fresh, empty `GNUPGHOME` directory with a path short enough for gpg-agent's socket (limited
/// to about 107 bytes) and mode 0700 on unix.
fn gnupg_tempdir() -> tempfile::TempDir {
    #[cfg(unix)]
    let dir = tempfile::Builder::new()
        .tempdir_in("/tmp")
        .expect("tempdir_in /tmp");
    // Windows temp paths (`C:\Users\RUNNER~1\AppData\Local\Temp`) are already short.
    #[cfg(not(unix))]
    let dir = tempfile::tempdir().expect("tempdir");
    #[cfg(unix)]
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("chmod gnupghome");
    dir
}

fn kill_gpg_agent(gnupg_home: &Path) {
    let _ = Command::new("gpgconf")
        .env("GNUPGHOME", gnupg_home)
        .args(["--kill", "gpg-agent"])
        .status();
}

/// A repository with one age member `alice`, plus the identity file path.
pub fn repo_with_alice() -> (Repo, PathBuf) {
    let repo = Repo::new();
    let identity_path = repo.path().join("identity.txt");
    repo.run(&["keygen", identity_path.to_str().unwrap()])
        .assert_success();
    repo.run(&["init", "alice"]).assert_success();
    (repo, identity_path)
}

#[cfg(unix)]
pub fn find_on_path(name: &str) -> PathBuf {
    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths).find_map(|dir| {
                let candidate = dir.join(name);
                candidate.is_file().then_some(candidate)
            })
        })
        .unwrap_or_else(|| panic!("{name} not found on PATH"))
}

/// A throwaway `GNUPGHOME` for gpg tests; the agent is killed on drop. Pass the path to children
/// only.
pub struct GpgHome {
    dir: tempfile::TempDir,
}

impl GpgHome {
    /// `None`, with a skip notice, if `gpg` is not on PATH.
    pub fn new(test_name: &str) -> Option<Self> {
        if Command::new("gpg").arg("--version").output().is_err() {
            println!("skipping {test_name}: gpg not on PATH");
            return None;
        }
        Some(Self {
            dir: gnupg_tempdir(),
        })
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Imports a passphrase-less armored secret key.
    pub fn import_secret_key(&self, armored_secret: &str) {
        let key_path = self.dir.path().join("import.asc");
        std::fs::write(&key_path, armored_secret).expect("write key fixture");
        let status = Command::new("gpg")
            .env("GNUPGHOME", self.path())
            .args(["--batch", "--import"])
            .arg(&key_path)
            .status()
            .expect("spawn gpg --import");
        assert!(status.success(), "gpg --import failed");
    }

    /// Generates a passphrase-less ed25519/cv25519 key for `uid`; returns its primary
    /// fingerprint.
    pub fn generate_key(&self, uid: &str) -> String {
        let output = Command::new("gpg")
            .env("GNUPGHOME", self.path())
            .args(["--batch", "--passphrase", "", "--status-fd", "1"])
            .args(["--quick-gen-key", uid, "default", "default", "never"])
            .output()
            .expect("spawn gpg --quick-gen-key");
        output.assert_success();
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|l| l.strip_prefix("[GNUPG:] KEY_CREATED B "))
            .and_then(|rest| rest.split(' ').next())
            .expect("KEY_CREATED status line")
            .to_string()
    }

    /// Revokes a key from `generate_key` using the certificate gpg stored at creation time.
    pub fn revoke_key(&self, fpr: &str) {
        let cert_path = self.dir.path().join(format!("openpgp-revocs.d/{fpr}.rev"));
        let cert = std::fs::read_to_string(cert_path).expect("read revocation certificate");
        // The stored certificate is commented out with a leading ':' to prevent accidents.
        let import_path = self.dir.path().join("revoke.asc");
        std::fs::write(&import_path, cert.replace(":-----BEGIN", "-----BEGIN"))
            .expect("write revocation certificate");
        let status = Command::new("gpg")
            .env("GNUPGHOME", self.path())
            .args(["--batch", "--import"])
            .arg(&import_path)
            .status()
            .expect("spawn gpg --import");
        assert!(status.success(), "gpg --import of the revocation failed");
    }

    /// The armored export-minimal public key for `fpr`, as stored in `.amaga/users/<name>.asc`.
    pub fn export_minimal(&self, fpr: &str) -> String {
        let output = Command::new("gpg")
            .env("GNUPGHOME", self.path())
            .args(["--armor", "--export", "--export-options", "export-minimal"])
            .arg(fpr)
            .output()
            .expect("spawn gpg --export");
        output.assert_success();
        String::from_utf8(output.stdout).expect("utf-8 armor")
    }

    /// Certifies `signee` with `signer` (a third-party certification on the signee's user IDs).
    pub fn certify(&self, signer: &str, signee: &str) {
        let status = Command::new("gpg")
            .env("GNUPGHOME", self.path())
            .args(["--batch", "--yes", "--pinentry-mode", "loopback"])
            .args(["--passphrase", "", "--local-user", signer])
            .args(["--quick-sign-key", signee])
            .status()
            .expect("spawn gpg --quick-sign-key");
        assert!(status.success(), "gpg --quick-sign-key failed");
    }

    /// Deletes one key's secret material (`<fpr>!`), keeping the rest of the key.
    pub fn delete_secret_key(&self, fpr: &str) {
        let status = Command::new("gpg")
            .env("GNUPGHOME", self.path())
            .args(["--batch", "--yes", "--delete-secret-keys"])
            .arg(format!("{fpr}!"))
            .status()
            .expect("spawn gpg --delete-secret-keys");
        assert!(status.success(), "gpg --delete-secret-keys failed");
    }
}

impl Drop for GpgHome {
    fn drop(&mut self) {
        kill_gpg_agent(self.path());
    }
}

pub trait OutputExt {
    /// Panics with stderr if the command did not exit successfully.
    fn assert_success(&self) -> &Self;
    /// Panics if the command exited successfully.
    fn assert_failure(&self) -> &Self;
}

impl OutputExt for Output {
    fn assert_success(&self) -> &Self {
        assert!(
            self.status.success(),
            "command failed (status {:?}): {}",
            self.status.code(),
            String::from_utf8_lossy(&self.stderr)
        );
        self
    }

    fn assert_failure(&self) -> &Self {
        assert!(
            !self.status.success(),
            "command unexpectedly succeeded: {}",
            String::from_utf8_lossy(&self.stdout)
        );
        self
    }
}
