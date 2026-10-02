//! Shared helpers for integration tests: an isolated Git repository used to run the built
//! `git-amaga` binary without ever touching the developer's own Git config (plan section 11).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A throwaway Git repository with its own `GIT_CONFIG_GLOBAL` file and its own `HOME`/
/// `USERPROFILE`, so `git` and `git-amaga` subprocesses spawned through [`Repo::git`]/
/// [`Repo::run`] never read or write `~/.gitconfig`, `~/.config/git-amaga/identity.txt`, or any
/// other file under the developer's real home directory. The isolation vars are set only on
/// those child processes, never via `std::env::set_var` on this test process.
pub struct Repo {
    dir: tempfile::TempDir,
    global_config: PathBuf,
    home: tempfile::TempDir,
}

impl Repo {
    /// Creates a new, isolated repository with `git init` already run.
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let global_config = dir.path().join("gitconfig");
        std::fs::write(&global_config, "").expect("write empty global config");
        let home = tempfile::tempdir().expect("tempdir");
        let repo = Self {
            dir,
            global_config,
            home,
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

    fn isolate(command: &mut Command, cwd: &Path, global_config: &Path, home: &Path) {
        command
            .current_dir(cwd)
            .env("GIT_CONFIG_GLOBAL", global_config)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", home)
            .env("USERPROFILE", home);
    }

    /// Runs `git` with `args` inside this repository, isolated from the developer's own config.
    pub fn git(&self, args: &[&str]) -> Output {
        let mut command = Command::new("git");
        command.args(args);
        Self::isolate(
            &mut command,
            self.path(),
            &self.global_config,
            self.home.path(),
        );
        command.output().expect("spawn git")
    }

    /// Runs the built `git-amaga` binary with `args` inside this repository, isolated the same
    /// way. `git-amaga` in turn spawns `git` as a subprocess, inheriting this isolation.
    pub fn run(&self, args: &[&str]) -> Output {
        self.run_in(self.path(), args)
    }

    /// Like [`Repo::run`], but inside `cwd` (for example a subdirectory of the repository),
    /// to exercise commands that resolve paths relative to the current directory.
    pub fn run_in(&self, cwd: &Path, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_git-amaga"));
        command.args(args);
        Self::isolate(&mut command, cwd, &self.global_config, self.home.path());
        command.output().expect("spawn git-amaga")
    }

    /// Like [`Repo::run`], with `extra_env` applied after the isolation (never via `set_var`).
    pub fn run_with_env(&self, args: &[&str], extra_env: &[(&str, &std::ffi::OsStr)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_git-amaga"));
        command.args(args);
        Self::isolate(
            &mut command,
            self.path(),
            &self.global_config,
            self.home.path(),
        );
        for (key, value) in extra_env {
            command.env(key, value);
        }
        command.output().expect("spawn git-amaga")
    }

    /// Runs `git` inside `cwd` rather than the repository root (for example to `clone` it).
    pub fn git_in(&self, cwd: &Path, args: &[&str]) -> Output {
        let mut command = Command::new("git");
        command.args(args);
        Self::isolate(&mut command, cwd, &self.global_config, self.home.path());
        command.output().expect("spawn git")
    }
}

/// Finds `name` on the current `PATH`.
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

/// A throwaway `GNUPGHOME` for gpg tests; the agent is killed on drop. Pass [`GpgHome::path`]
/// to child processes only.
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
        // gpg-agent's socket path is limited to about 107 bytes, so keep the path short.
        #[cfg(unix)]
        let dir = tempfile::Builder::new()
            .tempdir_in("/tmp")
            .expect("tempdir_in /tmp");
        #[cfg(not(unix))]
        let dir = tempfile::tempdir().expect("tempdir");
        #[cfg(unix)]
        std::fs::set_permissions(
            dir.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("chmod gnupghome");
        Some(Self { dir })
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
        let _ = Command::new("gpgconf")
            .env("GNUPGHOME", self.path())
            .args(["--kill", "gpg-agent"])
            .status();
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
