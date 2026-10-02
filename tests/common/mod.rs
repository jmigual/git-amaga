//! Shared integration-test helpers: an isolated Git repository for running the built binary
//! (plan 11).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A throwaway repository with its own `GIT_CONFIG_GLOBAL` and `HOME`/`USERPROFILE`, so child
/// processes never touch the developer's real config or home. The isolation is set on children
/// only, never via `set_var`.
pub struct Repo {
    dir: tempfile::TempDir,
    global_config: PathBuf,
    home: tempfile::TempDir,
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
        // A hook or `rebase -x` exports GIT_DIR, GIT_INDEX_FILE, ...; children must not inherit
        // them.
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("GIT_") {
                command.env_remove(key);
            }
        }
        command
            .current_dir(cwd)
            .env("GIT_CONFIG_GLOBAL", global_config)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", home)
            .env("USERPROFILE", home);
    }

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

    pub fn run(&self, args: &[&str]) -> Output {
        self.run_in(self.path(), args)
    }

    /// Like [`Repo::run`], but inside `cwd`.
    pub fn run_in(&self, cwd: &Path, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_git-amaga"));
        command.args(args);
        Self::isolate(&mut command, cwd, &self.global_config, self.home.path());
        command.output().expect("spawn git-amaga")
    }

    /// Like [`Repo::run`], with `extra_env` applied after the isolation.
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

    pub fn git_in(&self, cwd: &Path, args: &[&str]) -> Output {
        let mut command = Command::new("git");
        command.args(args);
        Self::isolate(&mut command, cwd, &self.global_config, self.home.path());
        command.output().expect("spawn git")
    }
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
