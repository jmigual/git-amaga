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
