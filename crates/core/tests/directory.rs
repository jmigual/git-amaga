//! Commands act on the directory they are given, never on the process's current directory.
//!
//! Read-only on purpose: these tests share the real environment (HOME, git config), so a
//! command that writes belongs in the CLI tests, which isolate both.

use git_amaga_core::{Error, cmd_status};

#[test]
fn status_looks_at_the_given_directory_not_the_process_cwd() {
    // git honours GIT_DIR over the directory it is given, so the test cannot isolate itself.
    if std::env::var_os("GIT_DIR").is_some_and(|dir| dir != "/nonexistent") {
        println!(
            "skipping status_looks_at_the_given_directory_not_the_process_cwd: GIT_DIR is set"
        );
        return;
    }
    // The test process runs inside this repository; the temp directory is outside any.
    let outside = tempfile::tempdir().expect("tempdir");

    let result = cmd_status(outside.path());

    assert!(matches!(result, Err(Error::NotAGitRepo)));
}
