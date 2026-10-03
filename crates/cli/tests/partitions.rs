//! Integration tests for partitions (ADR-0017, plan 5.7, tests 52-64).

mod common;

use common::{OutputExt, repo_with_alice};

/// Test 52: the label is readable in the header, and changing it breaks authentication.
#[test]
fn secret_label_is_readable_and_authenticated() {
    let (repo, _identity_path) = repo_with_alice();
    std::fs::write(repo.path().join("a.env"), b"v1").unwrap();
    repo.run(&["add", "a.env"]).assert_success();
    std::fs::remove_file(repo.path().join("a.env")).unwrap();

    let path = repo.path().join("a.env.amaga");
    let mut bytes = std::fs::read(&path).unwrap();
    let label = b"-> amaga-partition default\n";
    let at = bytes.windows(label.len()).position(|w| w == label).unwrap();

    // The last name byte, before the newline.
    bytes[at + label.len() - 2] = b'x';
    std::fs::write(&path, &bytes).unwrap();
    repo.run(&["open", "a.env"]).assert_failure();
    assert!(!repo.path().join("a.env").exists());
}
