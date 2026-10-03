//! Pure helpers for `import-git-crypt` (plan 7.5, ADR-0018).

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::Error;

/// The git-crypt key a `filter` attribute value names: `git-crypt` is key `default`, and
/// `git-crypt-<key>` is `<key>`.
pub(crate) fn filter_key(value: &str) -> Option<&str> {
    match value.strip_prefix("git-crypt") {
        Some("") => Some("default"),
        Some(rest) => rest.strip_prefix('-').filter(|key| !key.is_empty()),
        None => None,
    }
}

/// The key holders of git-crypt key `key`: the uppercase fingerprints in the names of
/// `<keys_dir>/<key>/0/*.gpg`, and the entries that are not named `<40 hex digits>.gpg`.
pub(crate) fn holders(
    keys_dir: &Path,
    key: &str,
) -> Result<(BTreeSet<String>, Vec<String>), Error> {
    let dir = keys_dir.join(key).join("0");
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Default::default()),
        Err(source) => {
            return Err(Error::IoPath {
                path: dir.display().to_string(),
                source,
            });
        }
    };
    let (mut fprs, mut skipped) = (BTreeSet::new(), Vec::new());
    for entry in entries {
        let name = entry?.file_name().to_string_lossy().into_owned();
        match name.strip_suffix(".gpg") {
            Some(fpr) if fpr.len() == 40 && fpr.chars().all(|c| c.is_ascii_hexdigit()) => {
                fprs.insert(fpr.to_ascii_uppercase());
            }
            _ => skipped.push(name),
        }
    }
    skipped.sort();
    Ok((fprs, skipped))
}

/// A member name for a key holder (plan 7.5, decision 23): the part before `@` of the address in
/// the last `<…>` of `user_id` (or of `user_id` itself), normalised to the name rule; `gpg-<last 16
/// hex digits>` when nothing usable is left; `-2`, `-3`… appended while the name is in `taken`.
pub(crate) fn derive_name(user_id: &str, fpr: &str, taken: &BTreeSet<String>) -> String {
    let address = match (user_id.rfind('<'), user_id.rfind('>')) {
        (Some(open), Some(close)) if open < close => &user_id[open + 1..close],
        _ => user_id,
    };
    let local = address.split_once('@').map_or("", |(local, _)| local);
    let normalised: String = local
        .to_lowercase()
        .chars()
        .map(|c| match c {
            'a'..='z' | '0'..='9' | '.' | '_' | '-' => c,
            _ => '-',
        })
        .skip_while(|c| !c.is_ascii_alphanumeric())
        .take(64)
        .collect();
    let base = match normalised.is_empty() {
        true => format!(
            "gpg-{}",
            fpr[fpr.len().saturating_sub(16)..].to_ascii_lowercase()
        ),
        false => normalised,
    };
    let mut name = base.clone();
    for n in 2.. {
        if !taken.contains(&name) {
            break;
        }
        let suffix = format!("-{n}");
        name = format!("{}{suffix}", &base[..base.len().min(64 - suffix.len())]);
    }
    name
}

/// `contents` of a `.gitattributes` file without its git-crypt `filter` and `diff` tokens. A line
/// left with only its pattern is deleted; every other byte is kept.
pub(crate) fn strip_git_crypt(contents: &str) -> String {
    contents
        .split_inclusive('\n')
        .filter_map(strip_line)
        .collect()
}

fn is_git_crypt_token(token: &str) -> bool {
    ["filter", "diff"].iter().any(|attr| {
        token
            .strip_prefix(attr)
            .and_then(|t| t.strip_prefix("=git-crypt"))
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('-'))
    })
}

// `None` deletes the line.
fn strip_line(line: &str) -> Option<String> {
    let body = line.trim_end_matches(['\r', '\n']);
    let eol = &line[body.len()..];
    let trimmed = body.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Some(line.to_string());
    }
    let indent = &body[..body.len() - trimmed.len()];
    let (pattern, rest) = split_pattern(trimmed);
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    let kept: Vec<&str> = tokens
        .iter()
        .copied()
        .filter(|t| !is_git_crypt_token(t))
        .collect();
    match (kept.len() == tokens.len(), kept.is_empty()) {
        (true, _) => Some(line.to_string()),
        (false, true) => None,
        (false, false) => Some(format!("{indent}{pattern} {}{eol}", kept.join(" "))),
    }
}

// The pattern is one token even when quoted (`"a b" -text`).
fn split_pattern(line: &str) -> (&str, &str) {
    let end = if line.starts_with('"') {
        let mut escaped = false;
        let close = line.char_indices().skip(1).find(|&(_, c)| {
            let closes = c == '"' && !escaped;
            escaped = c == '\\' && !escaped;
            closes
        });
        close.map_or(line.len(), |(i, _)| i + 1)
    } else {
        line.find(char::is_whitespace).unwrap_or(line.len())
    };
    line.split_at(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn taken(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    const FPR: &str = "0123456789ABCDEF0123456789ABCDEF01234567";

    #[test]
    fn filter_values_map_to_keys() {
        assert_eq!(filter_key("git-crypt"), Some("default"));
        assert_eq!(filter_key("git-crypt-Prod"), Some("Prod"));
        assert_eq!(filter_key("other"), None);
        assert_eq!(filter_key("unspecified"), None);
        assert_eq!(filter_key("git-crypt-"), None);
        assert_eq!(filter_key("git-cryptx"), None);
    }

    #[test]
    fn holders_skip_non_hex_names_and_directories_other_than_0() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("default");
        let lower = FPR.to_ascii_lowercase();
        for (sub, name) in [
            ("0", format!("{lower}.gpg")),
            ("0", "notes.txt".to_string()),
            ("0", "ABCD.gpg".to_string()),
            ("1", format!("{FPR}.gpg")),
        ] {
            fs::create_dir_all(key.join(sub)).unwrap();
            fs::write(key.join(sub).join(name), "").unwrap();
        }

        let (fprs, skipped) = holders(dir.path(), "default").unwrap();
        assert_eq!(fprs.into_iter().collect::<Vec<_>>(), [FPR]);
        assert_eq!(skipped, ["ABCD.gpg", "notes.txt"]);
        assert!(holders(dir.path(), "missing").unwrap().0.is_empty());
    }

    #[test]
    fn derive_name_uses_the_local_part_of_the_email() {
        let none = taken(&[]);
        assert_eq!(
            derive_name("Dave Smith <Dave.Smith@example.org>", FPR, &none),
            "dave.smith"
        );
        assert_eq!(derive_name("dave@example.org", FPR, &none), "dave");
    }

    #[test]
    fn derive_name_falls_back_to_the_fingerprint_without_an_email() {
        assert_eq!(
            derive_name("Dave Smith", FPR, &taken(&[])),
            "gpg-89abcdef01234567"
        );
        assert_eq!(derive_name("", FPR, &taken(&[])), "gpg-89abcdef01234567");
    }

    #[test]
    fn derive_name_normalises_case_non_ascii_and_a_leading_dot() {
        assert_eq!(derive_name("<ÉRIC@x.org>", FPR, &taken(&[])), "ric");
        assert_eq!(derive_name("<.dot@x.org>", FPR, &taken(&[])), "dot");
        assert_eq!(derive_name("<A B@x.org>", FPR, &taken(&[])), "a-b");
        assert_eq!(
            derive_name("<é@x.org>", FPR, &taken(&[])),
            "gpg-89abcdef01234567"
        );
    }

    #[test]
    fn derive_name_appends_a_counter_on_collisions_and_stays_within_64() {
        assert_eq!(derive_name("<dave@x>", FPR, &taken(&["dave"])), "dave-2");
        let both = taken(&["dave", "dave-2"]);
        assert_eq!(derive_name("<dave@x>", FPR, &both), "dave-3");

        let long = format!("<{}@x>", "a".repeat(70));
        let first = derive_name(&long, FPR, &taken(&[]));
        assert_eq!(first, "a".repeat(64));
        let second = derive_name(&long, FPR, &taken(&[&first]));
        assert_eq!(second, format!("{}-2", "a".repeat(62)));
    }

    #[test]
    fn a_line_with_only_git_crypt_attributes_is_deleted() {
        let input = "secret.env filter=git-crypt diff=git-crypt\nprod/** filter=git-crypt-Prod diff=git-crypt-Prod\nkeep.txt text\n";
        assert_eq!(strip_git_crypt(input), "keep.txt text\n");
        assert_eq!(strip_git_crypt("x filter=git-crypt"), "");
    }

    #[test]
    fn other_attributes_on_the_line_stay() {
        assert_eq!(
            strip_git_crypt("*.key filter=git-crypt diff=git-crypt -text\n"),
            "*.key -text\n"
        );
        assert_eq!(
            strip_git_crypt("a filter=git-crypt -text\r\n"),
            "a -text\r\n"
        );
    }

    #[test]
    fn comments_unrelated_lines_and_crlf_are_kept_byte_for_byte() {
        let input = "# filter=git-crypt stays\r\n\r\n*.txt text eol=lf filter=git-cryptic\r\n";
        assert_eq!(strip_git_crypt(input), input);
    }

    #[test]
    fn a_quoted_pattern_is_one_token() {
        assert_eq!(
            strip_git_crypt("\"a b\" filter=git-crypt -text\n"),
            "\"a b\" -text\n"
        );
        assert_eq!(strip_git_crypt("\"a b\" filter=git-crypt\n"), "");
    }
}
