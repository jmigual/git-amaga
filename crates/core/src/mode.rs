//! The Unix mode `open` gives a plaintext (ADR-0019).

use std::path::Path;

use crate::{Error, git};

/// The mode of a plaintext that neither the attribute nor an existing file sets.
const DEFAULT: u32 = 0o600;

const ATTRIBUTE: &str = "amaga-mode";

/// The `amaga-mode` attribute of each of `plaintexts`, in order; `None` where it is unspecified.
/// A value that [`parse`] refuses is [`Error::ModeAttributeInvalid`].
pub(crate) fn attributes(root: &Path, plaintexts: &[&str]) -> Result<Vec<Option<u32>>, Error> {
    if plaintexts.is_empty() {
        return Ok(Vec::new());
    }
    git::check_attr(root, &[ATTRIBUTE], plaintexts)?
        .into_iter()
        .zip(plaintexts)
        .map(|((_, _, value), plaintext)| match value.as_str() {
            "unspecified" => Ok(None),
            v => parse(v)
                .map(Some)
                .ok_or_else(|| Error::ModeAttributeInvalid(plaintext.to_string())),
        })
        .collect()
}

// Three or four octal digits with owner read-write and at most read for group and others:
// `0600`, `0640`, `0604` or `0644`. Execute bits, write for others and an owner who cannot
// read or write the file are refused.
fn parse(value: &str) -> Option<u32> {
    let digits = value
        .strip_prefix('0')
        .filter(|d| d.len() == 3)
        .unwrap_or(value);
    if digits.len() != 3 || !digits.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return None;
    }
    let mode = u32::from_str_radix(digits, 8).ok()?;
    (mode & 0o600 == 0o600 && mode & !0o644 == 0).then_some(mode)
}

/// The permission bits of the plaintext at `path`, clamped by [`clamp`], or `None` when there is
/// none to keep.
#[cfg(unix)]
pub(crate) fn existing(root: &Path, path: &str) -> Result<Option<u32>, Error> {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(root.join(path)) {
        Ok(meta) => Ok(Some(clamp(meta.permissions().mode()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(Error::IoPath {
            path: path.to_string(),
            source,
        }),
    }
}

/// Drops execute, group and other write and the special bits, and forces owner read-write, so a
/// kept mode is always one `amaga-mode` could have set.
#[cfg(unix)]
fn clamp(mode: u32) -> u32 {
    mode & 0o644 | 0o600
}

#[cfg(not(unix))]
pub(crate) fn existing(_root: &Path, _path: &str) -> Result<Option<u32>, Error> {
    Ok(None)
}

pub(crate) fn choose(attribute: Option<u32>, existing: Option<u32>) -> u32 {
    attribute.or(existing).unwrap_or(DEFAULT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_owner_read_write_and_read_for_the_rest() {
        for (value, mode) in [
            ("0600", 0o600),
            ("600", 0o600),
            ("0640", 0o640),
            ("0604", 0o604),
            ("0644", 0o644),
            ("644", 0o644),
        ] {
            assert_eq!(parse(value), Some(mode), "{value}");
        }
    }

    #[test]
    fn parse_refuses_execute_write_for_others_and_malformed_values() {
        for value in [
            "0700", "0755", "0666", "0660", "0620", "0400", "0200", "0000", "4644", "1644",
            "00644", "0o644", "64", "0", "", "set", "unset", "06a4", "0648", " 644",
        ] {
            assert_eq!(parse(value), None, "{value:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn clamp_keeps_only_the_allowed_bits() {
        for (mode, clamped) in [
            (0o666, 0o644),
            (0o775, 0o644),
            (0o640, 0o640),
            (0o400, 0o600),
            (0o100755, 0o644),
            (0o4755, 0o644),
            (0o604, 0o604),
        ] {
            assert_eq!(clamp(mode), clamped, "{mode:o}");
        }
    }

    #[test]
    fn choose_prefers_attribute_then_existing_then_default() {
        assert_eq!(choose(Some(0o644), Some(0o640)), 0o644);
        assert_eq!(choose(None, Some(0o640)), 0o640);
        assert_eq!(choose(None, None), DEFAULT);
        assert_eq!(choose(Some(0o640), None), 0o640);
    }
}
