//! Appends events to `.amaga/audit.jsonl` (plan 5.3): plain, append-only JSONL, written by the
//! tool and never parsed by it.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::error::Error;

#[derive(Serialize)]
struct Event<'a> {
    time: String,
    actor: &'a str,
    event: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gpg_fpr: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gpg_uid: Option<&'a str>,
}

/// Appends one JSONL event (plan 5.3); `secret_path` is the repo-relative plaintext path, `None`
/// for `init`. `gpg` is the member's (primary fingerprint, first user ID), if it has an `.asc`.
pub fn append(
    path: &Path,
    actor: &str,
    event: &str,
    secret_path: Option<&str>,
    gpg: Option<(&str, &str)>,
) -> Result<(), Error> {
    let line = serde_json::to_string(&Event {
        time: format_rfc3339(SystemTime::now()),
        actor,
        event,
        path: secret_path,
        gpg_fpr: gpg.map(|(fpr, _)| fpr),
        gpg_uid: gpg.map(|(_, uid)| uid),
    })
    // Serializing a struct of plain strings cannot fail: no maps, no non-UTF8 keys.
    .expect("audit event serialization is infallible");

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{line}")?;
    Ok(())
}

// RFC 3339 UTC (plan 5.3), e.g. `2026-10-02T12:34:56Z`.
fn format_rfc3339(time: SystemTime) -> String {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (secs / 86400) as i64;
    let secs_of_day = secs % 86400;
    let (year, month, day) = civil_from_days(days);
    let (h, m, s) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

// Hinnant's `civil_from_days` (howardhinnant.github.io/date_algorithms.html); avoids a date
// dependency.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn format_rfc3339_at_the_epoch() {
        assert_eq!(format_rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn format_rfc3339_at_a_known_timestamp() {
        // 2023-11-14T22:13:20Z, per `date -u -d @1700000000`.
        let time = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(format_rfc3339(time), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn format_rfc3339_on_a_leap_day() {
        // 2000 is a leap year (divisible by 400): 2000-02-29T12:00:00Z.
        let time = UNIX_EPOCH + Duration::from_secs(951_825_600);
        assert_eq!(format_rfc3339(time), "2000-02-29T12:00:00Z");
    }

    #[test]
    fn format_rfc3339_across_a_non_leap_century_boundary() {
        // 2100 is divisible by 100 but not 400, so not a leap year: the day after
        // 2100-02-28 is 2100-03-01T00:00:00Z, not 2100-02-29.
        let time = UNIX_EPOCH + Duration::from_secs(4_107_542_400);
        assert_eq!(format_rfc3339(time), "2100-03-01T00:00:00Z");
    }

    #[test]
    fn append_writes_one_json_line_with_actor_and_event() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        append(&path, "alice", "init", None, None).unwrap();
        append(&path, "alice", "rotated", Some("secrets/prod.env"), None).unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"actor\":\"alice\""));
        assert!(lines[0].contains("\"event\":\"init\""));
        assert!(!lines[0].contains("\"path\""));
        assert!(lines[1].contains("\"event\":\"rotated\""));
        assert!(lines[1].contains("\"path\":\"secrets/prod.env\""));
    }

    #[test]
    fn append_records_gpg_fingerprint_and_user_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        append(&path, "alice", "init", None, Some(("ABCD", "Alice <a@x>"))).unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"gpg_fpr\":\"ABCD\""));
        assert!(contents.contains("\"gpg_uid\":\"Alice <a@x>\""));
    }
}
