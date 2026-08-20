//! Minimal RFC 3339 helpers used for registration expiry semantics.
//!
//! The control plane compares client-supplied expiry timestamps against the
//! current time. Only UTC timestamps in the `YYYY-MM-DDTHH:MM:SS[.frac]Z`
//! (or numeric UTC offset) form are accepted.

use std::time::{SystemTime, UNIX_EPOCH};

/// Return the current time as an RFC 3339 UTC string.
pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    format_unix(secs)
}

/// Parse an RFC 3339 timestamp into Unix seconds.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, rest) = s.split_once('T')?;
    let (time, tz) = split_timezone(rest)?;
    let (y, m, d) = parse_date(date)?;
    let (hh, mm, ss) = parse_time(time)?;
    let days = days_from_civil(y, m, d)?;
    let mut unix = days * 86_400 + hh * 3_600 + mm * 60 + ss;
    match tz {
        "Z" => {}
        tz => {
            let (sign, hh, mm) = parse_offset(tz)?;
            let offset = hh * 3_600 + mm * 60;
            unix -= if sign == '+' { offset } else { -offset };
        }
    }
    Some(unix)
}

/// True if `ts` is strictly before `now`.
pub fn is_past(ts: &str, now: &str) -> bool {
    match (parse_rfc3339(ts), parse_rfc3339(now)) {
        (Some(a), Some(b)) => a < b,
        _ => false,
    }
}

/// True if `ts` is strictly after `now`.
pub fn is_future(ts: &str, now: &str) -> bool {
    match (parse_rfc3339(ts), parse_rfc3339(now)) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}

fn split_timezone(rest: &str) -> Option<(&str, &str)> {
    if let Some(tz) = rest.strip_suffix('Z') {
        return Some((tz, "Z"));
    }
    // Look for a numeric offset like +08:00 or -0530 at the end.
    let bytes = rest.as_bytes();
    let mut split = None;
    for (i, &b) in bytes.iter().enumerate() {
        if (b == b'+' || b == b'-') && i > 0 && bytes[i - 1].is_ascii_digit() {
            split = Some(i);
            break;
        }
    }
    let i = split?;
    Some((&rest[..i], &rest[i..]))
}

fn parse_date(s: &str) -> Option<(i64, u32, u32)> {
    let y: i64 = s.get(0..4)?.parse().ok()?;
    let m: u32 = s.get(5..7)?.parse().ok()?;
    let d: u32 = s.get(8..10)?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some((y, m, d))
}

fn parse_time(s: &str) -> Option<(i64, i64, i64)> {
    let hh: i64 = s.get(0..2)?.parse().ok()?;
    let mm: i64 = s.get(3..5)?.parse().ok()?;
    let ss: i64 = s.get(6..8)?.parse().ok()?;
    if hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    Some((hh, mm, ss))
}

fn parse_offset(s: &str) -> Option<(char, i64, i64)> {
    let sign = s.chars().next()?;
    let digits = &s[1..];
    let (hh, mm) = if digits.len() == 5 {
        (digits[0..2].parse().ok()?, digits[3..5].parse().ok()?)
    } else if digits.len() == 4 {
        (digits[0..2].parse().ok()?, digits[2..4].parse().ok()?)
    } else {
        return None;
    };
    if hh > 23 || mm > 59 {
        return None;
    }
    Some((sign, hh, mm))
}

/// Convert Unix seconds to an RFC 3339 UTC string.
fn format_unix(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let hh = rem / 3_600;
    let mm = (rem % 3_600) / 60;
    let ss = rem % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Days since 1970-01-01 to civil date (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Days from civil date to 1970-01-01 (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> Option<i64> {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_utc() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2026-08-20T00:00:00Z"), Some(1787184000));
    }

    #[test]
    fn parses_offset() {
        assert_eq!(parse_rfc3339("1970-01-01T01:00:00+01:00"), Some(0));
        assert_eq!(parse_rfc3339("1969-12-31T23:00:00-01:00"), Some(0));
    }

    #[test]
    fn past_and_future() {
        let now = "2026-08-20T00:00:00Z";
        assert!(is_past("2026-08-19T00:00:00Z", now));
        assert!(!is_past("2026-08-21T00:00:00Z", now));
        assert!(is_future("2026-08-21T00:00:00Z", now));
        assert!(!is_future("2026-08-19T00:00:00Z", now));
    }

    #[test]
    fn formats_now() {
        let s = now_rfc3339();
        assert!(s.ends_with('Z'));
        assert_eq!(s.len(), 20);
    }
}
