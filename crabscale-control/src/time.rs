//! RFC 3339 helpers used for registration expiry semantics.
//!
//! The control plane compares client-supplied expiry timestamps against the
//! current time. Only UTC timestamps in the `YYYY-MM-DDTHH:MM:SSZ` (or
//! numeric UTC offset) form are accepted. Fractional seconds are explicitly
//! rejected because the public API returns whole Unix seconds and silently
//! truncating them would hide malformed input.

use chrono::{DateTime, Duration, SecondsFormat, Utc};

/// Return the current time as an RFC 3339 UTC string.
pub fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Return the current time as Unix seconds.
pub fn now_unix() -> i64 {
    Utc::now().timestamp()
}

/// Return the current time plus `secs` seconds as an RFC 3339 UTC string.
pub fn now_plus_seconds(secs: i64) -> String {
    (Utc::now() + Duration::seconds(secs)).to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Parse an RFC 3339 timestamp into Unix seconds.
///
/// Fractional seconds are rejected: the API returns whole Unix seconds and
/// silently truncating would hide malformed input.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.contains('.') {
        return None;
    }
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.timestamp())
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
    fn rejects_invalid_dates() {
        assert_eq!(parse_rfc3339("2026-02-30T00:00:00Z"), None);
        assert_eq!(parse_rfc3339("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_rfc3339("2026-00-01T00:00:00Z"), None);
    }

    #[test]
    fn rejects_fractional_seconds() {
        assert_eq!(parse_rfc3339("2026-08-20T00:00:00.123Z"), None);
        assert_eq!(parse_rfc3339("2026-08-20T00:00:00,123Z"), None);
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
