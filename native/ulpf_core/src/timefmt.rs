//! Timestamp parsing with `ulpf.engine.normalizer._parse_ts` semantics.
//!
//! Only shapes whose Python result is certain on every supported Python
//! (3.10 through 3.13) are parsed here; for anything else these functions
//! return `None` and the caller hands the line to the Python pipeline. They
//! never guess.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

pub fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

pub fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// `datetime(..., tzinfo=UTC).isoformat()`
pub fn iso_utc(epoch_s: i64, micro: i64) -> String {
    let days = epoch_s.div_euclid(86400);
    let secs = epoch_s.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let (h, mi, s) = (secs / 3600, secs % 3600 / 60, secs % 60);
    if micro != 0 {
        format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{micro:06}+00:00")
    } else {
        format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}+00:00")
    }
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn num(s: &str) -> Option<i64> {
    if all_digits(s) {
        s.parse().ok()
    } else {
        None
    }
}

/// `^\d{10}(?:\d{3})?(?:\.\d+)?$` -> `datetime.fromtimestamp(float(s) [/1000], UTC).isoformat()`
fn parse_epoch(ts: &str) -> Option<String> {
    let (int_part, frac) = match ts.split_once('.') {
        Some((a, b)) => (a, Some(b)),
        None => (ts, None),
    };
    if !(int_part.len() == 10 || int_part.len() == 13) || !all_digits(int_part) {
        return None;
    }
    if let Some(f) = frac {
        if !all_digits(f) {
            return None;
        }
    }
    let mut val: f64 = ts.parse().ok()?;
    if val > 1e11 {
        val /= 1000.0;
    }
    // CPython _PyTime_ObjectToTimeval with ROUND_HALF_EVEN
    let intpart = val.trunc();
    let mut floatpart = (val - intpart) * 1e6;
    floatpart = floatpart.round_ties_even();
    let mut secs = intpart;
    if floatpart >= 1e6 {
        floatpart -= 1e6;
        secs += 1.0;
    }
    let secs = secs as i64;
    let (y, _, _) = civil_from_days(secs.div_euclid(86400));
    if !(1..=9999).contains(&y) {
        return None;
    }
    Some(iso_utc(secs, floatpart as i64))
}

/// Strict ISO 8601 subset that `datetime.fromisoformat` accepts identically on
/// Python 3.10+: YYYY-MM-DD[T ]HH:MM:SS[.fff|.ffffff][Z|z|±HH:MM].
fn parse_iso(ts: &str) -> Option<String> {
    let b = ts.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let (y, mo, d) = (num(&ts[0..4])?, num(&ts[5..7])?, num(&ts[8..10])?);
    if !(2..=9998).contains(&y) || !(1..=12).contains(&mo) || d < 1 || d > days_in_month(y, mo) {
        return None;
    }
    if b[10] != b'T' && b[10] != b' ' {
        return None;
    }
    let rest = &ts[11..];
    let rb = rest.as_bytes();
    if rb.len() < 8 || rb[2] != b':' || rb[5] != b':' {
        return None;
    }
    let (h, mi, s) = (num(&rest[0..2])?, num(&rest[3..5])?, num(&rest[6..8])?);
    if h > 23 || mi > 59 || s > 59 {
        return None;
    }
    let mut rest = &rest[8..];
    let mut micro = 0i64;
    if let Some(r) = rest.strip_prefix('.') {
        let n = r.bytes().take_while(|c| c.is_ascii_digit()).count();
        micro = match n {
            3 => num(&r[..3])? * 1000,
            6 => num(&r[..6])?,
            _ => return None,
        };
        rest = &r[n..];
    }
    let off = match rest {
        "" => 0,
        "Z" | "z" => 0,
        _ => {
            let ob = rest.as_bytes();
            if ob.len() != 6 || (ob[0] != b'+' && ob[0] != b'-') || ob[3] != b':' {
                return None;
            }
            let (oh, om) = (num(&rest[1..3])?, num(&rest[4..6])?);
            if oh > 23 || om > 59 {
                return None;
            }
            (oh * 60 + om) * if ob[0] == b'-' { -1 } else { 1 }
        }
    };
    let epoch = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s - off * 60;
    let (yy, _, _) = civil_from_days(epoch.div_euclid(86400));
    if !(2..=9998).contains(&yy) {
        return None;
    }
    Some(iso_utc(epoch, micro))
}

pub const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

fn month(s: &str) -> Option<i64> {
    MONTHS.iter().position(|m| *m == s).map(|p| p as i64 + 1)
}

fn now_parts() -> (i64, i64) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (now.as_secs() as i64, now.subsec_micros() as i64)
}

/// `_infer_syslog_year`: the most recent past occurrence (one day of future allowed).
fn infer_year(mon: i64, d: i64, h: i64, mi: i64, s: i64) -> Option<i64> {
    let (now_s, now_us) = now_parts();
    let (ny, _, _) = civil_from_days(now_s.div_euclid(86400));
    if d < 1 || d > days_in_month(ny, mon) || (mon == 2 && d == 29) {
        return None; // the year rollback could land on a non-leap year: Python decides
    }
    let mut epoch = days_from_civil(ny, mon, d) * 86400 + h * 3600 + mi * 60 + s;
    if (epoch - now_s) * 1_000_000 - now_us > 86_400 * 1_000_000 {
        epoch = days_from_civil(ny - 1, mon, d) * 86400 + h * 3600 + mi * 60 + s;
    }
    Some(epoch)
}

fn two(s: &str) -> Option<i64> {
    // Python int() of a two-character slice: a leading space is allowed ("Oct  1")
    num(s.trim_start_matches(' '))
}

/// RFC 3164 "Oct 11 22:14:15" (exactly 15 characters).
fn parse_rfc3164(ts: &str) -> Option<String> {
    let mon = month(&ts[0..3])?;
    let (d, h, mi, s) = (two(&ts[4..6])?, two(&ts[7..9])?, two(&ts[10..12])?, two(&ts[13..15])?);
    if h > 23 || mi > 59 || s > 59 {
        return None;
    }
    Some(iso_utc(infer_year(mon, d, h, mi, s)?, 0))
}

/// strptime "%b %d %Y %H:%M:%S" and "%b %d %Y %H:%M:%S.%f" (CEF/LEEF `rt` / `devTime`),
/// canonical month names and single spaces only.
fn parse_b_d_y(ts: &str) -> Option<String> {
    let parts: Vec<&str> = ts.split(' ').collect();
    if parts.len() != 4 {
        return None;
    }
    let mon = month(parts[0])?;
    let d = if (1..=2).contains(&parts[1].len()) { num(parts[1])? } else { return None };
    if parts[2].len() != 4 {
        return None;
    }
    let y = num(parts[2])?;
    let (clock, frac) = match parts[3].split_once('.') {
        Some((c, f)) => (c, Some(f)),
        None => (parts[3], None),
    };
    let hms: Vec<&str> = clock.split(':').collect();
    if hms.len() != 3 || hms.iter().any(|p| p.len() != 2) {
        return None;
    }
    let (h, mi, s) = (num(hms[0])?, num(hms[1])?, num(hms[2])?);
    // year 1900 means "no year" to _parse_ts (it infers one): Python decides
    if !(2..=9998).contains(&y) || y == 1900 || d < 1 || d > days_in_month(y, mon) || h > 23 || mi > 59 || s > 59 {
        return None;
    }
    let micro = match frac {
        None => 0,
        Some(f) if (1..=6).contains(&f.len()) => num(f)? * 10i64.pow(6 - f.len() as u32),
        Some(_) => return None,
    };
    Some(iso_utc(days_from_civil(y, mon, d) * 86400 + h * 3600 + mi * 60 + s, micro))
}

/// `_parse_ts` subset. `None` = the Python implementation must decide.
pub fn parse_ts(ts: &str) -> Option<String> {
    if !ts.is_ascii() {
        return None;
    }
    let b = ts.as_bytes();
    if b.first().map(|c| c.is_ascii_digit()).unwrap_or(false) && b.iter().all(|c| c.is_ascii_digit() || *c == b'.') {
        // epoch forms first (as in Python); other all-digit shapes go on to strptime: delegate
        return parse_epoch(ts);
    }
    if b.len() >= 10 && b[4] == b'-' && b[7] == b'-' {
        return parse_iso(ts);
    }
    if b.len() == 15 && b[3] == b' ' && b[9] == b':' && b[12] == b':' {
        return parse_rfc3164(ts);
    }
    if b.len() >= 20 && b[3] == b' ' {
        // "%b %d %Y ..." is tried after five other strptime formats; none of them accepts a
        // string that starts with a month name followed by a space
        return parse_b_d_y(ts);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes() {
        assert_eq!(parse_ts("1760000000").unwrap(), "2025-10-09T08:53:20+00:00");
        assert_eq!(parse_ts("1760000000.5").unwrap(), "2025-10-09T08:53:20.500000+00:00");
        assert_eq!(parse_ts("1760000000123").unwrap(), "2025-10-09T08:53:20.123000+00:00");
        assert_eq!(parse_ts("2026-10-21T10:00:00.123Z").unwrap(), "2026-10-21T10:00:00.123000+00:00");
        assert_eq!(parse_ts("2026-10-21 23:59:59-08:00").unwrap(), "2026-10-22T07:59:59+00:00");
        assert!(parse_ts("2026-10-21T10:00:00.1Z").is_none());
        assert_eq!(parse_ts("Oct 21 2026 10:00:00").unwrap(), "2026-10-21T10:00:00+00:00");
        assert_eq!(parse_ts("Oct 21 2026 10:00:00.25").unwrap(), "2026-10-21T10:00:00.250000+00:00");
        assert!(parse_ts("20261021100000").is_none());
    }
}
