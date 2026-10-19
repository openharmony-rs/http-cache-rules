//! HTTP-date parsing and formatting (RFC 9110 §5.6.7), with the relaxations
//! RFC 9111 §4.2 grants cache recipients.
//!
//! Times are whole seconds since the Unix epoch. Dates before the epoch are
//! clamped to 0, which every caller treats as "long ago".

/// The latest time [`format_http_date`] can represent: 9999-12-31T23:59:59Z.
pub const MAX_FORMATTABLE: u64 = 253_402_300_799;

const DAY_NAMES: [&[u8]; 7] = [b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat", b"Sun"];
const LONG_DAY_NAMES: [&[u8]; 7] = [
    b"Monday",
    b"Tuesday",
    b"Wednesday",
    b"Thursday",
    b"Friday",
    b"Saturday",
    b"Sunday",
];
const MONTHS: [&[u8]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

/// Parses an HTTP-date in any of its three formats.
///
/// RFC 9110 §5.6.7 requires recipients to accept IMF-fixdate, the obsolete
/// RFC 850 format and asctime. Following RFC 9111 §4.2, names are matched
/// case-insensitively and a zone other than `GMT` makes the date invalid. The
/// day name is checked to be a day name but not checked against the date, as
/// browsers do.
///
/// `now` resolves the two-digit years of the RFC 850 format: the year with
/// those last two digits that lies within 50 years of `now` is chosen, so a date
/// never appears to be more than 50 years in the future.
///
/// A leap second (`:60`) is read as `:59`, the nearest earlier representable
/// time, as RFC 9111 §4.2 requires for `Expires`.
pub fn parse_http_date(value: &[u8], now: u64) -> Option<u64> {
    let value = trim(value);
    if value.len() == 29 && value[3] == b',' {
        parse_imf_fixdate(value)
    } else if value.len() == 24 && value[3] == b' ' {
        parse_asctime(value)
    } else {
        parse_rfc850(value, now)
    }
}

/// Formats `time` as an IMF-fixdate, the only format a sender may generate.
/// Times after [`MAX_FORMATTABLE`] are formatted as that time.
pub fn format_http_date(time: u64) -> String {
    let time = time.min(MAX_FORMATTABLE);
    let days = time / 86_400;
    let seconds_of_day = time % 86_400;
    let (year, month, day) = civil_from_days(days);
    // 1970-01-01 was a Thursday, index 3 in `DAY_NAMES`.
    let day_name = DAY_NAMES[((days + 3) % 7) as usize];
    let mut out = String::with_capacity(29);
    out.push_str(std::str::from_utf8(day_name).unwrap_or("Mon"));
    out.push_str(", ");
    push_two_digits(&mut out, day);
    out.push(' ');
    out.push_str(std::str::from_utf8(MONTHS[(month - 1) as usize]).unwrap_or("Jan"));
    out.push(' ');
    push_two_digits(&mut out, (year / 100) as u32);
    push_two_digits(&mut out, year as u32);
    out.push(' ');
    push_two_digits(&mut out, (seconds_of_day / 3600) as u32);
    out.push(':');
    push_two_digits(&mut out, (seconds_of_day / 60 % 60) as u32);
    out.push(':');
    push_two_digits(&mut out, (seconds_of_day % 60) as u32);
    out.push_str(" GMT");
    out
}

/// Appends the last two decimal digits of `value`.
fn push_two_digits(out: &mut String, value: u32) {
    out.push(char::from(b'0' + (value / 10 % 10) as u8));
    out.push(char::from(b'0' + (value % 10) as u8));
}

/// `Sun, 06 Nov 1994 08:49:37 GMT`
fn parse_imf_fixdate(s: &[u8]) -> Option<u64> {
    if !is_one_of(&s[0..3], &DAY_NAMES)
        || s[4] != b' '
        || s[7] != b' '
        || s[11] != b' '
        || s[16] != b' '
        || s[25] != b' '
        || !s[26..29].eq_ignore_ascii_case(b"GMT")
    {
        return None;
    }
    let day = digits(&s[5..7])?;
    let month = month(&s[8..11])?;
    let year = digits(&s[12..16])?;
    let (hour, minute, second) = time_of_day(&s[17..25])?;
    to_timestamp(year, month, day, hour, minute, second)
}

/// `Sun Nov  6 08:49:37 1994`
fn parse_asctime(s: &[u8]) -> Option<u64> {
    if !is_one_of(&s[0..3], &DAY_NAMES) || s[7] != b' ' || s[10] != b' ' || s[19] != b' ' {
        return None;
    }
    let month = month(&s[4..7])?;
    let day = if s[8] == b' ' {
        digits(&s[9..10])?
    } else {
        digits(&s[8..10])?
    };
    let (hour, minute, second) = time_of_day(&s[11..19])?;
    let year = digits(&s[20..24])?;
    to_timestamp(year, month, day, hour, minute, second)
}

/// `Sunday, 06-Nov-94 08:49:37 GMT`
fn parse_rfc850(s: &[u8], now: u64) -> Option<u64> {
    let comma = s.iter().position(|&b| b == b',')?;
    if !is_one_of(&s[..comma], &LONG_DAY_NAMES) {
        return None;
    }
    let rest = &s[comma + 1..];
    if rest.len() != 23
        || rest[0] != b' '
        || rest[3] != b'-'
        || rest[7] != b'-'
        || rest[10] != b' '
        || rest[19] != b' '
        || !rest[20..23].eq_ignore_ascii_case(b"GMT")
    {
        return None;
    }
    let day = digits(&rest[1..3])?;
    let month = month(&rest[4..7])?;
    let two_digit_year = digits(&rest[8..10])?;
    let (hour, minute, second) = time_of_day(&rest[11..19])?;
    let year = resolve_two_digit_year(two_digit_year, now);
    to_timestamp(year, month, day, hour, minute, second)
}

/// The year ending in `two_digits` that lies in `(now_year - 50, now_year + 50]`,
/// or the one a century earlier when that would be after 9999, the last year an
/// HTTP-date can hold.
fn resolve_two_digit_year(two_digits: u32, now: u64) -> u32 {
    let (now_year, _, _) = civil_from_days(now.min(MAX_FORMATTABLE) / 86_400);
    let now_year = now_year as u32;
    let mut year = now_year / 100 * 100 + two_digits;
    if year > now_year + 50 {
        year -= 100;
    } else if year + 50 <= now_year && year + 100 <= 9999 {
        year += 100;
    }
    year
}

fn trim(mut value: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = value {
        value = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = value {
        value = rest;
    }
    value
}

fn is_one_of(value: &[u8], names: &[&[u8]]) -> bool {
    names.iter().any(|name| name.eq_ignore_ascii_case(value))
}

fn month(value: &[u8]) -> Option<u32> {
    MONTHS
        .iter()
        .position(|name| name.eq_ignore_ascii_case(value))
        .map(|index| index as u32 + 1)
}

/// A fixed-width run of ASCII digits. Callers pass 1 to 4 bytes.
fn digits(value: &[u8]) -> Option<u32> {
    let mut result = 0u32;
    for &byte in value {
        if !byte.is_ascii_digit() {
            return None;
        }
        result = result * 10 + u32::from(byte - b'0');
    }
    Some(result)
}

/// `hh:mm:ss`, with `ss` up to 60 for a leap second.
fn time_of_day(value: &[u8]) -> Option<(u32, u32, u32)> {
    if value[2] != b':' || value[5] != b':' {
        return None;
    }
    let hour = digits(&value[0..2])?;
    let minute = digits(&value[3..5])?;
    let second = digits(&value[6..8])?;
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some((hour, minute, second.min(59)))
}

fn is_leap_year(year: u32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn to_timestamp(
    year: u32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<u64> {
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + i64::from(hour * 3600 + minute * 60 + second);
    Some(seconds.max(0) as u64)
}

/// Days since 1970-01-01 of a proleptic Gregorian date, for years 0 to 9999.
/// Howard Hinnant's `days_from_civil`.
fn days_from_civil(year: u32, month: u32, day: u32) -> i64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month_from_march = i64::from((month + 9) % 12);
    let day_of_year = (153 * month_from_march + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The date of a day count since 1970-01-01, for counts up to the end of 9999.
/// Howard Hinnant's `civil_from_days`, specialised to non-negative counts.
fn civil_from_days(days: u64) -> (u64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_from_march + 2) / 5 + 1) as u32;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    } as u32;
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_760_000_000; // 2025-10-09

    #[test]
    fn rfc_9110_examples_denote_the_same_instant() {
        let expected = Some(784_111_777);
        assert_eq!(
            parse_http_date(b"Sun, 06 Nov 1994 08:49:37 GMT", NOW),
            expected
        );
        assert_eq!(
            parse_http_date(b"Sunday, 06-Nov-94 08:49:37 GMT", NOW),
            expected
        );
        assert_eq!(parse_http_date(b"Sun Nov  6 08:49:37 1994", NOW), expected);
    }

    #[test]
    fn formatting_produces_imf_fixdate() {
        assert_eq!(
            format_http_date(784_111_777),
            "Sun, 06 Nov 1994 08:49:37 GMT"
        );
        assert_eq!(format_http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(format_http_date(u64::MAX), "Fri, 31 Dec 9999 23:59:59 GMT");
    }

    #[test]
    fn names_and_zone_are_case_insensitive() {
        assert_eq!(
            parse_http_date(b"sun, 06 nov 1994 08:49:37 gmt", NOW),
            Some(784_111_777)
        );
        assert_eq!(
            parse_http_date(b"SUNDAY, 06-NOV-94 08:49:37 GMT", NOW),
            Some(784_111_777)
        );
    }

    #[test]
    fn a_zone_other_than_gmt_is_invalid() {
        assert_eq!(parse_http_date(b"Sun, 06 Nov 1994 08:49:37 UTC", NOW), None);
        assert_eq!(parse_http_date(b"Sun, 06 Nov 1994 08:49:37 PST", NOW), None);
    }

    #[test]
    fn day_name_is_not_checked_against_the_date() {
        assert_eq!(
            parse_http_date(b"Mon, 06 Nov 1994 08:49:37 GMT", NOW),
            Some(784_111_777)
        );
        assert_eq!(parse_http_date(b"Foo, 06 Nov 1994 08:49:37 GMT", NOW), None);
    }

    #[test]
    fn invalid_calendar_dates_are_rejected() {
        assert_eq!(parse_http_date(b"Thu, 29 Feb 2001 00:00:00 GMT", NOW), None);
        assert!(parse_http_date(b"Tue, 29 Feb 2000 00:00:00 GMT", NOW).is_some());
        assert_eq!(parse_http_date(b"Mon, 31 Apr 2000 00:00:00 GMT", NOW), None);
        assert_eq!(parse_http_date(b"Mon, 00 Apr 2000 00:00:00 GMT", NOW), None);
        assert_eq!(parse_http_date(b"Mon, 10 Apr 2000 24:00:00 GMT", NOW), None);
    }

    #[test]
    fn leap_second_reads_as_the_second_before() {
        assert_eq!(
            parse_http_date(b"Sat, 31 Dec 2016 23:59:60 GMT", NOW),
            parse_http_date(b"Sat, 31 Dec 2016 23:59:59 GMT", NOW)
        );
    }

    #[test]
    fn two_digit_years_never_land_more_than_50_years_ahead() {
        // NOW is in 2025.
        let year_of = |value: &[u8]| {
            let time = parse_http_date(value, NOW).unwrap();
            civil_from_days(time / 86_400).0
        };
        assert_eq!(year_of(b"Monday, 01-Jan-75 00:00:00 GMT"), 2075);
        assert_eq!(year_of(b"Monday, 01-Jan-76 00:00:00 GMT"), 1976);
        assert_eq!(year_of(b"Monday, 01-Jan-99 00:00:00 GMT"), 1999);
        assert_eq!(year_of(b"Monday, 01-Jan-25 00:00:00 GMT"), 2025);
    }

    /// Every separator, and the zone, must be exactly right: one wrong
    /// character anywhere makes the date invalid.
    #[test]
    fn each_separator_is_checked() {
        for valid in [
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
        ] {
            assert!(parse_http_date(valid.as_bytes(), NOW).is_some());
            for (index, byte) in valid.bytes().enumerate() {
                if !matches!(byte, b' ' | b',' | b'-' | b':') {
                    continue;
                }
                let mut broken = valid.as_bytes().to_vec();
                broken[index] = b'x';
                assert_eq!(
                    parse_http_date(&broken, NOW),
                    None,
                    "{}",
                    String::from_utf8_lossy(&broken)
                );
            }
        }
    }

    #[test]
    fn time_of_day_fields_are_range_checked_one_by_one() {
        assert!(parse_http_date(b"Sun, 06 Nov 1994 23:59:59 GMT", NOW).is_some());
        for invalid in [
            &b"Sun, 06 Nov 1994 24:00:00 GMT"[..],
            b"Sun, 06 Nov 1994 23:60:00 GMT",
            b"Sun, 06 Nov 1994 23:59:61 GMT",
            b"Sun, 06 Nov 1994 0a:49:37 GMT",
        ] {
            assert_eq!(
                parse_http_date(invalid, NOW),
                None,
                "{}",
                String::from_utf8_lossy(invalid)
            );
        }
    }

    #[test]
    fn two_digit_years_move_forward_when_more_than_50_years_back() {
        // 2090-01-01: "10" is 2110, not 2010, and "39" is 2039.
        let in_2090 = 3_786_912_000;
        let year_of =
            |value: &[u8]| civil_from_days(parse_http_date(value, in_2090).unwrap() / 86_400).0;
        assert_eq!(year_of(b"Monday, 01-Jan-10 00:00:00 GMT"), 2110);
        assert_eq!(year_of(b"Monday, 01-Jan-40 00:00:00 GMT"), 2140);
        assert_eq!(year_of(b"Monday, 01-Jan-41 00:00:00 GMT"), 2041);
        assert_eq!(year_of(b"Monday, 01-Jan-39 00:00:00 GMT"), 2139);
    }

    #[test]
    fn two_digit_years_stay_within_four_digits() {
        let in_9999 = MAX_FORMATTABLE - 1000;
        let time = parse_http_date(b"Monday, 01-Jan-49 00:00:00 GMT", in_9999).unwrap();
        assert_eq!(civil_from_days(time / 86_400).0, 9949);
        assert!(time <= MAX_FORMATTABLE);
    }

    #[test]
    fn surrounding_whitespace_is_ignored() {
        assert_eq!(
            parse_http_date(b"  Sun, 06 Nov 1994 08:49:37 GMT\t", NOW),
            Some(784_111_777)
        );
    }

    #[test]
    fn garbage_is_rejected() {
        for value in [
            &b""[..],
            b"0",
            b"-1",
            b"Sun, 06 Nov 1994 08:49:37",
            b"Sun, 06 Nov 1994 08:49:37 GMT extra",
            b"Sun,  6 Nov 1994 08:49:37 GMT",
            b"Sun, 06 Nov 94 08:49:37 GMT",
            b"Sun Nov 6 08:49:37 1994",
            b"Sunday, 06-Nov-1994 08:49:37 GMT",
        ] {
            assert_eq!(parse_http_date(value, NOW), None, "{value:?}");
        }
    }

    /// Every instant the formatter can represent round-trips through
    /// formatting and parsing, by enumeration rather than sampling. Both
    /// functions treat the day and the second of the day independently (the
    /// time is `days * 86400 + seconds`), so it is enough to enumerate every day
    /// at one second and every second of three days: the first, a leap day,
    /// and the last. The calendar conversions are checked against each other
    /// and against stepping one day at a time.
    #[test]
    fn every_instant_round_trips() {
        let last_day = MAX_FORMATTABLE / 86_400;
        let mut previous = civil_from_days(0);
        assert_eq!(previous, (1970, 1, 1));
        for days in 0..=last_day {
            let (year, month, day) = civil_from_days(days);
            assert_eq!(days_from_civil(year as u32, month, day), days as i64);
            if days > 0 {
                let next_in_month = (year, month, day) == (previous.0, previous.1, previous.2 + 1);
                let next_month = day == 1
                    && ((year == previous.0 && month == previous.1 + 1)
                        || (year == previous.0 + 1 && month == 1 && previous.1 == 12));
                assert!(
                    next_in_month || next_month,
                    "{previous:?} -> {:?}",
                    (year, month, day)
                );
                if day == 1 {
                    assert_eq!(previous.2, days_in_month(previous.0 as u32, previous.1));
                }
            }
            let time = days * 86_400 + 43_210;
            assert_eq!(
                parse_http_date(format_http_date(time).as_bytes(), NOW),
                Some(time)
            );
            previous = (year, month, day);
        }
        assert_eq!(previous, (9999, 12, 31));
        let leap_day = (days_from_civil(2000, 2, 29) as u64) * 86_400;
        for start in [0, leap_day, last_day * 86_400] {
            for second in 0..86_400 {
                let time = start + second;
                assert_eq!(
                    parse_http_date(format_http_date(time).as_bytes(), NOW),
                    Some(time)
                );
            }
        }
    }

    #[test]
    fn dates_before_the_epoch_clamp_to_zero() {
        assert_eq!(
            parse_http_date(b"Mon, 01 Jan 1900 00:00:00 GMT", NOW),
            Some(0)
        );
    }
}
