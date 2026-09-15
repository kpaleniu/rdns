//! The `YYYYMMDDHHmmSS` an RRSIG's times are written in, and the calendar
//! arithmetic under it (RFC 4034 §3.2).
//!
//! Its own module because it is the one piece of presentation that is not about
//! a record's shape, and because the parser and the writer are inverses that
//! must not drift — they are tested against each other here rather than from
//! two crates (`CLAUDE.md` §7).

/// The small parse helpers below return `Result<_, String>` on purpose: they
/// produce a *detail*, and only their caller — the zone parser — knows the line
/// number to attach it to. A `ZoneError` here would have to invent one.
fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// How many days `month` (1-12) has in `year`, or `None` if that is not a
/// month. `None` and not zero: zero reads as an answer to a caller summing
/// days, which turns month 13 into a plausible epoch for a date that does not
/// exist.
fn days_in_month(month: i32, year: i32) -> Option<i32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 => Some(if is_leap(year) { 29 } else { 28 }),
        _ => None,
    }
}

/// An RRSIG's inception or expiration: a bare epoch, or `YYYYMMDDHHmmSS` in UTC
/// (RFC 4034 §3.2). Every field is range-checked and the result is checked to
/// fit. The inverse is [`format_dnssec_time`].
pub fn parse_dnssec_time(time_str: &str) -> Result<u32, String> {
    if let Ok(epoch) = time_str.parse::<u32>() {
        return Ok(epoch);
    }

    // Fourteen ASCII digits, established before anything is sliced: the
    // slicing below is by byte, so a 14-byte string holding a multi-byte
    // character would panic on a boundary rather than fail to parse.
    if time_str.len() != 14 || !time_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "Invalid DNSSEC time format: {time_str} (want a bare epoch or 14 digits)"
        ));
    }

    let year = time_str[0..4].parse::<i32>().map_err(|e| e.to_string())?;
    let month = time_str[4..6].parse::<i32>().map_err(|e| e.to_string())?;
    let day = time_str[6..8].parse::<i32>().map_err(|e| e.to_string())?;
    let hour = time_str[8..10].parse::<i32>().map_err(|e| e.to_string())?;
    let min = time_str[10..12].parse::<i32>().map_err(|e| e.to_string())?;
    let sec = time_str[12..14].parse::<i32>().map_err(|e| e.to_string())?;

    // A year before 1970 makes `total_days` negative, which widens into the far
    // future rather than failing.
    if year < 1970 {
        return Err(format!("{time_str}: year {year} is before the POSIX epoch"));
    }
    let days_this_month = days_in_month(month, year)
        .ok_or_else(|| format!("{time_str}: month {month} is not a month"))?;
    if !(1..=days_this_month).contains(&day) {
        return Err(format!(
            "{time_str}: day {day} is not a day of month {month}"
        ));
    }
    // Seconds stop at 59: this converts to POSIX time, which has no leap
    // seconds, so there is no instant for a `:60` to name.
    if hour > 23 || min > 59 || sec > 59 {
        return Err(format!(
            "{time_str}: {hour:02}:{min:02}:{sec:02} is not a time"
        ));
    }

    let mut total_days = 0;
    for y in 1970..year {
        total_days += if is_leap(y) { 366 } else { 365 };
    }
    for m in 1..month {
        // Cannot be `None`: `month` is 1-12 by the check above, so `m` is 1-11.
        total_days += days_in_month(m, year).unwrap_or(0);
    }
    total_days += day - 1;

    let epoch = total_days as i64 * 86400 + hour as i64 * 3600 + min as i64 * 60 + sec as i64;
    // Checked, not `as`: one second past the field truncates to 0, turning a
    // signature dated the far future into one that expired in 1970.
    u32::try_from(epoch)
        .map_err(|_| format!("{time_str} is outside the range a 32-bit DNSSEC timestamp can hold"))
}

/// The `YYYYMMDDHHmmSS` form an RRSIG's times are written in, UTC
/// (RFC 4034 §3.2). The inverse of [`parse_dnssec_time`].
///
/// The parser also accepts a bare epoch and writing that would be shorter, but
/// nothing else in the ecosystem does.
pub fn format_dnssec_time(epoch: u32) -> String {
    let mut days = (epoch / 86400) as i32;
    let seconds = epoch % 86400;

    let mut year = 1970;
    loop {
        let in_year = if is_leap(year) { 366 } else { 365 };
        if days < in_year {
            break;
        }
        days -= in_year;
        year += 1;
    }

    // Bounded at December rather than trusting the day count to run out: a
    // month contributing zero days would spin until `month` overflowed.
    let mut month = 1;
    while month < 12 {
        let Some(in_month) = days_in_month(month, year) else {
            break;
        };
        if days < in_month {
            break;
        }
        days -= in_month;
        month += 1;
    }

    format!(
        "{year:04}{month:02}{:02}{:02}{:02}{:02}",
        days + 1,
        seconds / 3600,
        (seconds / 60) % 60,
        seconds % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The formatter and the parser are inverses, or a rewritten RRSIG claims a
    /// different validity period from the one it was signed with.
    #[test]
    fn test_dnssec_time_round_trips() {
        for (epoch, text) in [
            (0u32, "19700101000000"),
            (1, "19700101000001"),
            (951_868_800, "20000301000000"), // the day after a leap day
            (1_078_012_800, "20040229000000"), // a leap day itself
            (1_609_459_199, "20201231235959"),
            (2_147_483_647, "20380119031407"),
            (u32::MAX, "21060207062815"),
        ] {
            assert_eq!(format_dnssec_time(epoch), text, "formatting {epoch}");
            assert_eq!(parse_dnssec_time(text), Ok(epoch), "parsing {text}");
        }
    }

    /// A 14-*byte* string is not fourteen characters, and the slicing is by
    /// byte: a multi-byte character must not panic on a char boundary.
    #[test]
    fn a_fourteen_byte_time_that_is_not_fourteen_digits_is_an_error() {
        let multibyte = "abcé123456789";
        assert_eq!(multibyte.len(), 14, "the byte-length check passes");
        assert!(parse_dnssec_time(multibyte).is_err(), "must not panic");

        // The same shape with the multi-byte character at each slice boundary.
        for probe in ["é12345678901", "1234é678901234", "123456789012é"] {
            let _ = parse_dnssec_time(probe);
        }
    }
}
