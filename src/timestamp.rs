//! Validated RFC 3339 timestamps with exact fractional-second ordering.

use std::cmp::Ordering;
use std::fmt::{self, Display, Formatter};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::{Date, Month, Time};

use crate::types::{Diagnostic, InputError};

const UNIX_EPOCH_JULIAN_DAY: i64 = 2_440_588;
const SECONDS_PER_DAY: i64 = 86_400;

/// A validated RFC 3339 timestamp compared as an exact UTC instant.
///
/// Fractional seconds retain arbitrary RFC 3339 precision, and serialization
/// preserves the original spelling. No system clock is consulted.
#[derive(Clone, Debug)]
pub struct Timestamp {
    original: String,
    utc_seconds: i64,
    leap_second: bool,
    normalized_fraction: String,
}

impl Timestamp {
    /// Parses an RFC 3339 timestamp with a validated calendar date and offset.
    ///
    /// Timestamp fractions are preserved exactly rather than truncated to
    /// nanoseconds. Leap seconds are accepted only on dates in the known
    /// positive-leap-second table used by authority assessment.
    ///
    /// # Errors
    ///
    /// Returns an input error for malformed date-time syntax, invalid calendar
    /// or offset fields, or a leap second not present in that table.
    ///
    /// # Examples
    ///
    /// ```
    /// use cvd_policy::Timestamp;
    ///
    /// let earlier = Timestamp::parse("2026-01-01T12:00:00.0000000000Z")?;
    /// let later = Timestamp::parse("2026-01-01T12:00:00.0000000001Z")?;
    /// assert!(earlier < later);
    /// # Ok::<(), cvd_policy::InputError>(())
    /// ```
    pub fn parse(value: &str) -> Result<Self, InputError> {
        let bytes = value.as_bytes();
        if bytes.len() < 20
            || bytes.get(4) != Some(&b'-')
            || bytes.get(7) != Some(&b'-')
            || !bytes
                .get(10)
                .is_some_and(|byte| matches!(*byte, b'T' | b't'))
            || bytes.get(13) != Some(&b':')
            || bytes.get(16) != Some(&b':')
        {
            return Err(invalid_timestamp());
        }

        let year = parse_digits(bytes, 0, 4).ok_or_else(invalid_timestamp)?;
        let month_number = parse_digits(bytes, 5, 7).ok_or_else(invalid_timestamp)?;
        let day = parse_digits(bytes, 8, 10).ok_or_else(invalid_timestamp)?;
        let hour = parse_digits(bytes, 11, 13).ok_or_else(invalid_timestamp)?;
        let minute = parse_digits(bytes, 14, 16).ok_or_else(invalid_timestamp)?;
        let second = parse_digits(bytes, 17, 19).ok_or_else(invalid_timestamp)?;
        if second > 60 {
            return Err(invalid_timestamp());
        }

        let year = i32::try_from(year).map_err(|_| invalid_timestamp())?;
        let month = u8::try_from(month_number)
            .ok()
            .and_then(|number| Month::try_from(number).ok())
            .ok_or_else(invalid_timestamp)?;
        let day = u8::try_from(day).map_err(|_| invalid_timestamp())?;
        let hour = u8::try_from(hour).map_err(|_| invalid_timestamp())?;
        let minute = u8::try_from(minute).map_err(|_| invalid_timestamp())?;
        let second = u8::try_from(second).map_err(|_| invalid_timestamp())?;
        let date = Date::from_calendar_date(year, month, day).map_err(|_| invalid_timestamp())?;
        let time = Time::from_hms(hour, minute, second.min(59)).map_err(|_| invalid_timestamp())?;

        let mut index = 19;
        let fraction_start = if bytes.get(index) == Some(&b'.') {
            index += 1;
            let fraction_start = index;
            while bytes.get(index).is_some_and(u8::is_ascii_digit) {
                index += 1;
            }
            if index == fraction_start {
                return Err(invalid_timestamp());
            }
            Some(fraction_start)
        } else {
            None
        };
        let zone_start = index;

        let offset_seconds = match bytes.get(index).copied() {
            Some(b'Z' | b'z') if index + 1 == bytes.len() => 0_i64,
            Some(b'+' | b'-') if bytes.len().saturating_sub(index) == 6 => {
                if bytes.get(index + 3) != Some(&b':') {
                    return Err(invalid_timestamp());
                }
                let offset_hour =
                    parse_digits(bytes, index + 1, index + 3).ok_or_else(invalid_timestamp)?;
                let offset_minute =
                    parse_digits(bytes, index + 4, index + 6).ok_or_else(invalid_timestamp)?;
                if offset_hour > 23 || offset_minute > 59 {
                    return Err(invalid_timestamp());
                }
                let sign = if bytes[index] == b'+' { 1_i64 } else { -1_i64 };
                sign * (i64::from(offset_hour) * 3_600 + i64::from(offset_minute) * 60)
            }
            _ => return Err(invalid_timestamp()),
        };
        if zone_start >= bytes.len() {
            return Err(invalid_timestamp());
        }

        let days_since_epoch = i64::from(date.to_julian_day()) - UNIX_EPOCH_JULIAN_DAY;
        let local_seconds = days_since_epoch * SECONDS_PER_DAY
            + i64::from(time.hour()) * 3_600
            + i64::from(time.minute()) * 60
            + i64::from(time.second());
        let utc_seconds = local_seconds - offset_seconds;
        let leap_second = second == 60;
        if leap_second && !is_known_utc_leap_second(utc_seconds) {
            return Err(invalid_timestamp());
        }

        let fraction = fraction_start
            .map(|start| &value[start..zone_start])
            .unwrap_or_default();
        let normalized_fraction = fraction.trim_end_matches('0').to_owned();

        Ok(Self {
            original: value.to_owned(),
            utc_seconds,
            leap_second,
            normalized_fraction,
        })
    }
}

impl Display for Timestamp {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.original)
    }
}

impl PartialEq for Timestamp {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Timestamp {}

impl PartialOrd for Timestamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Timestamp {
    fn cmp(&self, other: &Self) -> Ordering {
        self.utc_seconds
            .cmp(&other.utc_seconds)
            .then_with(|| self.leap_second.cmp(&other.leap_second))
            .then_with(|| compare_fraction(&self.normalized_fraction, &other.normalized_fraction))
    }
}

fn compare_fraction(left: &str, right: &str) -> Ordering {
    for index in 0..left.len().max(right.len()) {
        let left_digit = left.as_bytes().get(index).copied().unwrap_or(b'0');
        let right_digit = right.as_bytes().get(index).copied().unwrap_or(b'0');
        match left_digit.cmp(&right_digit) {
            Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    Ordering::Equal
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.original)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

fn parse_digits(bytes: &[u8], start: usize, end: usize) -> Option<u32> {
    let digits = bytes.get(start..end)?;
    digits.iter().try_fold(0_u32, |value, digit| {
        if !digit.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(u32::from(*digit - b'0'))
    })
}

fn is_known_utc_leap_second(utc_seconds: i64) -> bool {
    let utc_day = utc_seconds.div_euclid(SECONDS_PER_DAY);
    if utc_seconds.rem_euclid(SECONDS_PER_DAY) != SECONDS_PER_DAY - 1 {
        return false;
    }
    let julian_day = utc_day + UNIX_EPOCH_JULIAN_DAY;
    let Ok(julian_day) = i32::try_from(julian_day) else {
        return false;
    };
    let Ok(date) = Date::from_julian_day(julian_day) else {
        return false;
    };

    matches!(
        (date.year(), date.month(), date.day()),
        (1972, Month::June, 30)
            | (1972, Month::December, 31)
            | (1973, Month::December, 31)
            | (1974, Month::December, 31)
            | (1975, Month::December, 31)
            | (1976, Month::December, 31)
            | (1977, Month::December, 31)
            | (1978, Month::December, 31)
            | (1979, Month::December, 31)
            | (1981, Month::June, 30)
            | (1982, Month::June, 30)
            | (1983, Month::June, 30)
            | (1985, Month::June, 30)
            | (1987, Month::December, 31)
            | (1989, Month::December, 31)
            | (1990, Month::December, 31)
            | (1992, Month::June, 30)
            | (1993, Month::June, 30)
            | (1994, Month::June, 30)
            | (1995, Month::December, 31)
            | (1997, Month::June, 30)
            | (1998, Month::December, 31)
            | (2005, Month::December, 31)
            | (2008, Month::December, 31)
            | (2012, Month::June, 30)
            | (2015, Month::June, 30)
            | (2016, Month::December, 31)
    )
}

fn invalid_timestamp() -> InputError {
    InputError {
        diagnostics: vec![Diagnostic {
            code: "timestamp_invalid".to_owned(),
            path: String::new(),
            message: "invalid RFC 3339 timestamp".to_owned(),
        }],
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use super::Timestamp;

    fn timestamp(value: &str) -> Timestamp {
        Timestamp::parse(value).unwrap()
    }

    #[test]
    fn compares_offset_spellings_as_the_same_instant() {
        let utc = timestamp("2026-01-01T12:00:00Z");
        let offset = timestamp("2026-01-01t13:00:00+01:00");
        assert_eq!(utc, offset);
        assert_eq!(utc.cmp(&offset), Ordering::Equal);
        assert_eq!(offset.to_string(), "2026-01-01t13:00:00+01:00");
    }

    #[test]
    fn preserves_and_orders_fractional_seconds_beyond_nanoseconds() {
        let now = timestamp("2026-01-01T12:00:00.0000000000Z");
        let expiry = timestamp("2026-01-01T12:00:00.0000000001Z");
        assert!(now < expiry);
        assert_ne!(now, expiry);
        assert_eq!(now.to_string(), "2026-01-01T12:00:00.0000000000Z");
        assert_eq!(
            timestamp("2026-01-01T12:00:00.1Z"),
            timestamp("2026-01-01T12:00:00.1000Z")
        );
        assert!(timestamp("2026-01-01T12:00:00.1Z") < timestamp("2026-01-01T12:00:00.1001Z"));
    }

    #[test]
    fn validates_calendar_offset_and_rfc3339_syntax() {
        for invalid in [
            "2027-02-30T00:00:00Z",
            "2026-01-01T00:00:00",
            "2026-01-01 00:00:00Z",
            "2026-01-01T00:00:00+24:00",
            "2026-01-01T00:00:00+01:60",
            "2026-01-01T00:00:00. Z",
            "2026-01-01T00:00:61Z",
        ] {
            assert!(Timestamp::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn accepts_only_known_utc_leap_seconds() {
        let leap = timestamp("2016-12-31T23:59:60.25Z");
        let offset_leap = timestamp("2017-01-01T00:59:60.25+01:00");
        assert_eq!(leap, offset_leap);
        assert!(Timestamp::parse("2026-12-31T23:59:60Z").is_err());
        assert!(Timestamp::parse("2016-12-30T23:59:60Z").is_err());
        assert!(timestamp("2016-12-31T23:59:59.9Z") < leap);
        assert!(leap < timestamp("2017-01-01T00:00:00Z"));
    }

    #[test]
    fn accepts_the_known_leap_second_dates_from_authority_assessment() {
        for date in [
            "1972-06-30",
            "1972-12-31",
            "1973-12-31",
            "1974-12-31",
            "1975-12-31",
            "1976-12-31",
            "1977-12-31",
            "1978-12-31",
            "1979-12-31",
            "1981-06-30",
            "1982-06-30",
            "1983-06-30",
            "1985-06-30",
            "1987-12-31",
            "1989-12-31",
            "1990-12-31",
            "1992-06-30",
            "1993-06-30",
            "1994-06-30",
            "1995-12-31",
            "1997-06-30",
            "1998-12-31",
            "2005-12-31",
            "2008-12-31",
            "2012-06-30",
            "2015-06-30",
            "2016-12-31",
        ] {
            assert!(
                Timestamp::parse(&format!("{date}T23:59:60Z")).is_ok(),
                "{date}"
            );
        }
    }

    #[test]
    fn serde_validates_and_preserves_the_original_string() {
        let original = "2026-01-01t13:00:00.000+01:00";
        let parsed: Timestamp = serde_json::from_str(&format!("\"{original}\"")).unwrap();
        assert_eq!(parsed.to_string(), original);
        assert_eq!(
            serde_json::to_string(&parsed).unwrap(),
            format!("\"{original}\"")
        );
        assert!(serde_json::from_str::<Timestamp>("\"2027-02-30T00:00:00Z\"").is_err());
    }
}
