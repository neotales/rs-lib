// Civil-date arithmetic is integer arithmetic on a proleptic Gregorian calendar,
// and it crosses `i64` and `i128` constantly: a Unix timestamp in nanoseconds is
// about 1.8e18, which is inside an `i64` but nowhere near its comfortable range
// for arithmetic. The conversions are therefore deliberate and each is bounded
// by the range the surrounding code checks, rather than accidental.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]

//! The date and time helpers.
//!
//! Everything here follows the reference: a date is parsed into an instant and
//! an offset, and rendered through a layout that is Go's reference time, so
//! `{{ date "2006-01-02" "2019-06-13T20:39:39Z" }}` prints `2019-06-13`.
//!
//! Two spellings of the reference's layouts are worth knowing about, because
//! they are .NET artefacts of the reference's translation rather than Go's
//! behaviour, and the parity fixture pins both:
//!
//! - `-0700` is translated to .NET's `zzzz`, which prints the offset with a
//!   colon (`+00:00`) where Go prints `+0000`. The fixture case
//!   `{{ date_in_zone "02 Jan 06 15:04 -0700" "2019-06-13T20:39:39Z" "UTC" }}`
//!   expects `13 Jun 19 20:39 +00:00`, so that is what is produced.
//! - `MST` is translated to .NET's `zzz`, which for a `DateTimeOffset` is the
//!   same numeric offset rather than a zone abbreviation, so `MST` prints
//!   `+00:00` too. No fixture case covers `MST`, and this is the reading that
//!   matches the translation the reference performs.
//!
//! A zone is resolved to a fixed offset. `UTC` and its spellings are zero, a
//! numeric offset such as `+05:30` is itself, and anything the lookup does not
//! recognise falls back to UTC — which is what the reference does when
//! `TimeZoneInfo.FindSystemTimeZoneById` throws, and is the only behaviour
//! available without a time zone database. A named zone like
//! `America/New_York` therefore renders as UTC here, which is a real difference
//! from the reference and the one thing in this module that cannot be made
//! exact without a new dependency.
//!
//! # `now` reads a clock
//!
//! Every other helper in this crate is a function of its arguments, and this
//! module's other helpers are no exception: none of them looks at the current
//! time. `now` is the single exception, and it is not reproducible — a template
//! that uses it renders differently on every run, which is the property the rest
//! of the crate exists to preserve. It is implemented because the reference
//! registers it and a template written against the reference needs it, but a
//! Compose file that has to render identically on a laptop and in a pipeline
//! should not use it. `ago` has the same caveat in a milder form: it measures
//! against the current time, so its output moves even though the argument does
//! not.

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::support;
use crate::{Context, Error, Value};

/// The layout `date` uses when it is given only a time.
///
/// This is Go's reference time, which is the layout the reference's own
/// `GoDateFormat` is written against.
const DEFAULT_LAYOUT: &str = "2006-01-02 15:04:05 -0700 MST";

/// The layout `htmlDate` and `htmlDateInZone` use.
///
/// The reference writes these as .NET's `yyyy-MM-dd` rather than translating a
/// Go layout, but the two are the same characters for every date.
const HTML_DATE_LAYOUT: &str = "2006-01-02";

/// The value `toDate` produces for a value its layout cannot parse.
///
/// The reference falls back to `DateTimeOffset.MinValue.ToString("O")`, which is
/// this exact text. `mustToDate` is the form that reports the problem instead.
const MINIMUM_DATE: &str = "0001-01-01T00:00:00.0000000+00:00";

/// The months, both spellings, indexed by month number.
const MONTHS: [(&str, &str); 12] = [
    ("January", "Jan"),
    ("February", "Feb"),
    ("March", "Mar"),
    ("April", "Apr"),
    ("May", "May"),
    ("June", "Jun"),
    ("July", "Jul"),
    ("August", "Aug"),
    ("September", "Sep"),
    ("October", "Oct"),
    ("November", "Nov"),
    ("December", "Dec"),
];

/// The weekdays, both spellings, indexed by day of the week with Sunday first.
const WEEKDAYS: [(&str, &str); 7] = [
    ("Sunday", "Sun"),
    ("Monday", "Mon"),
    ("Tuesday", "Tue"),
    ("Wednesday", "Wed"),
    ("Thursday", "Thu"),
    ("Friday", "Fri"),
    ("Saturday", "Sat"),
];

/// Dispatches a date helper.
pub(super) const DISPATCH: crate::Dispatch =
    |name, arguments, context| dispatch(name, arguments, context);

#[allow(clippy::trivially_copy_pass_by_ref)]
fn dispatch(
    name: &str,
    arguments: &[Value],
    context: &Context<'_>,
) -> Option<Result<Value, Error>> {
    let _ = context;
    let result = match name {
        "now" => now(name, arguments),
        "date" => date(name, arguments),
        "dateInZone" | "date_in_zone" => date_in_zone(name, arguments),
        "htmlDate" => html_date(name, arguments),
        "htmlDateInZone" => html_date_in_zone(name, arguments),
        "dateModify" | "date_modify" => date_modify(name, arguments, false),
        "mustDateModify" | "must_date_modify" => date_modify(name, arguments, true),
        "toDate" => to_date(name, arguments, false),
        "mustToDate" => to_date(name, arguments, true),
        "ago" => ago(name, arguments),
        "duration" => duration(name, arguments),
        "durationRound" => duration_round(name, arguments),
        "unixEpoch" => unix_epoch(name, arguments),
        _ => return None,
    };
    Some(result)
}

/// Reports whether this module's helper wants rendered string arguments.
///
/// False for all of them. A date, a layout, and a duration are all read as
/// written, and `unixEpoch` returns a number-shaped string that the caller
/// prints whole. Rendering first would turn a layout into something that no
/// longer parses.
///
/// The answer is kept per module because that is where the contract for it
/// lives: a module that later grows a helper which does want its arguments
/// rendered has one place to say so. `lib.rs` currently folds the answer for
/// this module to a constant `false`, so nothing outside the module's own tests
/// calls this; the lint is allowed rather than the function dropped so that the
/// two cannot drift apart.
#[allow(dead_code)]
pub(super) fn takes_rendered_strings(_name: &str) -> bool {
    false
}

/// The current instant, in the reference's round-trip spelling.
///
/// This is the reference's `Now`, which is `DateTimeOffset.UtcNow.ToString("O")`.
/// It is the one helper in the crate that reads a clock, so a template that
/// calls it does not render reproducibly; see the module documentation.
fn now(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 0, Some(0))?;
    Ok(Value::String(format_round_trip(&Instant::now())))
}

/// Formats a time with a layout, as `date FMT TIME` does.
///
/// With two arguments the layout is the first one, as the reference's `Date`
/// takes it. With one argument the layout is Go's reference time, which is the
/// form upstream Sprig documents and the only way to write `{{ date now }}`.
fn date(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 1, Some(2))?;
    let (layout, value) = if arguments.len() == 2 {
        (
            support::text(name, &arguments[0])?,
            support::text(name, &arguments[1])?,
        )
    } else {
        (
            DEFAULT_LAYOUT.to_owned(),
            support::text(name, &arguments[0])?,
        )
    };
    let instant = parse_date(name, &value)?;
    Ok(Value::String(format_layout(&layout, &instant)))
}

/// Formats a time in a named zone, as `dateInZone FMT TIME ZONE` does.
///
/// Both spellings of the reference's name are the same helper, and so are both
/// spellings of the `must` forms below.
fn date_in_zone(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 3, Some(3))?;
    let layout = support::text(name, &arguments[0])?;
    let value = support::text(name, &arguments[1])?;
    let zone = support::text(name, &arguments[2])?;
    let instant = parse_date(name, &value)?;
    let instant = instant.in_offset(zone_offset(&zone));
    Ok(Value::String(format_layout(&layout, &instant)))
}

/// Renders the date part alone, as `htmlDate TIME` does.
///
/// The reference does not convert zones here: it formats the offset the time was
/// written in, so `htmlDate` of a time with an offset is that offset's date.
fn html_date(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 1, Some(1))?;
    let value = support::text(name, &arguments[0])?;
    let instant = parse_date(name, &value)?;
    Ok(Value::String(format_layout(HTML_DATE_LAYOUT, &instant)))
}

/// Renders the date part alone in a named zone, as `htmlDateInZone TIME ZONE`.
fn html_date_in_zone(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 2, Some(2))?;
    let value = support::text(name, &arguments[0])?;
    let zone = support::text(name, &arguments[1])?;
    let instant = parse_date(name, &value)?;
    let instant = instant.in_offset(zone_offset(&zone));
    Ok(Value::String(format_layout(HTML_DATE_LAYOUT, &instant)))
}

/// Adds a duration to a time, as `dateModify DURATION TIME` does.
///
/// The `must` form is the one that reports a duration it cannot read. The plain
/// form leaves the time alone, which is the reference's `catch (FormatException)`
/// around `ParseDuration` and nothing else. A *time* it cannot read is an error
/// from both forms either way; only the wording differs, because the reference
/// parses the time outside the `try` in `DateModify` and inside it in
/// `MustDateModify`.
fn date_modify(name: &str, arguments: &[Value], must: bool) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 2, Some(2))?;
    let duration = support::text(name, &arguments[0])?;
    let value = support::text(name, &arguments[1])?;
    let instant = match parse_date(name, &value) {
        Ok(instant) => instant,
        // The reference parses the time outside the `try` in `DateModify` and
        // inside it in `MustDateModify`, so a time it cannot read is its own
        // error in the plain form and comes out as the duration complaint in
        // the `must` one.
        Err(_) if must => return Err(crate::invalid(name, "a valid duration")),
        Err(error) => return Err(error),
    };
    let instant = match parse_go_duration(&duration) {
        Some(nanoseconds) => instant.add_nanoseconds(name, nanoseconds)?,
        None if must => return Err(crate::invalid(name, "a valid duration")),
        None => instant,
    };
    Ok(Value::String(format_round_trip(&instant)))
}

/// Parses a time with a layout, as `toDate LAYOUT VALUE` does.
///
/// The parse is exact: the layout has to describe the whole value, which is what
/// the reference's `TryParseExact` against the translated layout does. A value
/// the layout cannot parse becomes the minimum date in the plain form, and an
/// error in the `must` form.
fn to_date(name: &str, arguments: &[Value], must: bool) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 2, Some(2))?;
    let layout = support::text(name, &arguments[0])?;
    let value = support::text(name, &arguments[1])?;
    match parse_with_layout(&layout, &value) {
        Some(instant) => Ok(Value::String(format_round_trip(&instant))),
        None if must => Err(crate::invalid(name, "a date matching the layout")),
        None => Ok(Value::String(MINIMUM_DATE.to_owned())),
    }
}

/// Renders how long ago a time was, as `ago TIME` does.
///
/// The reference rounds to the nearest whole second, away from zero at the
/// halfway point, and then formats the result the way Go formats a duration made
/// of whole seconds: hours, minutes, and seconds, with a component left out only
/// when it is zero and no larger one is present.
fn ago(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 1, Some(1))?;
    let value = support::text(name, &arguments[0])?;
    let instant = parse_date(name, &value)?;
    let elapsed = Instant::now().nanoseconds_since(&instant);
    // `Math.Round(elapsed.TotalSeconds, MidpointRounding.AwayFromZero)`.
    let seconds = (elapsed as f64 / 1_000_000_000.0).round();
    let nanoseconds = (seconds * 1_000_000_000.0) as i128;
    Ok(Value::String(format_go_duration(nanoseconds)))
}

/// Renders a count of seconds as a duration, as `duration SECONDS` does.
///
/// The reference reads the argument with `NLong`, which renders a scalar and
/// treats anything it cannot read as zero, so `duration "later"` is `0s` rather
/// than an error. A fraction is truncated, so `duration 61.9` is `1m1s`.
fn duration(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 1, Some(1))?;
    let seconds = arguments[0].as_number().trunc();
    let seconds = if seconds.is_finite() {
        seconds.clamp(i64::MIN as f64, i64::MAX as f64) as i64
    } else {
        0
    };
    Ok(Value::String(format_go_duration(
        i128::from(seconds) * 1_000_000_000,
    )))
}

/// Rounds a duration to its largest whole unit, as `durationRound DURATION`.
///
/// A number is a count of 100-nanosecond ticks divided by 100, which the
/// reference spells `TimeSpan.FromTicks(NLong(i, 0) / 100)`; that is nanoseconds
/// truncated to a whole tick, and it is why the reference's own fixture
/// `{{ durationRound 10000000000 }}` is `10s`. Anything else is read as a Go
/// duration, and text that is not one is `0s` rather than an error.
///
/// A number written in a template reaches this crate as a string, because that
/// is what the template engine makes of a numeric literal, and the reference
/// can tell the two apart where this cannot. A bare number is therefore read as
/// nanoseconds however it arrives, which is what keeps the reference's own case
/// working: `durationRound 10000000000` is `10s`. A quoted number is then read
/// the same way, which is a difference from the reference — `durationRound
/// "10000000000"` is `10s` here and `0s` there, because the reference refuses a
/// duration string with no unit on it — and the alternative is a case the
/// fixture covers failing.
///
/// The bounds are the reference's: over a year is years, over a month is months,
/// over a day is days, and the comparisons are strict, so a duration of exactly
/// one hour rounds to `60m` rather than `1h`.
fn duration_round(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 1, Some(1))?;
    let nanoseconds = match &arguments[0] {
        Value::Number(value) => count_ticks(*value),
        other => {
            let text = support::text(name, other)?;
            match parse_go_duration(&text) {
                Some(nanoseconds) => nanoseconds,
                // Not a duration, so it is a count if it is a number at all.
                // A count the ladder cannot show is `0s`, which is also what the
                // reference gives text that is neither, so the two agree.
                None => count_ticks(other.as_number()),
            }
        }
    };

    let seconds = (nanoseconds as f64 / 1_000_000_000.0).abs();
    let days = seconds / 86_400.0;
    let hours = seconds / 3_600.0;
    let minutes = seconds / 60.0;
    let unit;
    let value = if days > 365.0 {
        unit = "y";
        days / 365.0
    } else if days > 30.0 {
        unit = "mo";
        days / 30.0
    } else if days > 1.0 {
        unit = "d";
        days
    } else if hours > 1.0 {
        unit = "h";
        hours
    } else if minutes > 1.0 {
        unit = "m";
        minutes
    } else if seconds > 1.0 {
        unit = "s";
        seconds
    } else {
        return Ok(Value::String("0s".to_owned()));
    };
    Ok(Value::String(format!("{}{unit}", whole(value.floor()))))
}

/// Renders a Unix timestamp, as `unixEpoch TIME` does.
///
/// The result is a string rather than a number because the crate's number model
/// is a `float64` rendered the way Go renders one, which is `1.560458379e+09` at
/// this magnitude. The reference's own fixture expects `1560458379`, and a
/// timestamp is a count of whole seconds, so it is written out as one.
fn unix_epoch(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 1, Some(1))?;
    let value = support::text(name, &arguments[0])?;
    let instant = parse_date(name, &value)?;
    Ok(Value::String(instant.seconds.to_string()))
}

/// Renders a number of nanoseconds as Go spells a whole-second duration.
///
/// This is the reference's `FormatGoDuration`, which is not Go's own layout: it
/// omits a zero component unless a larger one is present, always writes the
/// seconds, and never writes a fraction, so a duration of zero is `0s` and
/// 125 seconds is `2m5s`.
fn format_go_duration(nanoseconds: i128) -> String {
    let negative = nanoseconds < 0;
    let total_seconds = nanoseconds.unsigned_abs() / 1_000_000_000;
    let hours = total_seconds / 3_600;
    let minutes = total_seconds / 60 % 60;
    let seconds = total_seconds % 60;
    let mut output = String::new();
    if negative {
        output.push('-');
    }
    if hours > 0 {
        let _ = write!(output, "{hours}h");
    }
    if minutes > 0 || hours > 0 {
        let _ = write!(output, "{minutes}m");
    }
    let _ = write!(output, "{seconds}s");
    output
}

/// Reads a count of 100-nanosecond ticks as the reference's `FromTicks` does.
///
/// The reference divides the count by 100 and multiplies by a tick, which is a
/// count of nanoseconds truncated to a whole tick.
fn count_ticks(count: f64) -> i128 {
    let ticks = if count.is_finite() {
        count.trunc().clamp(i64::MIN as f64, i64::MAX as f64) as i64
    } else {
        0
    };
    i128::from(ticks / 100) * 100
}

/// Renders a whole number without a fractional part.
fn whole(value: f64) -> i64 {
    if value.is_finite() {
        value.clamp(i64::MIN as f64, i64::MAX as f64) as i64
    } else {
        0
    }
}

/// Renders an offset the way the reference's translated layouts do.
///
/// The reference turns Go's `-0700` into .NET's `zzzz`, which prints the offset
/// with a colon, and that is what the parity fixture expects. The same text is
/// used for `MST`, which the reference turns into .NET's `zzz` and which for a
/// `DateTimeOffset` is this same numeric offset.
fn format_offset(offset: i32) -> String {
    let sign = if offset < 0 { '-' } else { '+' };
    let magnitude = offset.unsigned_abs();
    format!("{sign}{:02}:{:02}", magnitude / 3_600, magnitude / 60 % 60)
}

/// A moment in time, with the offset it is written in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Instant {
    /// Seconds since the Unix epoch, in UTC.
    seconds: i64,
    /// The sub-second remainder, in nanoseconds.
    nanoseconds: u32,
    /// Seconds east of UTC this instant is written in.
    offset: i32,
}

impl Instant {
    /// The current time, in UTC.
    fn now() -> Self {
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            seconds: i64::try_from(since_epoch.as_secs()).unwrap_or(i64::MAX),
            nanoseconds: since_epoch.subsec_nanos(),
            offset: 0,
        }
    }

    /// The same moment, written in another offset.
    ///
    /// The epoch seconds do not change: only the offset the civil fields are
    /// read in does, which is what a zone conversion is.
    fn in_offset(&self, offset: i32) -> Self {
        Self { offset, ..*self }
    }

    /// This instant shifted by a signed number of nanoseconds.
    ///
    /// # Errors
    ///
    /// Returns an error when the shift leaves the range of a date, which is
    /// what the reference's `DateTimeOffset.Add` throws for.
    fn add_nanoseconds(&self, helper: &str, nanoseconds: i128) -> Result<Self, Error> {
        let total =
            i128::from(self.seconds) * 1_000_000_000 + i128::from(self.nanoseconds) + nanoseconds;
        let seconds = total.div_euclid(1_000_000_000);
        let remainder = total.rem_euclid(1_000_000_000);
        let seconds =
            i64::try_from(seconds).map_err(|_| crate::invalid(helper, "a date within range"))?;
        let civil = Civil::of(Instant {
            seconds,
            nanoseconds: u32::try_from(remainder).unwrap_or(0),
            offset: self.offset,
        });
        if !(1..=9_999).contains(&civil.year) {
            return Err(crate::invalid(helper, "a date within range"));
        }
        Ok(Self {
            seconds,
            nanoseconds: u32::try_from(remainder).unwrap_or(0),
            offset: self.offset,
        })
    }

    /// The signed number of nanoseconds from `other` to this instant.
    fn nanoseconds_since(&self, other: &Self) -> i128 {
        i128::from(self.seconds - other.seconds) * 1_000_000_000 + i128::from(self.nanoseconds)
            - i128::from(other.nanoseconds)
    }

    /// The calendar fields of this instant in its own offset.
    fn civil(&self) -> Civil {
        Civil::of(*self)
    }

    /// The instant the reference's `ToString("O")` produces.
    ///
    /// Seven fractional digits, because .NET's round-trip format writes the
    /// resolution of a `DateTimeOffset` rather than the resolution of the
    /// value, and an offset with a colon.
    fn round_trip(&self) -> String {
        let civil = self.civil();
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:07}{}",
            civil.year,
            civil.month,
            civil.day,
            civil.hour,
            civil.minute,
            civil.second,
            self.nanoseconds / 100,
            format_offset(self.offset)
        )
    }
}

/// Renders an instant in the reference's round-trip spelling.
fn format_round_trip(instant: &Instant) -> String {
    instant.round_trip()
}

/// The calendar fields of an instant.
struct Civil {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    nanoseconds: u32,
    /// The day of the week, with Sunday first.
    weekday: usize,
    /// The day of the year, counting from one.
    year_day: u32,
}

impl Civil {
    /// The fields of an instant, read in its own offset.
    fn of(instant: Instant) -> Self {
        let local = instant.seconds + i64::from(instant.offset);
        let days = local.div_euclid(86_400);
        let seconds = local.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        // 1970-01-01 was a Thursday, which is index 4 with Sunday first.
        let weekday = (days + 4).rem_euclid(7) as usize;
        let first_of_year = days_from_civil(year, 1, 1);
        Self {
            year,
            month,
            day,
            hour: (seconds / 3_600) as u32,
            minute: (seconds / 60 % 60) as u32,
            second: (seconds % 60) as u32,
            nanoseconds: instant.nanoseconds,
            weekday,
            year_day: u32::try_from(days - first_of_year + 1).unwrap_or(1),
        }
    }
}

/// The days since 1970-01-01 for a date in the proleptic Gregorian calendar.
///
/// This is Howard Hinnant's `days_from_civil`, which is exact for every year a
/// `DateTimeOffset` can hold and needs no lookup table.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_position = (i64::from(month) + 9) % 12;
    let day_of_year = (153 * month_position + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The date for a count of days since 1970-01-01.
///
/// The inverse of [`days_from_civil`], by the same algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_position = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_position + 2) / 5 + 1;
    let month = if month_position < 10 {
        month_position + 3
    } else {
        month_position - 9
    };
    (
        if month <= 2 { year + 1 } else { year },
        month as u32,
        day as u32,
    )
}

/// Reports whether a year is a leap year in the proleptic Gregorian calendar.
fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// The number of days in a month.
fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Parses a time the way the reference's `ParseDate` does.
///
/// A value that reads as an integer is a count of seconds since the epoch, as
/// the reference's `long.TryParse` then `FromUnixTimeSeconds` does. Anything
/// else is read as ISO 8601 — a date, an optional time with an optional
/// fraction, and an optional offset — and a value with no offset is treated as
/// UTC, which is the reference's `DateTimeStyles.AssumeUniversal`.
///
/// The reference parses with `DateTimeOffset.Parse`, which also accepts a dozen
/// other spellings; the ones here are the ones an ISO 8601 timestamp and the
/// reference's own round-trip output use, and both of those are covered.
fn parse_date(helper: &str, value: &str) -> Result<Instant, Error> {
    parse(value).ok_or_else(|| crate::invalid(helper, format!("cannot read {value:?} as a date")))
}

/// The month and day a day-of-the-year names, which is what a `002` layout
/// reads.
fn month_and_day_of_year(year: i64, year_day: u32) -> Option<(u32, u32)> {
    let mut remaining = year_day;
    for month in 1..=12 {
        let length = days_in_month(year, month);
        if remaining <= length {
            return Some((month, remaining));
        }
        remaining -= length;
    }
    None
}

/// Parses a time, or returns nothing when it is not one.
fn parse(value: &str) -> Option<Instant> {
    let text = value.trim();
    if text.is_empty() {
        return None;
    }
    if let Ok(seconds) = text.parse::<i64>() {
        return build(seconds, 0, 0);
    }
    parse_iso(text)
}

/// Builds an instant from its parts, refusing a date no offset can hold.
fn build(seconds: i64, nanoseconds: u32, offset: i32) -> Option<Instant> {
    let instant = Instant {
        seconds,
        nanoseconds,
        offset,
    };
    let year = Civil::of(instant).year;
    if (1..=9_999).contains(&year) {
        Some(instant)
    } else {
        None
    }
}

/// Parses an ISO 8601 date, with an optional time and offset.
fn parse_iso(text: &str) -> Option<Instant> {
    let bytes = text.as_bytes();
    let mut index = 0;
    let (year, month, day) = parse_iso_date(bytes, &mut index)?;

    let mut hour = 0;
    let mut minute = 0;
    let mut second = 0;
    let mut nanoseconds = 0;
    if index < bytes.len() {
        if !matches!(bytes[index], b'T' | b't' | b' ') {
            return None;
        }
        index += 1;
        let parsed = parse_iso_time(bytes, &mut index)?;
        hour = parsed.0;
        minute = parsed.1;
        second = parsed.2;
        nanoseconds = parsed.3;
    }

    let mut offset = 0;
    if index < bytes.len() {
        match bytes[index] {
            b'Z' | b'z' => index += 1,
            b'+' | b'-' => {
                let sign = if bytes[index] == b'-' { -1 } else { 1 };
                index += 1;
                offset = sign * parse_iso_offset(bytes, &mut index)?;
            }
            _ => return None,
        }
    }
    if index != bytes.len() {
        return None;
    }

    let days = days_from_civil(year, month, day);
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3_600)?
        .checked_add(i64::from(minute) * 60)?
        .checked_add(i64::from(second))?
        .checked_sub(i64::from(offset))?;
    build(seconds, nanoseconds, offset)
}

/// Parses a date, in either `YYYY-MM-DD` or the invariant `M/d/yyyy`.
///
/// .NET's invariant culture writes a short date as `M/d/yyyy`, and
/// `DateTimeOffset.Parse` accepts it, so a template that writes a date that way
/// keeps working.
fn parse_iso_date(bytes: &[u8], index: &mut usize) -> Option<(i64, u32, u32)> {
    let start = *index;
    // The year first: four digits, then a separator, then the month and day.
    if let Some(year) = read_number(bytes, index, 4, 4) {
        if matches!(bytes.get(*index), Some(b'-' | b'/')) {
            *index += 1;
            let month = read_number(bytes, index, 1, 2)?;
            if !matches!(bytes.get(*index), Some(b'-' | b'/')) {
                return None;
            }
            *index += 1;
            let day = read_number(bytes, index, 1, 2)?;
            return checked_date(year, month, day);
        }
        // A year with no separator after it is not this shape, so the cursor
        // goes back and the short form is tried.
        *index = start;
    }
    // Otherwise the year comes last, as the invariant culture writes it.
    let month = read_number(bytes, index, 1, 2)?;
    if bytes.get(*index) != Some(&b'/') {
        return None;
    }
    *index += 1;
    let day = read_number(bytes, index, 1, 2)?;
    if bytes.get(*index) != Some(&b'/') {
        return None;
    }
    *index += 1;
    let year = read_number(bytes, index, 4, 4)?;
    checked_date(year, month, day)
}

/// Reads a date and rejects one that is not a real day.
fn checked_date(year: i64, month: i64, day: i64) -> Option<(i64, u32, u32)> {
    if !(1..=12).contains(&month) {
        return None;
    }
    let month = u32::try_from(month).ok()?;
    if day < 1 || day > i64::from(days_in_month(year, month)) {
        return None;
    }
    Some((year, month, u32::try_from(day).ok()?))
}

/// Parses a time of day, with an optional fraction.
fn parse_iso_time(bytes: &[u8], index: &mut usize) -> Option<(u32, u32, u32, u32)> {
    let hour = read_number(bytes, index, 1, 2)?;
    if bytes.get(*index) != Some(&b':') {
        return None;
    }
    *index += 1;
    let minute = read_number(bytes, index, 1, 2)?;
    let mut second = 0;
    let mut nanoseconds = 0;
    if bytes.get(*index) == Some(&b':') {
        *index += 1;
        second = read_number(bytes, index, 1, 2)?;
        if bytes.get(*index) == Some(&b'.') {
            *index += 1;
            let first = *index;
            while matches!(bytes.get(*index), Some(byte) if byte.is_ascii_digit()) {
                *index += 1;
            }
            if *index == first {
                return None;
            }
            // Nine digits is a nanosecond, which is more than the reference
            // keeps; the rest are rounded away.
            let mut fraction = String::from_utf8_lossy(&bytes[first..*index]).into_owned();
            fraction.truncate(9);
            while fraction.len() < 9 {
                fraction.push('0');
            }
            nanoseconds = fraction.parse::<u32>().ok()?;
        }
    }
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some((
        u32::try_from(hour).ok()?,
        u32::try_from(minute).ok()?,
        u32::try_from(second).ok()?,
        nanoseconds,
    ))
}

/// Parses a zone offset, in seconds.
fn parse_iso_offset(bytes: &[u8], index: &mut usize) -> Option<i32> {
    let hours = read_number(bytes, index, 1, 2)?;
    let mut minutes = 0;
    if bytes.get(*index) == Some(&b':') {
        *index += 1;
        minutes = read_number(bytes, index, 2, 2)?;
    } else if matches!(bytes.get(*index), Some(byte) if byte.is_ascii_digit()) {
        minutes = read_number(bytes, index, 2, 2)?;
    }
    if hours > 23 || minutes > 59 {
        return None;
    }
    i32::try_from(hours * 3_600 + minutes * 60).ok()
}

/// Reads a number of between `min` and `max` digits.
///
/// A shorter run than `min` leaves the cursor where it was and reads as nothing,
/// so a caller can try one shape of a field and fall back to another.
fn read_number(bytes: &[u8], index: &mut usize, min: usize, max: usize) -> Option<i64> {
    let start = *index;
    let mut digits = 0;
    let mut value: i64 = 0;
    while digits < max {
        let Some(byte) = bytes.get(*index) else { break };
        if !byte.is_ascii_digit() {
            break;
        }
        value = value.checked_mul(10)?.checked_add(i64::from(byte - b'0'))?;
        *index += 1;
        digits += 1;
    }
    if digits < min {
        *index = start;
        return None;
    }
    Some(value)
}

/// Resolves a zone name to a fixed offset, in seconds.
///
/// `UTC` and its spellings are zero, and a numeric offset is itself. Anything
/// else falls back to UTC, which is what the reference does when
/// `TimeZoneInfo.FindSystemTimeZoneById` throws. A named zone therefore resolves
/// to UTC here; see the module documentation.
fn zone_offset(zone: &str) -> i32 {
    let trimmed = zone.trim();
    if trimmed.is_empty() {
        return 0;
    }
    if matches!(
        trimmed.to_ascii_uppercase().as_str(),
        "UTC" | "GMT" | "Z" | "ZULU" | "UNIVERSAL" | "ETC/UTC" | "ETC/GMT" | "UTC+0" | "UTC-0"
    ) {
        return 0;
    }
    if let Some(offset) = parse_numeric_zone(trimmed) {
        return offset;
    }
    0
}

/// Parses a numeric zone such as `+05:30`, `-0800`, or `+9`.
fn parse_numeric_zone(zone: &str) -> Option<i32> {
    let bytes = zone.as_bytes();
    let sign = match bytes.first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let mut index = 1;
    let hours = read_number(bytes, &mut index, 1, 2)?;
    let mut minutes = 0;
    if bytes.get(index) == Some(&b':') {
        index += 1;
        minutes = read_number(bytes, &mut index, 2, 2)?;
    } else if matches!(bytes.get(index), Some(byte) if byte.is_ascii_digit()) {
        minutes = read_number(bytes, &mut index, 2, 2)?;
    }
    if index != bytes.len() || hours > 23 || minutes > 59 {
        return None;
    }
    i32::try_from(sign * (hours * 3_600 + minutes * 60)).ok()
}

/// Parses a duration in Go's spelling, in nanoseconds.
///
/// This is the reference's `ParseDuration`, which requires the whole text to be
/// a run of number-and-unit pairs: a bare number is not a duration, and a stray
/// character makes the whole thing invalid. `support::parse_duration` is
/// deliberately more forgiving — it reads a bare number as nanoseconds — and
/// using it here would make `durationRound "61"` a nanosecond count where the
/// reference says `0s`, so the rules are reproduced here instead.
///
/// The arithmetic is exact: a pair contributes its digits scaled by its unit as
/// a whole number of nanoseconds, so `1.5h` is exactly `5400000000000` and
/// `24h` is exactly `86400000000000`. The result is truncated to a whole
/// 100-nanosecond tick, which is the resolution the reference's `TimeSpan`
/// has.
fn parse_go_duration(value: &str) -> Option<i128> {
    let negative = value.starts_with('-');
    let text = value.strip_prefix(['+', '-']).unwrap_or(value);
    let mut total: i128 = 0;
    let mut rest = text;
    while !rest.is_empty() {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        let mut number_end = digits;
        let mut fraction_digits = 0;
        if rest[digits..].starts_with('.') {
            fraction_digits = rest[digits + 1..]
                .bytes()
                .take_while(u8::is_ascii_digit)
                .count();
            if fraction_digits == 0 {
                return None;
            }
            number_end = digits + 1 + fraction_digits;
        }
        let (number, tail) = rest.split_at(number_end);
        // The reference's alternation is `ns|us|µs|ms|s|m|h`, so the two-letter
        // units have to be tried before the one-letter ones they start with.
        let unit = ["ns", "us", "µs", "μs", "ms", "s", "m", "h"]
            .into_iter()
            .find(|unit| tail.starts_with(unit))?;
        let scale = match unit {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60 * 1_000_000_000,
            _ => 3_600 * 1_000_000_000,
        };
        total += scale_digits(number, fraction_digits, scale)?;
        rest = &tail[unit.len()..];
    }
    if text.is_empty() {
        return None;
    }
    // A `TimeSpan` counts ticks, so the reference truncates toward zero here.
    total -= total % 100;
    Some(if negative { -total } else { total })
}

/// Scales a decimal number written as digits and a fraction length to
/// nanoseconds.
fn scale_digits(number: &str, fraction_digits: usize, scale: i128) -> Option<i128> {
    let digits: i128 = number
        .chars()
        .filter(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .ok()?;
    if fraction_digits == 0 {
        return digits.checked_mul(scale);
    }
    if fraction_digits > 30 {
        return None;
    }
    // The digits include the fraction, so a number written as `1.5` arrives as
    // `15` with one fractional digit, and its value is `15 * scale / 10`.
    let divisor = 10_i128.checked_pow(u32::try_from(fraction_digits).ok()?)?;
    digits.checked_mul(scale)?.checked_div(divisor)
}

/// A piece of a layout, which is one of Go's reference-time elements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Chunk {
    Year,
    ShortYear,
    YearDay,
    LongMonth,
    ShortMonth,
    Month,
    MonthPadded,
    LongWeekday,
    ShortWeekday,
    Day,
    DayPadded,
    DaySpace,
    Hour24,
    Hour12,
    Hour12Padded,
    Minute,
    MinutePadded,
    Second,
    SecondPadded,
    UpperMeridiem,
    LowerMeridiem,
    /// A zone offset with a colon, which is what the reference prints for both
    /// of Go's `-0700` and `MST`.
    Offset,
    /// `Z0700` and `Z07:00`, which print `Z` at a zero offset.
    ZoneIso,
    /// A fixed number of fractional-second digits, as `.000` does.
    Fraction(u32),
    /// Up to that many fractional-second digits with the zeros trimmed, as
    /// `.999` does.
    TrimmedFraction(u32),
}

/// The layout elements, longest first at every position.
///
/// Go's own `time` package looks these up in this order, and the order is what
/// makes `2006` a year rather than a `2` followed by a `006`, and `15` an hour
/// rather than a `1` followed by a `5`.
const CHUNKS: [(&str, Chunk); 25] = [
    ("Monday", Chunk::LongWeekday),
    ("January", Chunk::LongMonth),
    ("Mon", Chunk::ShortWeekday),
    ("Jan", Chunk::ShortMonth),
    ("MST", Chunk::Offset),
    ("PM", Chunk::UpperMeridiem),
    ("pm", Chunk::LowerMeridiem),
    ("Z07:00", Chunk::ZoneIso),
    ("Z0700", Chunk::ZoneIso),
    ("-07:00", Chunk::Offset),
    ("-070000", Chunk::Offset),
    ("-0700", Chunk::Offset),
    ("2006", Chunk::Year),
    ("002", Chunk::YearDay),
    ("01", Chunk::MonthPadded),
    ("02", Chunk::DayPadded),
    ("03", Chunk::Hour12Padded),
    ("04", Chunk::MinutePadded),
    ("05", Chunk::SecondPadded),
    ("06", Chunk::ShortYear),
    ("15", Chunk::Hour24),
    ("_2", Chunk::DaySpace),
    ("1", Chunk::Month),
    ("2", Chunk::Day),
    ("3", Chunk::Hour12),
];

/// The two single-letter elements, kept out of the table so it stays a fixed
/// size: `4` is a minute and `5` is a second.
fn single_chunk(text: &str) -> Option<(Chunk, usize)> {
    match text.as_bytes().first()? {
        b'4' => Some((Chunk::Minute, 1)),
        b'5' => Some((Chunk::Second, 1)),
        _ => None,
    }
}

/// The next layout element at the start of `text`, with its length.
///
/// A `.` followed by a run of `0`s or a run of `9`s is a fractional second, and
/// nothing else beginning with a `.` is, which is how `time` distinguishes a
/// fraction from a literal point.
fn next_chunk(text: &str) -> Option<(Chunk, usize)> {
    for (element, chunk) in CHUNKS {
        if text.starts_with(element) {
            return Some((chunk, element.len()));
        }
    }
    if let Some(fraction) = text.strip_prefix('.') {
        let zeros = fraction.bytes().take_while(|byte| *byte == b'0').count();
        if zeros > 0 {
            return Some((Chunk::Fraction(u32::try_from(zeros).ok()?), 1 + zeros));
        }
        let nines = fraction.bytes().take_while(|byte| *byte == b'9').count();
        if nines > 0 {
            return Some((
                Chunk::TrimmedFraction(u32::try_from(nines).ok()?),
                1 + nines,
            ));
        }
    }
    single_chunk(text)
}

/// Renders an instant through a layout.
fn format_layout(layout: &str, instant: &Instant) -> String {
    let civil = instant.civil();
    let mut output = String::with_capacity(layout.len() + 8);
    let mut rest = layout;
    while !rest.is_empty() {
        if let Some((chunk, length)) = next_chunk(rest) {
            output.push_str(&render_chunk(chunk, &civil, instant));
            rest = &rest[length..];
            continue;
        }
        let character = rest
            .chars()
            .next()
            .expect("a non-empty remainder has a first character");
        output.push(character);
        rest = &rest[character.len_utf8()..];
    }
    output
}

/// Renders one layout element.
fn render_chunk(chunk: Chunk, civil: &Civil, instant: &Instant) -> String {
    let month = usize::try_from(civil.month).unwrap_or(1).saturating_sub(1);
    match chunk {
        Chunk::Year => format!("{:04}", civil.year),
        Chunk::ShortYear => format!("{:02}", civil.year.rem_euclid(100)),
        Chunk::YearDay => format!("{:03}", civil.year_day),
        Chunk::LongMonth => MONTHS[month.min(11)].0.to_owned(),
        Chunk::ShortMonth => MONTHS[month.min(11)].1.to_owned(),
        Chunk::Month => civil.month.to_string(),
        Chunk::MonthPadded => format!("{:02}", civil.month),
        Chunk::LongWeekday => WEEKDAYS[civil.weekday % 7].0.to_owned(),
        Chunk::ShortWeekday => WEEKDAYS[civil.weekday % 7].1.to_owned(),
        Chunk::Day => civil.day.to_string(),
        Chunk::DayPadded => format!("{:02}", civil.day),
        Chunk::DaySpace => format!("{:2}", civil.day),
        Chunk::Hour24 => format!("{:02}", civil.hour),
        Chunk::Hour12 => format!("{}", hour12(civil.hour)),
        Chunk::Hour12Padded => format!("{:02}", hour12(civil.hour)),
        Chunk::Minute => civil.minute.to_string(),
        Chunk::MinutePadded => format!("{:02}", civil.minute),
        Chunk::Second => civil.second.to_string(),
        Chunk::SecondPadded => format!("{:02}", civil.second),
        Chunk::UpperMeridiem => meridiem(civil.hour).to_owned(),
        Chunk::LowerMeridiem => meridiem(civil.hour).to_ascii_lowercase(),
        Chunk::Offset => format_offset(instant.offset),
        Chunk::ZoneIso => {
            if instant.offset == 0 {
                "Z".to_owned()
            } else {
                format_offset(instant.offset)
            }
        }
        Chunk::Fraction(digits) => {
            let fraction = fraction_digits(civil.nanoseconds, digits);
            format!(".{fraction}")
        }
        Chunk::TrimmedFraction(digits) => {
            let fraction = fraction_digits(civil.nanoseconds, digits);
            let trimmed = fraction.trim_end_matches('0');
            if trimmed.is_empty() {
                String::new()
            } else {
                format!(".{trimmed}")
            }
        }
    }
}

/// The hour on a twelve-hour clock, where midnight and noon are both twelve.
fn hour12(hour: u32) -> u32 {
    match hour % 12 {
        0 => 12,
        other => other,
    }
}

/// Whether an hour is before noon, as `AM` and `PM` report it.
fn meridiem(hour: u32) -> &'static str {
    if hour < 12 { "AM" } else { "PM" }
}

/// Renders nanoseconds as a fixed number of digits.
fn fraction_digits(nanoseconds: u32, digits: u32) -> String {
    let width = usize::try_from(digits).unwrap_or(9);
    let mut text = format!("{nanoseconds:09}");
    text.truncate(width);
    while text.len() < width {
        text.insert(0, '0');
    }
    text
}

/// Parses a time with a layout, exactly.
///
/// The whole value has to be described by the layout, which is what the
/// reference's `TryParseExact` against the translated layout requires: a layout
/// of `2006-01-02` parses `2017-12-31` and nothing else. A layout element with
/// no zone leaves the result at UTC, which is `AssumeUniversal`.
fn parse_with_layout(layout: &str, value: &str) -> Option<Instant> {
    let mut reader = Reader {
        bytes: value.as_bytes(),
        index: 0,
    };
    let mut fields = Fields::default();

    let mut rest = layout;
    while !rest.is_empty() {
        if let Some((chunk, length)) = next_chunk(rest) {
            rest = &rest[length..];
            read_chunk(chunk, &mut reader, &mut fields)?;
            continue;
        }
        // Anything that is not a layout element is literal text, and has to be
        // in the value as it stands.
        let character = rest
            .chars()
            .next()
            .expect("a non-empty remainder has a first character");
        rest = &rest[character.len_utf8()..];
        if reader.byte() != Some(character as u8) || !character.is_ascii() {
            return None;
        }
        reader.index += 1;
    }
    if reader.index != reader.bytes.len() {
        return None;
    }
    fields.into_instant()
}

/// The fields a layout element can fill in.
#[derive(Default)]
struct Fields {
    year: Option<i64>,
    month: Option<u32>,
    day: Option<u32>,
    year_day: Option<u32>,
    hour: u32,
    minute: u32,
    second: u32,
    nanoseconds: u32,
    /// Whether the layout read `PM` rather than `AM`.
    afternoon: Option<bool>,
    offset: Option<i32>,
}

impl Fields {
    /// Assembles the instant the fields name, or nothing when they do not name
    /// one.
    ///
    /// A layout with no year, or with a month but no day, names no date. A
    /// layout with no zone leaves the result at UTC, which is the reference's
    /// `AssumeUniversal`.
    fn into_instant(self) -> Option<Instant> {
        let year = self.year?;
        let (month, day) = match (self.month, self.year_day) {
            // A day of the year and a day of the month cannot both be written,
            // and the day of the year alone has to be resolved against the year.
            (Some(month), Some(_)) => (month, self.day.unwrap_or(1)),
            (Some(month), None) => (month, self.day?),
            (None, Some(year_day)) => month_and_day_of_year(year, year_day)?,
            (None, None) => return None,
        };
        let (year, month, day) = checked_date(year, i64::from(month), i64::from(day))?;
        if self.minute > 59 || self.second > 59 {
            return None;
        }
        let hour = match self.afternoon {
            // A twelve-hour layout reads 1 through 12, where twelve is midnight
            // or noon depending on which half of the day it is in.
            Some(afternoon) => {
                if !(1..=12).contains(&self.hour) {
                    return None;
                }
                match (afternoon, self.hour) {
                    (true, 12) => 12,
                    (true, other) => other + 12,
                    (false, 12) => 0,
                    (false, other) => other,
                }
            }
            None if self.hour > 23 => return None,
            None => self.hour,
        };
        let offset = self.offset.unwrap_or(0);
        let seconds = days_from_civil(year, month, day)
            .checked_mul(86_400)?
            .checked_add(i64::from(hour) * 3_600)?
            .checked_add(i64::from(self.minute) * 60)?
            .checked_add(i64::from(self.second))?
            .checked_sub(i64::from(offset))?;
        build(seconds, self.nanoseconds, offset)
    }
}

/// Reads one layout element out of the value.
fn read_chunk(chunk: Chunk, reader: &mut Reader<'_>, fields: &mut Fields) -> Option<()> {
    match chunk {
        Chunk::Year => fields.year = Some(reader.number(4, 4)?),
        Chunk::ShortYear => fields.year = Some(reader.number(2, 2)?),
        Chunk::YearDay => fields.year_day = Some(u32::try_from(reader.number(3, 3)?).ok()?),
        Chunk::LongMonth => fields.month = Some(reader.month(MONTHS.iter().map(|m| m.0))?),
        Chunk::ShortMonth => fields.month = Some(reader.month(MONTHS.iter().map(|m| m.1))?),
        Chunk::Month | Chunk::MonthPadded => {
            fields.month = Some(u32::try_from(reader.number(1, 2)?).ok()?);
        }
        Chunk::LongWeekday => {
            // A weekday names no part of the instant, so it is read and dropped,
            // as `DateTimeOffset.TryParseExact` against `dddd` does.
            reader.weekday(WEEKDAYS.iter().map(|day| day.0))?;
        }
        Chunk::ShortWeekday => {
            reader.weekday(WEEKDAYS.iter().map(|day| day.1))?;
        }
        Chunk::Day | Chunk::DayPadded => {
            fields.day = Some(u32::try_from(reader.number(1, 2)?).ok()?);
        }
        Chunk::DaySpace => {
            if reader.byte() == Some(b' ') {
                reader.index += 1;
            }
            fields.day = Some(u32::try_from(reader.number(1, 2)?).ok()?);
        }
        // The padded and unpadded forms of the hour, the minute, and the second
        // read the same digits; only the rendering differs, and a layout is not
        // rendered here.
        Chunk::Hour24 | Chunk::Hour12 | Chunk::Hour12Padded => {
            fields.hour = u32::try_from(reader.number(1, 2)?).ok()?;
        }
        Chunk::Minute | Chunk::MinutePadded => {
            fields.minute = u32::try_from(reader.number(1, 2)?).ok()?;
        }
        Chunk::Second | Chunk::SecondPadded => {
            fields.second = u32::try_from(reader.number(1, 2)?).ok()?;
        }
        Chunk::UpperMeridiem | Chunk::LowerMeridiem => {
            // Either spelling of the element reads the same text, as .NET's own
            // `tt` does.
            fields.afternoon = Some(reader.meridiem()?);
        }
        Chunk::Offset | Chunk::ZoneIso => {
            fields.offset = Some(reader.offset(chunk == Chunk::ZoneIso)?);
        }
        Chunk::Fraction(digits) => fields.nanoseconds = reader.fraction(digits)?,
        Chunk::TrimmedFraction(digits) => fields.nanoseconds = reader.trimmed_fraction(digits)?,
    }
    Some(())
}

/// A cursor over the value a layout is read against.
struct Reader<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl Reader<'_> {
    /// The byte at the cursor.
    fn byte(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    /// Reads a number of between `min` and `max` digits.
    fn number(&mut self, min: usize, max: usize) -> Option<i64> {
        let start = self.index;
        let mut value: i64 = 0;
        let mut digits = 0;
        while digits < max {
            let byte = *self.bytes.get(self.index)?;
            if !byte.is_ascii_digit() {
                break;
            }
            value = value.checked_mul(10)?.checked_add(i64::from(byte - b'0'))?;
            self.index += 1;
            digits += 1;
        }
        if digits < min {
            self.index = start;
            return None;
        }
        Some(value)
    }

    /// Reads a month name, ignoring case as .NET's `MMMM` does.
    fn month(&mut self, names: impl Iterator<Item = &'static str>) -> Option<u32> {
        let start = self.index;
        while matches!(self.byte(), Some(byte) if byte.is_ascii_alphabetic()) {
            self.index += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.index]).ok()?;
        let found = names
            .enumerate()
            .find(|(_, name)| name.eq_ignore_ascii_case(text))
            .map(|(index, _)| index + 1);
        if found.is_none() {
            self.index = start;
        }
        u32::try_from(found?).ok()
    }

    /// Reads a weekday name, whose value is not used.
    fn weekday(&mut self, names: impl Iterator<Item = &'static str>) -> Option<u32> {
        let start = self.index;
        while matches!(self.byte(), Some(byte) if byte.is_ascii_alphabetic()) {
            self.index += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.index]).ok()?;
        if names
            .into_iter()
            .any(|name| name.eq_ignore_ascii_case(text))
        {
            Some(0)
        } else {
            self.index = start;
            None
        }
    }

    /// Reads `AM` or `PM`, reporting whether it is the afternoon half.
    fn meridiem(&mut self) -> Option<bool> {
        let start = self.index;
        while matches!(self.byte(), Some(byte) if byte.is_ascii_alphabetic()) {
            self.index += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.index]).ok()?;
        // Either case is accepted for either spelling of the layout element, as
        // .NET's own `tt` does.
        match text.to_ascii_lowercase().as_str() {
            "am" => Some(false),
            "pm" => Some(true),
            _ => {
                self.index = start;
                None
            }
        }
    }

    /// Reads a zone offset, optionally as `Z`.
    fn offset(&mut self, allows_z: bool) -> Option<i32> {
        match self.byte() {
            Some(b'Z' | b'z') if allows_z => {
                self.index += 1;
                Some(0)
            }
            Some(b'+' | b'-') => {
                let sign: i64 = if self.byte() == Some(b'-') { -1 } else { 1 };
                self.index += 1;
                let hours = self.number(2, 2)?;
                let mut minutes = 0;
                if self.byte() == Some(b':') {
                    self.index += 1;
                    minutes = self.number(2, 2)?;
                }
                i32::try_from(sign * (hours * 3_600 + minutes * 60)).ok()
            }
            _ => None,
        }
    }

    /// Reads a fraction of a second with a fixed number of digits.
    fn fraction(&mut self, digits: u32) -> Option<u32> {
        if self.byte() != Some(b'.') {
            return None;
        }
        self.index += 1;
        let width = usize::try_from(digits).ok()?;
        let start = self.index;
        for _ in 0..width {
            let byte = *self.bytes.get(self.index)?;
            if !byte.is_ascii_digit() {
                return None;
            }
            self.index += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.index]).ok()?;
        let mut scaled = String::from(text);
        while scaled.len() < 9 {
            scaled.push('0');
        }
        scaled.truncate(9);
        scaled.parse::<u32>().ok()
    }

    /// Reads a fraction of a second of up to that many digits.
    fn trimmed_fraction(&mut self, digits: u32) -> Option<u32> {
        if self.byte() != Some(b'.') {
            return None;
        }
        self.index += 1;
        let start = self.index;
        for _ in 0..digits {
            match self.byte() {
                Some(byte) if byte.is_ascii_digit() => self.index += 1,
                _ => break,
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.index]).ok()?;
        let mut scaled = text.to_owned();
        while scaled.len() < 9 {
            scaled.push('0');
        }
        scaled.truncate(9);
        scaled.parse::<u32>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_LAYOUT, DISPATCH, MINIMUM_DATE, format_go_duration, parse_go_duration,
        takes_rendered_strings, zone_offset,
    };
    use crate::{Context, Error, Value};

    /// Calls the dispatch table the way `lib.rs` does, unwrapping `Some`.
    fn call(name: &str, arguments: &[Value]) -> Result<Value, Error> {
        let context = Context::default();
        DISPATCH(name, arguments, &context).expect("the module claims the name")
    }

    /// Renders a one-argument helper over a string.
    fn one(name: &str, value: &str) -> String {
        call(name, &[Value::String(value.to_owned())])
            .unwrap_or_else(|error| panic!("{name} {value:?}: {error}"))
            .render()
    }

    /// Calls a one-argument helper and hands back the result, so that a test
    /// can look at the error rather than at the value.
    fn try_one(name: &str, value: &str) -> Result<Value, Error> {
        call(name, &[Value::String(value.to_owned())])
    }

    /// Renders a two-argument helper over two strings.
    fn two(name: &str, first: &str, second: &str) -> String {
        call(
            name,
            &[
                Value::String(first.to_owned()),
                Value::String(second.to_owned()),
            ],
        )
        .unwrap_or_else(|error| panic!("{name} {first:?} {second:?}: {error}"))
        .render()
    }

    /// Renders a three-argument helper.
    fn three(name: &str, arguments: &[&str]) -> String {
        call(
            name,
            &arguments
                .iter()
                .map(|value| Value::String((*value).to_owned()))
                .collect::<Vec<_>>(),
        )
        .unwrap_or_else(|error| panic!("{name} {arguments:?}: {error}"))
        .render()
    }

    #[test]
    fn the_module_claims_only_its_own_helpers() {
        let context = Context::default();
        for name in [
            "now",
            "date",
            "dateInZone",
            "date_in_zone",
            "dateModify",
            "date_modify",
            "mustDateModify",
            "must_date_modify",
            "htmlDate",
            "htmlDateInZone",
            "toDate",
            "mustToDate",
            "mustToDate",
            "ago",
            "duration",
            "durationRound",
            "unixEpoch",
        ] {
            assert!(DISPATCH(name, &[], &context).is_some(), "{name}");
        }
        for name in ["trim", "env", "semver", "urlParse", "dateFormat"] {
            assert!(DISPATCH(name, &[], &context).is_none(), "{name}");
        }
    }

    #[test]
    fn the_snake_case_and_camel_case_spellings_are_the_same_helper() {
        // The reference registers `dateInZone` and `date_in_zone` as two names
        // for one method, and the same for the `must` and modify pairs.
        let arguments = [
            Value::String("2006-01-02".to_owned()),
            Value::String("2019-06-13T20:39:39Z".to_owned()),
            Value::String("UTC".to_owned()),
        ];
        assert_eq!(
            call("dateInZone", &arguments),
            call("date_in_zone", &arguments)
        );
        let modify = [
            Value::String("1h".to_owned()),
            Value::String("2019-06-13T20:39:39Z".to_owned()),
        ];
        assert_eq!(call("dateModify", &modify), call("date_modify", &modify));
        assert_eq!(
            call("mustDateModify", &modify),
            call("must_date_modify", &modify)
        );
        let to_date = [
            Value::String("2006-01-02".to_owned()),
            Value::String("2017-12-31".to_owned()),
        ];
        assert!(call("mustToDate", &to_date).is_ok());
    }

    #[test]
    fn no_helper_wants_rendered_arguments() {
        for name in [
            "now",
            "date",
            "dateInZone",
            "htmlDate",
            "htmlDateInZone",
            "dateModify",
            "mustDateModify",
            "toDate",
            "mustToDate",
            "ago",
            "duration",
            "durationRound",
            "unixEpoch",
        ] {
            assert!(!takes_rendered_strings(name), "{name}");
        }
    }

    #[test]
    fn the_reference_date_fixtures_match() {
        // `{{ htmlDate "2019-06-13T20:39:39Z" }}` is `2019-06-13`.
        assert_eq!(one("htmlDate", "2019-06-13T20:39:39Z"), "2019-06-13");
        // `{{ unixEpoch "2019-06-13T20:39:39Z" }}` is `1560458379`.
        assert_eq!(one("unixEpoch", "2019-06-13T20:39:39Z"), "1560458379");
        // `{{ date_in_zone "02 Jan 06 15:04 -0700" "2019-06-13T20:39:39Z" "UTC" }}`
        // is `13 Jun 19 20:39 +00:00`, and the same layout in an unknown zone
        // falls back to UTC and renders the same.
        assert_eq!(
            three(
                "date_in_zone",
                &["02 Jan 06 15:04 -0700", "2019-06-13T20:39:39Z", "UTC"]
            ),
            "13 Jun 19 20:39 +00:00"
        );
        assert_eq!(
            three(
                "date_in_zone",
                &["02 Jan 06 15:04 -0700", "2019-06-13T20:39:39Z", "foobar"]
            ),
            "13 Jun 19 20:39 +00:00"
        );
        // `{{ date_modify "24h" "2019-06-13T20:39:39Z" }}` adds a day and
        // renders in the reference's round-trip spelling.
        assert_eq!(
            two("date_modify", "24h", "2019-06-13T20:39:39Z"),
            "2019-06-14T20:39:39.0000000+00:00"
        );
        // `{{ must_date_modify "1h" "2019-06-13T20:39:39Z" }}` is the same
        // helper with the spelling that reports a bad duration.
        assert_eq!(
            two("must_date_modify", "1h", "2019-06-13T20:39:39Z"),
            "2019-06-13T21:39:39.0000000+00:00"
        );
        // `{{ toDate "2006-01-02" "2017-12-31" | date "02/01/2006" }}` is
        // `31/12/2017`, which is a layout whose day and month are in the other
        // order.
        assert_eq!(
            two(
                "date",
                "02/01/2006",
                &two("toDate", "2006-01-02", "2017-12-31")
            ),
            "31/12/2017"
        );
        // `{{ htmlDateInZone "2019-06-13T20:39:39Z" "UTC" }}` and
        // `{{ dateInZone "2006-01-02" "2019-06-13T20:39:39Z" "UTC" }}` both
        // render the date alone.
        assert_eq!(
            two("htmlDateInZone", "2019-06-13T20:39:39Z", "UTC"),
            "2019-06-13"
        );
        assert_eq!(
            three("dateInZone", &["2006-01-02", "2019-06-13T20:39:39Z", "UTC"]),
            "2019-06-13"
        );
    }

    #[test]
    fn the_reference_duration_fixtures_match() {
        // `{{ duration "61" }}` and `{{ duration 61 }}` are both `1m1s`, so a
        // number and the same number as a string agree.
        assert_eq!(one("duration", "61"), "1m1s");
        assert_eq!(
            call("duration", &[Value::Number(61.0)])
                .expect("ok")
                .render(),
            "1m1s"
        );
        // `{{ duration "93784" }}` is 26 hours, 3 minutes, and 4 seconds.
        assert_eq!(one("duration", "93784"), "26h3m4s");
        assert_eq!(
            call("duration", &[Value::Number(93784.0)])
                .expect("ok")
                .render(),
            "26h3m4s"
        );
        // The `durationRound` cases from the reference, one for each branch of
        // the ladder.
        for (value, expected) in [
            ("24h5s", "1d"),
            ("2400h5s", "3mo"),
            ("2h5s", "2h"),
            ("24h", "24h"),
            ("1s", "0s"),
            ("invalid", "0s"),
            ("-2h5s", "2h"),
        ] {
            assert_eq!(one("durationRound", value), expected, "{value}");
        }
        // A number is a count of 100-nanosecond ticks divided by 100, which is
        // nanoseconds: the reference's `{{ durationRound 10000000000 }}`. The
        // same number as a string reads the same way, because that is how a
        // numeric literal reaches this crate.
        for argument in [
            Value::Number(10_000_000_000.0),
            Value::String("10000000000".to_owned()),
        ] {
            assert_eq!(
                call("durationRound", &[argument]).expect("ok").render(),
                "10s"
            );
        }
        // A bare number finer than the rounding ladder can show is `0s` either
        // way, so reading one as nanoseconds costs nothing here.
        assert_eq!(one("durationRound", "61"), "0s");
        // And text that is neither a duration nor a number is `0s`, which is
        // what the reference's `catch (FormatException)` gives.
        assert_eq!(one("durationRound", "later"), "0s");
        assert_eq!(one("durationRound", ""), "0s");
        assert_eq!(
            call("durationRound", &[Value::Bool(true)])
                .expect("ok")
                .render(),
            "0s"
        );
    }

    #[test]
    fn the_must_helpers_report_what_the_plain_ones_recover_from() {
        // The reference's MustDateHelpersSurfaceInvalidInputsWhileNormalHelpersRecover:
        // a duration the plain helper ignores leaves the time alone, and the
        // `must` form raises.
        assert_eq!(
            two("dateModify", "not duration", "2019-06-13T20:39:39Z"),
            "2019-06-13T20:39:39.0000000+00:00"
        );
        assert!(matches!(
            call(
                "mustDateModify",
                &[
                    Value::String("not duration".to_owned()),
                    Value::String("2019-06-13T20:39:39Z".to_owned()),
                ]
            ),
            Err(Error::InvalidArgument { .. })
        ));
        assert!(matches!(
            call(
                "must_date_modify",
                &[
                    Value::String("not duration".to_owned()),
                    Value::String("2019-06-13T20:39:39Z".to_owned()),
                ]
            ),
            Err(Error::InvalidArgument { .. })
        ));
        // `toDate` falls back to the minimum date and `mustToDate` reports it.
        assert_eq!(two("toDate", "2006-01-02", "not a date"), MINIMUM_DATE);
        {
            assert!(
                matches!(
                    call(
                        "mustToDate",
                        &[
                            Value::String("2006-01-02".to_owned()),
                            Value::String("not a date".to_owned()),
                        ]
                    ),
                    Err(Error::InvalidArgument { .. })
                ),
                "mustToDate"
            );
        }
        // A time neither form can parse is an error from both, which is where
        // the reference's two `try` blocks differ.
        for name in ["dateModify", "mustDateModify"] {
            assert!(
                matches!(
                    call(
                        name,
                        &[
                            Value::String("1h".to_owned()),
                            Value::String("not a date".to_owned()),
                        ]
                    ),
                    Err(Error::InvalidArgument { .. })
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn ago_rounds_to_the_nearest_second() {
        // The reference's AgoUsesGoDurationFormatting: a time 125 seconds ago
        // renders as two minutes and a few seconds, and the assertion allows
        // 4 through 6 because the two clocks are read a moment apart.
        let reference = std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(125))
            .expect("125 seconds ago is a real time");
        let elapsed = std::time::SystemTime::now()
            .duration_since(reference)
            .expect("the reference time is in the past")
            .as_secs();
        let seconds = elapsed as i64;
        assert!((120..=127).contains(&seconds), "{seconds}");
        let rendered = one("ago", &round_trip(reference, 0));
        // 125 seconds is two minutes and about five seconds, and the reference
        // asserts `^2m[4-6]s$`; the band here is a second wider on each side
        // because this test reads the clock a moment later than the reference's
        // did.
        assert!(rendered.starts_with("2m"), "{rendered}");
        assert!(rendered.ends_with('s'), "{rendered}");
        let whole: i64 = rendered[2..rendered.len() - 1]
            .parse()
            .expect("a whole number of seconds");
        assert!((3..=7).contains(&whole), "{rendered}");
    }

    /// Renders a `SystemTime` the way the reference's round-trip format does.
    fn round_trip(time: std::time::SystemTime, offset: i32) -> String {
        let seconds = time
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs() as i64
            + i64::from(offset);
        let days = seconds.div_euclid(86_400);
        let rest = seconds.rem_euclid(86_400);
        let (year, month, day) = super::civil_from_days(days);
        let sign = if offset < 0 { '-' } else { '+' };
        let magnitude = offset.unsigned_abs();
        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.0000000{sign}{:02}:{:02}",
            rest / 3_600,
            rest / 60 % 60,
            rest % 60,
            magnitude / 3_600,
            magnitude / 60 % 60,
        )
    }

    #[test]
    fn now_is_the_current_time_in_the_reference_round_trip_spelling() {
        // `now` reads a clock, so this can only check the shape. A template
        // that uses it does not render reproducibly, which is why it is the one
        // helper the crate documents as an exception.
        let rendered = call("now", &[]).expect("now takes no arguments").render();
        assert_eq!(
            rendered.len(),
            "2019-06-13T20:39:39.0000000+00:00".len(),
            "{rendered}"
        );
        assert!(rendered.ends_with("+00:00"), "{rendered}");
        let fraction = &rendered[19..27];
        assert!(
            fraction[1..].bytes().all(|byte| byte.is_ascii_digit()),
            "{rendered}"
        );
        // It parses back as a date, and formatting it with a layout is the
        // document's use of it.
        let year = call(
            "date",
            &[
                Value::String("2006".to_owned()),
                Value::String(rendered.clone()),
            ],
        )
        .expect("now is a date")
        .render();
        assert_eq!(year.len(), 4, "{year}");
        assert!(year.bytes().all(|byte| byte.is_ascii_digit()), "{year}");
        assert!(matches!(
            call("now", &[Value::Null]),
            Err(Error::WrongArgumentCount { .. })
        ));
    }

    #[test]
    fn a_layout_chooses_the_fields() {
        let time = "2019-06-13T20:39:39Z";
        for (layout, expected) in [
            ("2006-01-02", "2019-06-13"),
            ("2006-01-02T15:04:05Z07:00", "2019-06-13T20:39:39Z"),
            ("02 Jan 06 15:04 MST", "13 Jun 19 20:39 +00:00"),
            ("Monday, 02 January 2006", "Thursday, 13 June 2019"),
            ("15:04:05", "20:39:39"),
            ("3:04 pm", "8:39 pm"),
            ("002", "164"),
            ("_2 Jan", "13 Jun"),
            ("2006", "2019"),
        ] {
            assert_eq!(two("date", layout, time), expected, "{layout}");
        }
        // A layout is a pattern, so text that is not part of it is copied.
        assert_eq!(two("date", "on 2006-01-02!", time), "on 2019-06-13!");
        assert_eq!(two("date", "1/2/2006", "2019-06-13T20:39:39Z"), "6/13/2019");
    }

    #[test]
    fn date_with_one_argument_uses_the_reference_time() {
        // Upstream Sprig's one-argument `date`, which is the form a template
        // writes as `{{ date now }}`.
        let rendered = one("date", "2019-06-13T20:39:39Z");
        assert_eq!(
            rendered,
            format_layout_of(DEFAULT_LAYOUT, "2019-06-13T20:39:39Z")
        );
        assert!(rendered.starts_with("2019-06-13 20:39:39 "), "{rendered}");
        assert!(rendered.ends_with("+00:00"), "{rendered}");
    }

    /// The reference's own rendering of a layout, through the dispatch table.
    fn format_layout_of(layout: &str, value: &str) -> String {
        two("date", layout, value)
    }

    #[test]
    fn a_time_is_parsed_from_the_spellings_a_template_writes() {
        for value in [
            "2019-06-13T20:39:39Z",
            "2019-06-13T20:39:39z",
            "2019-06-13 20:39:39",
            "2019-06-13T20:39:39.1234567+00:00",
            "2019-06-13T20:39:39-07:00",
            "2019-06-13T20:39:39+02:00",
            "2019-06-13",
            "06/13/2019 20:39:39",
            "2019-06-13T20:39:39.5Z",
        ] {
            let rendered = two("date", "2006-01-02 15:04:05 -0700", value);
            assert!(rendered.starts_with("2019-06-13 "), "{value}: {rendered}");
        }
        // An offset is kept, and the date is the one in that offset rather than
        // the one in UTC.
        assert_eq!(
            two(
                "date",
                "2006-01-02 15:04:05 -0700",
                "2019-06-13T23:30:00-07:00"
            ),
            "2019-06-13 23:30:00 -07:00"
        );
        assert_eq!(
            two(
                "date",
                "2006-01-02 15:04:05 -0700",
                "2019-06-13T01:30:00+07:00"
            ),
            "2019-06-13 01:30:00 +07:00"
        );
        // A whole number of seconds is a Unix timestamp, as the reference's
        // `long.TryParse` then `FromUnixTimeSeconds` has it.
        assert_eq!(one("htmlDate", "1560458379"), "2019-06-13");
        assert_eq!(one("unixEpoch", "0"), "0");
        assert_eq!(one("htmlDate", "-1"), "1969-12-31");
    }

    #[test]
    fn a_time_that_is_not_one_is_an_error() {
        for value in [
            "",
            "not a date",
            "2019-13-01",
            "2019-02-30",
            "2019-06-13T25:00:00Z",
            "2019-06-13T20:39:39Z trailing",
            "2019-06",
        ] {
            assert!(
                matches!(
                    try_one("htmlDate", value),
                    Err(Error::InvalidArgument { .. })
                ),
                "htmlDate {value:?}"
            );
        }
        // A date outside what a `DateTimeOffset` can hold is refused as well.
        assert!(matches!(
            try_one("unixEpoch", "99999999999999"),
            Err(Error::InvalidArgument { .. })
        ));
    }

    #[test]
    fn to_date_parses_only_what_its_layout_describes() {
        assert_eq!(
            two("toDate", "2006-01-02", "2017-12-31"),
            "2017-12-31T00:00:00.0000000+00:00"
        );
        assert_eq!(
            two("toDate", "2006-01-02 15:04:05", "2017-12-31 10:20:30"),
            "2017-12-31T10:20:30.0000000+00:00"
        );
        // An offset in the layout is honoured, and the result keeps it: a
        // `DateTimeOffset` is a moment *and* an offset, so `TryParseExact`
        // against `zzz` gives back the offset the value was written in.
        assert_eq!(
            two(
                "toDate",
                "2006-01-02T15:04:05Z07:00",
                "2017-12-31T10:20:30+02:00"
            ),
            "2017-12-31T10:20:30.0000000+02:00"
        );
        // And the instant is the one that offset names, so formatting it in
        // another zone moves it.
        assert_eq!(
            three(
                "dateInZone",
                &[
                    "2006-01-02 15:04:05 -07:00",
                    &two(
                        "toDate",
                        "2006-01-02T15:04:05Z07:00",
                        "2017-12-31T10:20:30+02:00"
                    ),
                    "UTC",
                ]
            ),
            "2017-12-31 08:20:30 +00:00"
        );
        // The parse is exact: a value the layout does not describe in full is
        // the minimum date, and a layout element with a wrong width fails too.
        assert_eq!(two("toDate", "2006-01-02", "2017-12-3"), MINIMUM_DATE);
        assert_eq!(
            two("toDate", "2006-01-02", "2017-12-31T00:00:00Z"),
            MINIMUM_DATE
        );
        assert_eq!(two("toDate", "01/02/2006", "2017-12-31"), MINIMUM_DATE);
        assert_eq!(two("toDate", "2006-01-02", "not a date"), MINIMUM_DATE);
        // A month name is read, so a locale-shaped layout works.
        assert_eq!(
            two("toDate", "02 Jan 2006", "31 Dec 2017"),
            "2017-12-31T00:00:00.0000000+00:00"
        );
        // And the result is itself a date the other helpers read.
        assert_eq!(
            two(
                "date",
                "2006-01-02",
                &two("toDate", "2006-01-02", "2017-12-31")
            ),
            "2017-12-31"
        );
    }

    #[test]
    fn date_modify_accepts_the_durations_go_does() {
        for (duration, expected) in [
            ("1h", "2019-06-13T21:39:39.0000000+00:00"),
            ("-1h", "2019-06-13T19:39:39.0000000+00:00"),
            ("1h30m", "2019-06-13T22:09:39.0000000+00:00"),
            ("1.5h", "2019-06-13T22:09:39.0000000+00:00"),
            ("90s", "2019-06-13T20:41:09.0000000+00:00"),
            ("1ms", "2019-06-13T20:39:39.0010000+00:00"),
            ("1500ms", "2019-06-13T20:39:40.5000000+00:00"),
            ("1us", "2019-06-13T20:39:39.0000010+00:00"),
            ("1ns", "2019-06-13T20:39:39.0000000+00:00"),
            ("0", "2019-06-13T20:39:39.0000000+00:00"),
        ] {
            assert_eq!(
                two("dateModify", duration, "2019-06-13T20:39:39Z"),
                expected,
                "{duration}"
            );
        }
    }

    #[test]
    fn a_duration_is_read_the_way_the_reference_reads_one() {
        // The reference's `ParseDuration` requires a unit on every number, so
        // these are not durations at all.
        for value in ["", "61", "1", "-", "1x", "1h2", "h", "1 h", "1h 30m"] {
            assert_eq!(parse_go_duration(value), None, "{value:?}");
        }
        // And these are, in nanoseconds.
        for (value, expected) in [
            // A `TimeSpan` counts 100-nanosecond ticks, so a duration finer than
            // that is truncated away: the reference's `quantity / 100` for
            // nanoseconds is the same truncation.
            ("1ns", 0),
            ("0.5ms", 500_000),
            ("1us", 1_000),
            ("1µs", 1_000),
            ("1ms", 1_000_000),
            ("1s", 1_000_000_000),
            ("1m", 60_000_000_000),
            ("1h", 3_600_000_000_000),
            ("1h30m", 5_400_000_000_000),
            ("1.5h", 5_400_000_000_000),
            ("-1h", -3_600_000_000_000),
            ("+1h", 3_600_000_000_000),
            ("1h30m10s", 5_410_000_000_000),
        ] {
            assert_eq!(parse_go_duration(value), Some(expected), "{value}");
        }
    }

    #[test]
    fn a_whole_second_duration_renders_the_way_the_reference_does() {
        // `FormatGoDuration` omits a zero component unless a larger one is
        // present, always writes the seconds, and writes no fraction.
        for (nanoseconds, expected) in [
            (0, "0s"),
            (1, "0s"),
            (999_999_999, "0s"),
            (1_000_000_000, "1s"),
            (61_000_000_000, "1m1s"),
            (125_000_000_000, "2m5s"),
            (3_600_000_000_000, "1h0m0s"),
            (3_661_000_000_000, "1h1m1s"),
            (93_784_000_000_000, "26h3m4s"),
            (-61_000_000_000, "-1m1s"),
        ] {
            assert_eq!(format_go_duration(nanoseconds), expected, "{nanoseconds}");
        }
    }

    #[test]
    fn duration_reads_its_argument_the_way_nlong_does() {
        // The reference's `NLong` renders a scalar and treats what it cannot
        // read as zero, so a bad argument is `0s` rather than an error.
        assert_eq!(one("duration", "later"), "0s");
        assert_eq!(
            call("duration", &[Value::Bool(true)]).expect("ok").render(),
            "1s"
        );
        assert_eq!(
            call("duration", &[Value::Bool(false)])
                .expect("ok")
                .render(),
            "0s"
        );
        // A fraction is truncated rather than rounded.
        assert_eq!(one("duration", "61.9"), "1m1s");
        // And a negative count is a negative duration.
        assert_eq!(one("duration", "-61"), "-1m1s");
    }

    #[test]
    fn duration_round_compares_strictly_against_each_bound() {
        // The reference's bounds are strict, so a duration of exactly one hour
        // is sixty minutes rather than one hour, and exactly one year is
        // twelve months.
        for (value, expected) in [
            ("0", "0s"),
            ("30m", "30m"),
            ("1h", "60m"),
            ("23h59m", "23h"),
            ("24h", "24h"),
            // A day is not a Go duration unit, so these are written in hours.
            ("720h", "30d"),
            ("744h", "1mo"),
            ("8760h", "12mo"),
            ("8784h", "1y"),
            ("17520h", "2y"),
            ("90s", "1m"),
            ("120s", "2m"),
            ("120m", "2h"),
        ] {
            assert_eq!(one("durationRound", value), expected, "{value}");
        }
    }

    #[test]
    fn a_zone_resolves_to_a_fixed_offset() {
        assert_eq!(zone_offset("UTC"), 0);
        assert_eq!(zone_offset("utc"), 0);
        assert_eq!(zone_offset("Etc/UTC"), 0);
        assert_eq!(zone_offset("GMT"), 0);
        assert_eq!(zone_offset("Z"), 0);
        assert_eq!(zone_offset(""), 0);
        // An unknown name falls back to UTC, which is what the reference does
        // when `FindSystemTimeZoneById` throws.
        assert_eq!(zone_offset("foobar"), 0);
        assert_eq!(zone_offset("America/New_York"), 0);
        // A numeric offset is itself.
        assert_eq!(zone_offset("+05:30"), 5 * 3_600 + 30 * 60);
        assert_eq!(zone_offset("-0800"), -(8 * 3_600));
        assert_eq!(zone_offset("+9"), 9 * 3_600);
        assert_eq!(zone_offset("+24:00"), 0);

        // The conversion is a real one: a time in the evening at UTC is the
        // next morning in a zone east of it.
        assert_eq!(
            three(
                "dateInZone",
                &[
                    "2006-01-02 15:04:05 -07:00",
                    "2019-06-13T20:39:39Z",
                    "+05:30"
                ]
            ),
            "2019-06-14 02:09:39 +05:30"
        );
        assert_eq!(
            three(
                "dateInZone",
                &[
                    "2006-01-02 15:04:05 -07:00",
                    "2019-06-13T20:39:39Z",
                    "-08:00"
                ]
            ),
            "2019-06-13 12:39:39 -08:00"
        );
        // And `htmlDateInZone` can see a different day than `htmlDate` does.
        assert_eq!(one("htmlDate", "2019-06-13T23:30:00Z"), "2019-06-13");
        assert_eq!(
            two("htmlDateInZone", "2019-06-13T23:30:00Z", "+02:00"),
            "2019-06-14"
        );
    }

    #[test]
    fn the_argument_count_is_checked_for_every_helper() {
        // Each helper with the counts it accepts and the one past each end.
        // `date` is the only one with a range: it takes a layout and a time, or
        // a time alone.
        let cases: [(&str, usize, usize); 13] = [
            ("now", 0, 0),
            ("date", 1, 2),
            ("dateInZone", 3, 3),
            ("htmlDate", 1, 1),
            ("htmlDateInZone", 2, 2),
            ("dateModify", 2, 2),
            ("mustDateModify", 2, 2),
            ("toDate", 2, 2),
            ("mustToDate", 2, 2),
            ("ago", 1, 1),
            ("duration", 1, 1),
            ("durationRound", 1, 1),
            ("unixEpoch", 1, 1),
        ];
        let filler = || Value::String("x".to_owned());
        for (name, min, max) in cases {
            // Every count the helper accepts is not an arity error, though the
            // value may still be refused, which is a different error.
            for count in min..=max {
                let arguments: Vec<Value> = (0..count).map(|_| filler()).collect();
                if let Err(error) = call(name, &arguments) {
                    assert!(
                        !matches!(error, Error::WrongArgumentCount { .. }),
                        "{name} with {count} arguments: {error}"
                    );
                }
            }
            // One past either end is.
            for count in [min.saturating_sub(1), max + 1] {
                if (min..=max).contains(&count) {
                    continue;
                }
                let arguments: Vec<Value> = (0..count).map(|_| filler()).collect();
                assert!(
                    matches!(
                        call(name, &arguments),
                        Err(Error::WrongArgumentCount { .. })
                    ),
                    "{name} with {count} arguments"
                );
            }
        }
    }

    #[test]
    fn a_collection_is_refused_where_the_reference_would_render_one() {
        // `support::text` refuses a list and a map, so a date written as one is
        // an error rather than a rendering of `[2019-06-13]`.
        assert!(matches!(
            call(
                "htmlDate",
                &[Value::List(vec![Value::String("2019-06-13".to_owned())])]
            ),
            Err(Error::InvalidArgument { .. })
        ));
        assert!(matches!(
            call("date", &[Value::Map(std::collections::BTreeMap::new())]),
            Err(Error::InvalidArgument { .. })
        ));
        // A number is read as its Go rendering, so `unixEpoch 0` is the epoch.
        assert_eq!(
            call("unixEpoch", &[Value::Number(0.0)])
                .expect("ok")
                .render(),
            "0"
        );
    }
}
