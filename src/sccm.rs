//! Configuration Manager (SCCM, MECM) client logs (`Windows\CCM\Logs\*.log`):
//! each entry `<![LOG[text]LOG]!><time="HH:MM:SS.fff±bias" date="M-D-YYYY"
//! component="…" context="" type="1" thread="…" file="…">`, its text
//! possibly on several lines. The bias is Windows' (UTC = local time +
//! bias, in minutes: `+480` on the US west coast, `-330` in India), so
//! times with one are UTC; without one, local.

use common::time::Ts;

use crate::{decode, time_hms, Civil, Parsed};

const OPEN: &str = "<![LOG[";
const CLOSE: &str = "]LOG]!>";

/// An entry of a client log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its first line, from 1.
    pub line: usize,
    /// When: UTC with a bias, local without.
    pub time: Option<Ts>,
    /// The component that wrote it (`AppEnforce`).
    pub component: String,
    /// Its severity (`1` information, `2` warning, `3` error).
    pub severity: Option<u8>,
    /// The thread.
    pub thread: Option<u32>,
    /// The source file and line (`appprovider.cpp:1702`).
    pub file: String,
    /// What it says.
    pub text: String,
}

/// Read a client log.
#[must_use]
pub fn read(data: &[u8]) -> Parsed<Entry> {
    let text = decode(data);
    let mut parsed = Parsed::default();
    let mut rest = text.as_str();
    while let Some(start) = rest.find(OPEN) {
        let line = text.len() - rest.len() + start;
        let line_number = text[..line].matches('\n').count() + 1;
        rest = &rest[start + OPEN.len()..];
        let Some(end) = rest.find(CLOSE) else {
            parsed
                .problems
                .push(format!("line {line_number}: an entry without its end"));
            break;
        };
        let message = rest[..end].trim().to_owned();
        rest = &rest[end + CLOSE.len()..];
        let attributes_end = rest.find('>').unwrap_or(rest.len());
        let attributes = &rest[..attributes_end];
        rest = &rest[attributes_end..];
        let attribute = |name: &str| attribute(attributes, name);
        let time = attribute("date")
            .zip(attribute("time"))
            .and_then(|(date, time)| entry_time(date, time));
        if time.is_none() {
            parsed
                .problems
                .push(format!("line {line_number}: no readable time"));
        }
        parsed.entries.push(Entry {
            line: line_number,
            time,
            component: attribute("component").unwrap_or_default().to_owned(),
            severity: attribute("type").and_then(|t| t.parse().ok()),
            thread: attribute("thread").and_then(|t| t.parse().ok()),
            file: attribute("file").unwrap_or_default().to_owned(),
            text: message,
        });
    }
    parsed
}

/// The value of `name="…"` in an entry's attributes.
fn attribute<'a>(attributes: &'a str, name: &str) -> Option<&'a str> {
    let key = format!("{name}=\"");
    let start = attributes.find(&key)? + key.len();
    let end = attributes[start..].find('"')? + start;
    Some(&attributes[start..end])
}

/// `M-D-YYYY` and `HH:MM:SS.fff±bias`.
fn entry_time(date: &str, time: &str) -> Option<Ts> {
    let mut parts = date.split('-');
    let month = parts.next()?.parse().ok()?;
    let day = parts.next()?.parse().ok()?;
    let year = parts.next()?.parse().ok()?;
    let (clock, bias) = match time.find(['+', '-']) {
        Some(at) => (&time[..at], Some(time[at..].parse::<i64>().ok()?)),
        None => (time, None),
    };
    let (hour, minute, second, millisecond) = time_hms(clock)?;
    let when = Civil {
        year,
        month,
        day,
        hour,
        minute,
        second,
        millisecond,
    };
    match bias {
        Some(bias) => when.with_bias(bias),
        None => when.local(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_with_and_without_a_bias() {
        let log = "<![LOG[Some stuff happened.]LOG]!><time=\"17:52:13.827+480\" date=\"11-23-2014\" component=\"PeerDPAgent\" context=\"\" type=\"1\" thread=\"3536\" file=\"a.cpp:12\">\n<![LOG[line one\nline two]LOG]!><time=\"10:22:50.8422964\" date=\"1-2-2015\" component=\"SCClient\" context=\"\" type=\"0\" thread=\"16\" file=\"\">";
        let parsed = read(log.as_bytes());
        assert_eq!(parsed.entries.len(), 2);
        let first = &parsed.entries[0];
        // Pacific time: UTC eight hours later.
        assert_eq!(
            first.time.and_then(|t| t.to_iso8601()).as_deref(),
            Some("2014-11-24T01:52:13.8270000Z")
        );
        assert_eq!(
            (first.component.as_str(), first.thread),
            ("PeerDPAgent", Some(3536))
        );
        let second = &parsed.entries[1];
        assert_eq!(second.text, "line one\nline two");
        assert_eq!(second.line, 2);
        assert_eq!(
            second.time.and_then(|t| t.to_iso8601()).as_deref(),
            Some("2015-01-02T10:22:50.8420000")
        );
    }
}
