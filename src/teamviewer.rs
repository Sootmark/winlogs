//! TeamViewer's logs (`Program Files\TeamViewer`, a user's
//! `AppData\Roaming\TeamViewer`): remote access in and out.
//!
//! - The application log (`TeamViewer15_Logfile.log`): `YYYY/MM/DD
//!   HH:MM:SS.fff  pid  tid  …  message`, local time.
//! - `Connections_incoming.txt`: one line per session into this machine,
//!   tab-separated: the remote TeamViewer ID, its display name, start and
//!   end (`DD-MM-YYYY HH:MM:SS`, UTC), the local account, the kind of
//!   session, its identifier.
//! - `Connections.txt`: one line per session from this machine: the remote
//!   ID, start, end, the local account, the kind, the identifier
//!   (separated by tabs or runs of blanks).

use common::time::Ts;

use crate::{date_ymd, decode, time_hms, Civil, Parsed};

/// A line of the application log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    /// Its line, from 1.
    pub line: usize,
    /// When (local time).
    pub time: Ts,
    /// The process.
    pub process: u32,
    /// The thread.
    pub thread: Option<u32>,
    /// What it says.
    pub message: String,
}

/// A remote session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    /// Its line, from 1.
    pub line: usize,
    /// Into this machine (`Connections_incoming.txt`) or from it.
    pub incoming: bool,
    /// The other side's TeamViewer ID.
    pub remote_id: String,
    /// The other side's display name (incoming sessions only).
    pub remote_name: Option<String>,
    /// When it started (UTC).
    pub start: Option<Ts>,
    /// When it ended (UTC).
    pub end: Option<Ts>,
    /// The local account.
    pub account: String,
    /// The kind of session (`RemoteControl`, `FileTransfer`, …).
    pub kind: String,
    /// Its identifier.
    pub id: String,
}

/// Read the application log. A line that doesn't start with a time
/// continues the entry before it (the start banner's version, ID, OS).
#[must_use]
pub fn log(data: &[u8]) -> Parsed<LogLine> {
    let mut parsed: Parsed<LogLine> = Parsed::default();
    for (index, line) in decode(data).lines().enumerate() {
        let Some((time, process, mut words)) = start(line) else {
            if let Some(previous) = parsed.entries.last_mut() {
                if !line.trim().is_empty() {
                    if !previous.message.is_empty() {
                        previous.message.push('\n');
                    }
                    previous.message.push_str(line.trim_end());
                }
            }
            continue;
        };
        let thread = words.next().and_then(|t| t.parse().ok());
        parsed.entries.push(LogLine {
            line: index + 1,
            time,
            process,
            thread,
            message: message_body(line).to_owned(),
        });
    }
    parsed
}

/// A log line's time and process, and the words after them; `None` for
/// a continuation line.
fn start(line: &str) -> Option<(Ts, u32, std::str::SplitWhitespace<'_>)> {
    let mut words = line.split_whitespace();
    let date = date_ymd(words.next()?)?;
    let clock = time_hms(words.next()?)?;
    let process = words.next()?.parse().ok()?;
    Some((crate::civil(date, clock).local()?, process, words))
}

/// The message after the time, process, thread and level columns.
fn message_body(line: &str) -> &str {
    let mut rest = line;
    for _ in 0..5 {
        rest = rest.trim_start();
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        rest = &rest[end..];
    }
    rest.trim()
}

/// Read `Connections_incoming.txt` (`incoming`) or `Connections.txt`.
#[must_use]
pub fn connections(data: &[u8], incoming: bool) -> Parsed<Connection> {
    let mut parsed = Parsed::default();
    for (index, line) in decode(data).lines().enumerate() {
        let line_number = index + 1;
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = if line.contains('\t') {
            line.split('\t').map(str::trim).collect()
        } else {
            split_runs(line)
        };
        let read = if incoming {
            match fields.as_slice() {
                [id, name, start, end, account, kind, session, ..] => {
                    Some((*id, Some(*name), *start, *end, *account, *kind, *session))
                }
                _ => None,
            }
        } else {
            match fields.as_slice() {
                [id, start, end, account, kind, session, ..] => {
                    Some((*id, None, *start, *end, *account, *kind, *session))
                }
                _ => None,
            }
        };
        let Some((id, name, start, end, account, kind, session)) = read else {
            parsed
                .problems
                .push(format!("line {line_number}: {} fields", fields.len()));
            continue;
        };
        parsed.entries.push(Connection {
            line: line_number,
            incoming,
            remote_id: id.to_owned(),
            remote_name: name.map(str::to_owned).filter(|n| !n.is_empty()),
            start: day_first(start),
            end: day_first(end),
            account: account.to_owned(),
            kind: kind.to_owned(),
            id: session.to_owned(),
        });
    }
    parsed
}

/// Fields separated by runs of two or more blanks (a date's single blank
/// kept).
fn split_runs(line: &str) -> Vec<&str> {
    line.split("  ")
        .map(str::trim)
        .filter(|field| !field.is_empty())
        .collect()
}

/// `DD-MM-YYYY HH:MM:SS`, UTC.
fn day_first(text: &str) -> Option<Ts> {
    let (date, clock) = text.trim().split_once(' ')?;
    let mut parts = date.split('-');
    let day = parts.next()?.parse().ok()?;
    let month = parts.next()?.parse().ok()?;
    let year = parts.next()?.parse().ok()?;
    let (hour, minute, second, millisecond) = time_hms(clock)?;
    Civil {
        year,
        month,
        day,
        hour,
        minute,
        second,
        millisecond,
    }
    .utc()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_lines() {
        let parsed =
            log(b"2024/02/16 06:05:19.349  2136       3688  0   Logger started.\ncontinued text\n");
        assert_eq!(parsed.entries.len(), 1);
        let line = &parsed.entries[0];
        assert_eq!((line.process, line.thread), (2136, Some(3688)));
        assert_eq!(line.message, "Logger started.\ncontinued text");
    }

    #[test]
    fn connections_both_ways() {
        let incoming = connections(b"1660360496\tTestUser\t16-02-2024 14:16:32\t16-02-2024 14:18:36\tIEUser\tRemoteControl\t{b3a4}\t\n", true);
        let session = &incoming.entries[0];
        assert_eq!(session.remote_name.as_deref(), Some("TestUser"));
        assert_eq!(
            session.start.and_then(|t| t.to_iso8601()).as_deref(),
            Some("2024-02-16T14:16:32.0000000Z")
        );
        let outgoing = connections(b"1660360496                      20-02-2024 13:10:33             20-02-2024 13:11:52             IEUser                          RemoteControl                   {b351}\n", false);
        assert_eq!(outgoing.entries[0].account, "IEUser");
        assert_eq!(outgoing.entries[0].id, "{b351}");
    }
}
