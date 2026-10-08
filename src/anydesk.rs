//! AnyDesk's logs (`ProgramData\AnyDesk` for the service, a user's
//! `AppData\Roaming\AnyDesk`): remote access in and out.
//!
//! - The traces (`ad.trace`, `ad_svc.trace`): `level date time role pid
//!   tid [thread name] module - message`, UTC, e.g.
//!   `info 2024-02-16 20:29:04.298  back 4668 6440  app.backend_session -
//!   Incoming session request: Richard Beard (221436813)`. Every line is
//!   kept; the ones naming a remote AnyDesk ID (`Incoming session
//!   request: <name> (<id>)`, `Accept request from <id>`, `Accepting from
//!   <id>`) and an address (`Logged in from <ip>:<port>`) give them.
//! - `connection_trace.txt`: one line per session, its direction, start
//!   (`YYYY-MM-DD, HH:MM`, UTC), how it was authorised (`User` accepted by
//!   the user, `Passwd` with the unattended password, `Token` with a saved
//!   token, `REJECTED`) and the AnyDesk IDs, separated by tabs or runs of
//!   blanks.

use common::time::Ts;

use crate::{date_ymd, decode, time_hms, Civil, Parsed};

/// A trace line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceLine {
    /// Its line, from 1.
    pub line: usize,
    /// Its level (`info`, `warning`, `error`).
    pub level: String,
    /// When (UTC).
    pub time: Ts,
    /// The process's role (`back` for the service, `front` for the user
    /// interface, `main`, `ctrl`, …).
    pub role: String,
    /// The process.
    pub process: u32,
    /// The thread.
    pub thread: u32,
    /// The module (`app.backend_session`, `anynet.any_socket`).
    pub module: String,
    /// What it says.
    pub message: String,
    /// The remote AnyDesk ID the line names, if any.
    pub remote_id: Option<String>,
    /// The remote user's name an incoming session request gives.
    pub remote_name: Option<String>,
    /// The address the line names (`Logged in from`), without its port.
    pub address: Option<String>,
}

/// A session of `connection_trace.txt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// Its line, from 1.
    pub line: usize,
    /// `Incoming` or `Outgoing`.
    pub direction: String,
    /// When it started (UTC, to the minute).
    pub time: Ts,
    /// How it was authorised: `User`, `Passwd`, `Token`, `REJECTED`, ….
    pub authorisation: String,
    /// The AnyDesk IDs the line lists, the remote side's first.
    pub ids: Vec<String>,
}

/// Every line of a trace.
#[must_use]
pub fn trace(data: &[u8]) -> Parsed<TraceLine> {
    let text = decode(data);
    let mut parsed = Parsed::default();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match trace_line(line) {
            Some(mut entry) => {
                entry.line = index + 1;
                parsed.entries.push(entry);
            }
            None => parsed
                .problems
                .push(format!("line {}: not a trace line", index + 1)),
        }
    }
    parsed
}

fn trace_line(line: &str) -> Option<TraceLine> {
    let (head, message) = line.split_once(" - ")?;
    let mut words = head.split_whitespace();
    let level = words.next()?.to_owned();
    let (year, month, day) = date_ymd(words.next()?)?;
    let (hour, minute, second, millisecond) = time_hms(words.next()?)?;
    let role = words.next()?.to_owned();
    let process = words.next()?.parse().ok()?;
    let thread = words.next()?.parse().ok()?;
    // A thread name may come before the module: the module is the last word.
    let module = words.last()?.to_owned();
    let time = Civil {
        year,
        month,
        day,
        hour,
        minute,
        second,
        millisecond,
    }
    .utc()?;
    let message = message.trim().to_owned();
    let (remote_name, remote_id) = remote(&message);
    Some(TraceLine {
        line: 0,
        level,
        time,
        role,
        process,
        thread,
        module,
        address: address(&message),
        remote_id,
        remote_name,
        message,
    })
}

/// The remote user's name and AnyDesk ID a message gives.
fn remote(message: &str) -> (Option<String>, Option<String>) {
    if let Some(request) = message.strip_prefix("Incoming session request: ") {
        if let Some((name, id)) = request
            .trim_end()
            .strip_suffix(')')
            .and_then(|r| r.rsplit_once(" ("))
        {
            return (Some(name.to_owned()), id_of(id));
        }
    }
    for marker in ["Accept request from ", "Accepting from "] {
        if let Some(rest) = message.split_once(marker).map(|(_, r)| r) {
            return (
                None,
                id_of(rest.split([' ', '.', ',']).next().unwrap_or_default()),
            );
        }
    }
    (None, None)
}

/// An AnyDesk ID: digits (or an alias, `name@ad`).
fn id_of(text: &str) -> Option<String> {
    let text = text.trim();
    let digits = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    (digits || text.contains('@')).then(|| text.to_owned())
}

/// The address `Logged in from <ip>:<port>` names, without the port.
fn address(message: &str) -> Option<String> {
    let rest = message.split_once("Logged in from ")?.1;
    let endpoint = rest.split_whitespace().next()?;
    let ip = endpoint.rsplit_once(':').map_or(endpoint, |(ip, _)| ip);
    (ip.chars().any(|c| c.is_ascii_digit())).then(|| ip.trim_matches(['[', ']']).to_owned())
}

/// Every session of `connection_trace.txt`.
#[must_use]
pub fn connections(data: &[u8]) -> Parsed<Session> {
    let text = decode(data);
    let mut parsed = Parsed::default();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match session(line) {
            Some(mut entry) => {
                entry.line = index + 1;
                parsed.entries.push(entry);
            }
            None => parsed
                .problems
                .push(format!("line {}: not a session line", index + 1)),
        }
    }
    parsed
}

fn session(line: &str) -> Option<Session> {
    let mut words = line.split_whitespace();
    let direction = words.next()?.to_owned();
    let (year, month, day) = date_ymd(words.next()?.strip_suffix(',')?)?;
    let (hour, minute) = words.next()?.split_once(':')?;
    let time = Civil {
        year,
        month,
        day,
        hour: hour.parse().ok()?,
        minute: minute.parse().ok()?,
        second: 0,
        millisecond: 0,
    }
    .utc()?;
    let authorisation = words.next()?.to_owned();
    Some(Session {
        line: 0,
        direction,
        time,
        authorisation,
        ids: words.map(str::to_owned).collect(),
    })
}

/// Whether a line looks like a trace line.
pub(crate) fn is_trace(line: &str) -> bool {
    trace_line(line).is_some()
}

/// Whether a line looks like a `connection_trace.txt` line.
pub(crate) fn is_session(line: &str) -> bool {
    session(line).is_some_and(|s| s.direction == "Incoming" || s.direction == "Outgoing")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_lines() {
        let line = "   info 2024-02-16 20:29:04.298       back   4668   6440                   app.backend_session - Incoming session request: Richard Beard (221436813)";
        let entry = trace_line(line).unwrap();
        assert_eq!(entry.module, "app.backend_session");
        assert_eq!(entry.remote_id.as_deref(), Some("221436813"));
        assert_eq!(entry.remote_name.as_deref(), Some("Richard Beard"));
        assert_eq!(
            entry.time.to_iso8601().as_deref(),
            Some("2024-02-16T20:29:04.2980000Z")
        );
        let login = trace_line("   info 2024-02-16 20:29:01.000       back   4668   6440   7 anynet.relay_conn - Logged in from 198.51.100.4:51888 on relay 8a3c1d2e.").unwrap();
        assert_eq!(login.address.as_deref(), Some("198.51.100.4"));
        assert_eq!(login.module, "anynet.relay_conn");
        assert!(trace_line("hello - world").is_none());
    }

    #[test]
    fn sessions() {
        let entry = session("Incoming    2024-02-16, 20:29    User                              221436813    221436813").unwrap();
        assert_eq!(entry.authorisation, "User");
        assert_eq!(entry.ids, ["221436813", "221436813"]);
        assert_eq!(
            entry.time.to_iso8601().as_deref(),
            Some("2024-02-16T20:29:00.0000000Z")
        );
        assert!(session("Incoming 2024-02-16 20:29 User").is_none());
    }
}
